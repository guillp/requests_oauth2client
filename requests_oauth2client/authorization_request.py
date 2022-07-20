"""Classes and utilities related to Authorization Requests and Responses."""


import re
import secrets
from datetime import datetime
from typing import Any, Dict, Iterable, Optional, Tuple, Type, Union

from binapy import BinaPy
from furl import furl  # type: ignore[import]
from jwskate import Jwk, Jwt

from .exceptions import (
    AuthorizationResponseError,
    ConsentRequired,
    InteractionRequired,
    LoginRequired,
    MismatchingIssuer,
    MismatchingState,
    MissingAuthCode,
    SessionSelectionRequired,
)
from .utils import accepts_expires_in


class PkceUtils:
    """Contains helper methods for PKCE, as described in RFC7636.

    See [RFC7636](https://tools.ietf.org/html/rfc7636).
    """

    code_verifier_re = re.compile(r"^[a-zA-Z0-9_\-~.]{43,128}$")
    """A regex that matches valid code verifiers."""

    @classmethod
    def generate_code_verifier(cls) -> str:
        """Generate a valid `code_verifier`.

        Returns:
            a code_verifier ready to use for PKCE
        """
        return secrets.token_urlsafe(96)

    @classmethod
    def derive_challenge(cls, verifier: Union[str, bytes], method: str = "S256") -> str:
        """Derive the `code_challenge` from a given `code_verifier`.

        Args:
            verifier: a code verifier
            method: the method to use for deriving the challenge. Accepts 'S256' or 'plain'.

        Returns:
            a code_challenge derived from the given verifier
        """
        if isinstance(verifier, bytes):
            verifier = verifier.decode()

        if not cls.code_verifier_re.match(verifier):
            raise ValueError(
                f"Invalid code verifier, does not match {cls.code_verifier_re}",
                verifier,
            )

        if method == "S256":
            return BinaPy(verifier).to("sha256").to("b64u").ascii()
        elif method == "plain":
            return verifier
        else:
            raise ValueError("Unsupported code_challenge_method", method)

    @classmethod
    def generate_code_verifier_and_challenge(cls, method: str = "S256") -> Tuple[str, str]:
        """Generate a valid `code_verifier` and derive its `code_challenge`.

        Args:
            method: the method to use for deriving the challenge. Accepts 'S256' or 'plain'.

        Returns:
            a (code_verifier, code_challenge) tuple.
        """
        verifier = cls.generate_code_verifier()
        challenge = cls.derive_challenge(verifier, method)
        return verifier, challenge

    @classmethod
    def validate_code_verifier(
        cls, verifier: str, challenge: str, method: str = "S256"
    ) -> bool:
        """Validate a `code_verifier` against a `code_challenge`.

        Args:
            verifier: the `code_verifier`, exactly as submitted by the client on token request.
            challenge: the `code_challenge`, exactly as submitted by the client on authorization request.
            method: the method to use for deriving the challenge. Accepts 'S256' or 'plain'.

        Returns:
            `True` if verifier is valid, or `False` otherwise
        """
        return (
            cls.code_verifier_re.match(verifier) is not None
            and cls.derive_challenge(verifier, method) == challenge
        )


class AuthorizationResponse:
    """Represent a successful Authorization Response.

    An Authorization Response is the redirection initiated by the AS
    to the client's redirection endpoint (redirect_uri) after an Authorization Request.
    This Response is typically created with a call to `AuthorizationRequest.validate_callback()` once the call
    to the client Redirection Endpoint is made.
    AuthorizationResponse contains the following, all accessible as attributes:
     - all the parameters that have been returned by the AS, most notably the `code`, and optional parameters such as `state`.
     - the redirect_uri that was used for the Authorization Request
     - the code_verifier matching the code_challenge that was used for the Authorization Request

    Parameters `redirect_uri` and `code_verifier` must be those from the matching `AuthorizationRequest`.
    All other parameters including `code` and `state` must be those extracted from the Authorization Response parameters.

    Args:
        code: the authorization code returned by the AS
        redirect_uri: the redirect_uri that was passed as parameter in the AuthorizationRequest
        code_verifier: the code_verifier matching the code_challenge that was passed as parameter in the AuthorizationRequest
        state: the state returned by the AS
        **kwargs: other parameters as returned by the AS

    Usage:
        ```python
        request = AuthorizationRequest(
            client_id, scope="openid", redirect_uri="http://localhost:54121/callback"
        )
        webbrowser.open(request)  # open the authorization request in a browser
        response_uri = ...  # at this point, manage to get the response uri
        response = request.validate_callback(
            response_uri
        )  # get an AuthorizationResponse at this point

        client = OAuth2Client(token_endpoint, auth=(client_id, client_secret))
        client.authorization_code(
            response
        )  # you can pass this response on a call to `OAuth2Client.authorization_code()`
        ```
    """

    def __init__(
        self,
        code: Optional[str] = None,
        redirect_uri: Optional[str] = None,
        code_verifier: Optional[str] = None,
        state: Optional[str] = None,
        **kwargs: str,
    ):
        self.code = code
        self.redirect_uri = redirect_uri
        self.code_verifier = code_verifier
        self.state = state
        self.others = kwargs

    def __getattr__(self, item: str) -> Optional[str]:
        """Make additional parameters available as attributes.

        Args:
            item: the attribute name

        Returns:
            the attribute value, or None if it isn't part of the returned attributes
        """
        return self.others.get(item)


class AuthorizationRequest:
    """Represents an Authorization Request.

    This class makes it easy to generate valid Authorization Request URI (possibly including a state, nonce, PKCE, and custom args),
    to store all parameters, and to validate an Authorization Response.

    All parameters passed at init time will be included in the request query parameters as-is,
    excepted for a few parameters which have a special behaviour:

    * `state`: if True (default), a random state parameter will be generated for you. You may pass your own state as `str`,
    or set it to `None` so that the state parameter will not be included in the request. You may access that state in the
    `state` attribute from this request.
    * `nonce`: if True (default) and scope includes 'openid', a random nonce will be generated and included in the request.
     You may access that nonce in the `nonce` attribute from this request.
    * `code_verifier`: if `None`, and `code_challenge_method` is `'S256'` or `'plain'`, a valid `code_challenge`
    and `code_verifier` for PKCE will be automatically generated, and the `code_challenge` will be included
    in the request. You may pass your own `code_verifier` as a `str` parameter, in which case the appropriate
    `code_challenge` will be included in the request, according to the `code_challenge_method`.

    Args:
        authorization_endpoint: the uri for the authorization endpoint.
        client_id: the client_id to include in the request.
        redirect_uri: the redirect_uri to include in the request. This is required in OAuth 2.0 and optional
            in OAuth 2.1. Pass `None` if you don't need any redirect_uri in the Authorization Request.
        scope: the scope to include in the request, as an iterable of `str`, or a single space-separated `str`.
        response_type: the response type to include in the request.
        state: the state to include in the request, or `True` to autogenerate one (default).
        nonce: the nonce to include in the request, or `True` to autogenerate one (default).
        code_verifier: the state to include in the request, or `True` to autogenerate one (default).
        code_challenge_method: the method to use to derive the `code_challenge` from the `code_verifier`.
        issuer: Issuer Identifier value from the OAuth/OIDC Server, if known. Set it to `False` if the AS doesn't support Server Issuer Identification.
        **kwargs: extra parameters to include in the request, as-is.
    """

    exception_classes: Dict[str, Type[Exception]] = {
        "interaction_required": InteractionRequired,
        "login_required": LoginRequired,
        "session_selection_required": SessionSelectionRequired,
        "consent_required": ConsentRequired,
    }

    def __init__(
        self,
        authorization_endpoint: str,
        client_id: str,
        redirect_uri: Optional[str],
        scope: Union[None, str, Iterable[str]],
        response_type: str = "code",
        state: Union[str, bool, None] = True,
        nonce: Union[str, bool, None] = True,
        code_verifier: Optional[str] = None,
        code_challenge_method: Optional[str] = "S256",
        issuer: Union[str, bool, None] = None,
        **kwargs: Any,
    ) -> None:
        if state is True:
            state = secrets.token_urlsafe(32)
        elif state is False:
            state = None

        if scope is not None and isinstance(scope, str):
            scope = scope.split(" ")

        if nonce is True and scope is not None and "openid" in scope:
            nonce = secrets.token_urlsafe(32)
        elif nonce is False:
            nonce = None

        if scope is not None and not isinstance(scope, str):
            scope = " ".join(str(s) for s in scope)

        if "code_challenge" in kwargs:
            raise ValueError(
                "A code_challenge must not be passed as parameter. "
                "Pass the code_verifier instead, and the appropriate code_challenge "
                "will automatically be derived from it and included in the request, "
                "based on code_challenge_method."
            )

        if not code_challenge_method:
            code_verifier = code_challenge = code_challenge_method = None
        else:
            if not code_verifier:
                code_verifier = PkceUtils.generate_code_verifier()
            code_challenge = PkceUtils.derive_challenge(code_verifier, code_challenge_method)

        self.authorization_endpoint = authorization_endpoint
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.response_type = response_type
        self.scope = scope
        self.state = state
        self.nonce = nonce
        self.code_verifier = code_verifier
        self.code_challenge = code_challenge
        self.code_challenge_method = code_challenge_method
        self.kwargs = kwargs

        self.issuer = issuer

        self.args = dict(
            client_id=client_id,
            redirect_uri=redirect_uri,
            response_type=response_type,
            scope=scope,
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            **kwargs,
        )

    def sign_request_jwt(
        self, jwk: Union[Jwk, Dict[str, Any]], alg: Optional[str] = None
    ) -> Jwt:
        """Sign the `request` object that matches this Authorization Request parameters.

        Args:
            jwk: the JWK to use to sign the request
            alg: the alg to use to sign the request, if the passed `jwk` has no `alg` parameter.

        Returns:
            a :class:`Jwt` that contains the signed request object.
        """
        return Jwt.sign(
            claims={key: val for key, val in self.args.items() if val is not None},
            jwk=jwk,
            alg=alg,
        )

    def sign(
        self, jwk: Union[Jwk, Dict[str, Any]], alg: Optional[str] = None
    ) -> "AuthorizationRequest":
        """Sign the current Authorization Request.

        This replaces all parameters with a signed `request` JWT.

        Args:
            jwk: the JWK to use to sign the request
            alg: the alg to use to sign the request, if the passed `jwk` has no `alg` parameter.

        Returns:
            the signed Authorization Request
        """
        request_jwt = self.sign_request_jwt(jwk, alg)
        self.args = {"request": str(request_jwt)}
        return self

    def sign_and_encrypt_request_jwt(
        self,
        sign_jwk: Union[Jwk, Dict[str, Any]],
        enc_jwk: Union[Jwk, Dict[str, Any]],
        sign_alg: Optional[str] = None,
        enc_alg: Optional[str] = None,
        enc: Optional[str] = None,
    ) -> Jwt:
        """Sign and encrypt a `request` object for this Authorization Request.

        The signed `request` will contain the same parameters as this AuthorizationRequest.

        Args:
            sign_jwk: the JWK to use to sign the request
            enc_jwk: the JWK to use to encrypt the request
            sign_alg: the alg to use to sign the request, if the passed `jwk` has no `alg` parameter.
            enc_alg: the alg to use to encrypt the request, if the passed `jwk` has no `alg` parameter.
            enc: the encoding to use to encrypt the request, if the passed `jwk` has no `enc` parameter.

        Returns:
            the signed and encrypted request object, as a `jwskate.Jwt`
        """
        return Jwt.sign_and_encrypt(
            claims={key: val for key, val in self.args.items() if val is not None},
            sign_jwk=sign_jwk,
            sign_alg=sign_alg,
            enc_jwk=enc_jwk,
            enc_alg=enc_alg,
            enc=enc,
        )

    def sign_and_encrypt(
        self,
        sign_jwk: Union[Jwk, Dict[str, Any]],
        enc_jwk: Union[Jwk, Dict[str, Any]],
        sign_alg: Optional[str] = None,
        enc_alg: Optional[str] = None,
        enc: Optional[str] = None,
    ) -> "AuthorizationRequest":
        """Sign and encrypt the current Authorization Request.

        This replaces all parameters with a matching `request` object.

        Args:
            sign_jwk: the JWK to use to sign the request
            enc_jwk: the JWK to use to encrypt the request
            sign_alg: the alg to use to sign the request, if the passed `jwk` has no `alg` parameter.
            enc_alg: the alg to use to encrypt the request, if the passed `jwk` has no `alg` parameter.
            enc: the encoding to use to encrypt the request, if the passed `jwk` has no `enc` parameter.

        Returns:
            the same AuthorizationRequest, with a request object as parameter
        """
        request_jwt = self.sign_and_encrypt_request_jwt(
            sign_jwk=sign_jwk,
            enc_jwk=enc_jwk,
            sign_alg=sign_alg,
            enc_alg=enc_alg,
            enc=enc,
        )
        self.args = {"client_id": self.client_id, "request": str(request_jwt)}
        return self

    def validate_callback(self, response: str) -> AuthorizationResponse:
        """Validate an Authorization Response against this Request.

        Validate a given Authorization Response URI against this Authorization
        Request, and return an [AuthorizationResponse][requests_oauth2client.authorization_request.AuthorizationResponse].

        This includes matching the `state` parameter, checking for returned errors, and extracting the returned `code`
        and other parameters.

        Args:
            response: the Authorization Response URI. This can be the full URL, or just the query parameters.

        Returns:
            the extracted code, if the

        Raises:
            MismatchingState: if the response `state` does not match the expected value.
            OAuth2Error: if the response includes an error.
            MissingAuthCode: if the response does not contain a `code`.
        """
        try:
            response_url = furl(response)
        except ValueError:
            return self.on_response_error(response)

        # validate 'iss' according to https://www.ietf.org/archive/id/draft-ietf-oauth-iss-auth-resp-05.html
        expected_issuer = self.issuer
        if expected_issuer is not None:
            received_issuer = response_url.args.get("iss")
            if (expected_issuer is False and received_issuer is not None) or (
                expected_issuer and received_issuer != expected_issuer
            ):
                raise MismatchingIssuer(expected_issuer, received_issuer)

        requested_state = self.state
        if requested_state:
            received_state = response_url.args.get("state")
            if requested_state != received_state:
                raise MismatchingState(requested_state, received_state)

        error = response_url.args.get("error")
        if error:
            return self.on_response_error(response)

        code: str = response_url.args.get("code")
        if code is None:
            raise MissingAuthCode()

        return AuthorizationResponse(
            code_verifier=self.code_verifier,
            redirect_uri=self.redirect_uri,
            **response_url.args,
        )

    def on_response_error(self, response: str) -> AuthorizationResponse:
        """Error handler for Authorization Response errors.

        Triggered by [validate_callback()][requests_oauth2client.authorization_request.AuthorizationRequest.validate_callback] if the response uri contains
        an error.

        Args:
            response: the Authorization Response URI. This can be the full URL, or just the query parameters.

        Returns:
            may return a default code that will be returned by `validate_callback`. But this method will most likely raise exceptions instead.
        """
        response_url = furl(response)
        error = response_url.args.get("error")
        error_description = response_url.args.get("error_description")
        error_uri = response_url.args.get("error_uri")
        exception_class = self.exception_classes.get(error, AuthorizationResponseError)
        raise exception_class(error, error_description, error_uri)

    @property
    def uri(self) -> str:
        """Return the Authorization Request URI, as a `str`.

        You may also use `repr()` or `str()` on an AuthorizationRequest to obtain the same uri.

        Authorization requests typically look like:
        ```
        https://myas.local/authorize?client_id=<client_id>&response_type=code&scope=openid&redirect_uri=<redirect_uri>
        ```
        Unless they have been signed, and optionally encrypted, into a `request` object, then they look like:
        ```
        https://myas.local/authorize?client_id=<client_id>&request=<request>
        ```

        Returns:
            the Authorization Request URI.
        """
        return str(
            furl(
                self.authorization_endpoint,
                args={key: value for key, value in self.args.items() if value is not None},
            ).url
        )

    def __repr__(self) -> str:
        """Return the Authorization Request URI, as a `str`.

        Returns:
            the Authorization Request URI.
        """
        return self.uri

    def __eq__(self, other: Any) -> bool:
        """Check if this Authorization Request is the same as another one.

        Args:
            other: another AuthorizationRequest, or a url as string

        Returns:
            `True` if the other AuthorizationRequest is the same as this one, `False` otherwise
        """
        if isinstance(other, AuthorizationRequest):
            return (
                self.authorization_endpoint == other.authorization_endpoint
                and self.args == other.kwargs
                and self.issuer == other.issuer
            )
        elif isinstance(other, str):
            return self.uri == other
        return super().__eq__(other)


class RequestUriParameterAuthorizationRequest:
    """Represent an Authorization Request that includes a `request` object.

    Args:
        authorization_endpoint: the Authorization Endpoint uri
        client_id: the client_id
        request_uri: the request_uri
        expires_at: the expiration date for this request
    """

    @accepts_expires_in
    def __init__(
        self,
        authorization_endpoint: str,
        client_id: str,
        request_uri: str,
        expires_at: Optional[datetime] = None,
    ):
        self.authorization_endpoint = authorization_endpoint
        self.client_id = client_id
        self.request_uri = request_uri
        self.expires_at = expires_at

    @property
    def uri(self) -> str:
        """Return the Authorization Request URI, as a `str`.

        Returns:
            the Authorization Request URI
        """
        return str(
            furl(
                self.authorization_endpoint,
                args={"client_id": self.client_id, "request_uri": self.request_uri},
            ).url
        )

    def __repr__(self) -> str:
        """Return the Authorization Request URI, as a `str`.

        Returns:
             the Authorization Request URI
        """
        return self.uri
