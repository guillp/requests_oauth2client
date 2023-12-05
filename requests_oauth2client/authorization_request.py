"""Classes and utilities related to Authorization Requests and Responses."""

from __future__ import annotations

import re
import secrets
from datetime import datetime
from typing import Any, Callable, ClassVar, Final, Iterable, Sequence

from attrs import Factory, asdict, field, fields, frozen
from binapy import BinaPy
from furl import furl  # type: ignore[import-not-found]
from jwskate import JweCompact, Jwk, Jwt, SignedJwt

from .exceptions import (
    AuthorizationResponseError,
    ConsentRequired,
    InteractionRequired,
    LoginRequired,
    MismatchingIssuer,
    MismatchingState,
    MissingAuthCode,
    MissingIssuer,
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
            a `code_verifier` ready to use for PKCE

        """
        return secrets.token_urlsafe(96)

    @classmethod
    def derive_challenge(cls, verifier: str | bytes, method: str = "S256") -> str:
        """Derive the `code_challenge` from a given `code_verifier`.

        Args:
            verifier: a code verifier
            method: the method to use for deriving the challenge. Accepts 'S256' or 'plain'.

        Returns:
            a `code_challenge` derived from the given verifier

        """
        if isinstance(verifier, bytes):
            verifier = verifier.decode()

        if not cls.code_verifier_re.match(verifier):
            msg = f"Invalid code verifier, does not match {cls.code_verifier_re}"
            raise ValueError(
                msg,
                verifier,
            )

        if method == "S256":
            return BinaPy(verifier).to("sha256").to("b64u").ascii()
        elif method == "plain":
            return verifier
        else:
            msg = "Unsupported code_challenge_method"
            raise ValueError(msg, method)

    @classmethod
    def generate_code_verifier_and_challenge(cls, method: str = "S256") -> tuple[str, str]:
        """Generate a valid `code_verifier` and derive its `code_challenge`.

        Args:
            method: the method to use for deriving the challenge. Accepts 'S256' or 'plain'.

        Returns:
            a `(code_verifier, code_challenge)` tuple.

        """
        verifier = cls.generate_code_verifier()
        challenge = cls.derive_challenge(verifier, method)
        return verifier, challenge

    @classmethod
    def validate_code_verifier(cls, verifier: str, challenge: str, method: str = "S256") -> bool:
        """Validate a `code_verifier` against a `code_challenge`.

        Args:
            verifier: the `code_verifier`, exactly as submitted by the client on token request.
            challenge: the `code_challenge`, exactly as submitted by the client on authorization request.
            method: the method to use for deriving the challenge. Accepts 'S256' or 'plain'.

        Returns:
            `True` if verifier is valid, or `False` otherwise

        """
        return cls.code_verifier_re.match(verifier) is not None and cls.derive_challenge(verifier, method) == challenge


@frozen(init=False)
class AuthorizationResponse:
    """Represent a successful Authorization Response.

    An Authorization Response is the redirection initiated by the AS to the client's redirection
    endpoint (redirect_uri) after an Authorization Request. This Response is typically created with
    a call to `AuthorizationRequest.validate_callback()` once the call to the client Redirection
    Endpoint is made. AuthorizationResponse contains the following, all accessible as attributes:

     - all the parameters that have been returned by the AS, most notably the `code`, and optional
       parameters such as `state`.
     - the redirect_uri that was used for the Authorization Request
     - the code_verifier matching the code_challenge that was used for the Authorization Request

    Parameters `redirect_uri` and `code_verifier` must be those from the matching
    `AuthorizationRequest`. All other parameters including `code` and `state` must be those
    extracted from the Authorization Response parameters.

    Args:
        code: the authorization code returned by the AS
        redirect_uri: the redirect_uri that was passed as parameter in the AuthorizationRequest
        code_verifier: the code_verifier matching the code_challenge that was passed as
            parameter in the AuthorizationRequest
        state: the state returned by the AS
        **kwargs: other parameters as returned by the AS

    """

    code: str
    redirect_uri: str | None = None
    code_verifier: str | None = None
    state: str | None = None
    nonce: str | None = None
    acr_values: list[str] | None = None
    max_age: int | None = None
    issuer: str | None = None
    kwargs: dict[str, Any] = Factory(dict)

    def __init__(
        self,
        *,
        code: str,
        redirect_uri: str | None = None,
        code_verifier: str | None = None,
        state: str | None = None,
        nonce: str | None = None,
        acr_values: str | Sequence[str] | None = None,
        max_age: int | None = None,
        issuer: str | None = None,
        **kwargs: str,
    ):
        if not acr_values:
            acr_values = None
        elif isinstance(acr_values, str):
            acr_values = acr_values.split(" ")
        else:
            acr_values = list(acr_values)

        self.__attrs_init__(
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
            state=state,
            nonce=nonce,
            acr_values=acr_values,
            max_age=max_age,
            issuer=issuer,
            kwargs=kwargs,
        )

    def __getattr__(self, item: str) -> str | None:
        """Make additional parameters available as attributes.

        Args:
            item: the attribute name

        Returns:
            the attribute value, or None if it isn't part of the returned attributes

        """
        return self.kwargs.get(item)


GENERATE: Final = object()


@frozen(init=False)
class AuthorizationRequest:
    """Represent an Authorization Request.

    This class makes it easy to generate valid Authorization Request URI (possibly including a
    state, nonce, PKCE, and custom args), to store all parameters, and to validate an Authorization
    Response.

    All parameters passed at init time will be included in the request query parameters as-is,
    excepted for a few parameters which have a special behaviour:

    - `state`: if `GENERATE` (default), a random `state` parameter will be generated for you.
      You may pass your own `state` as `str`, or set it to `None` so that the `state` parameter
      will not be included in the request. You may access that state in the `state` attribute
      from this request.
    - `nonce`: if `GENERATE` (default) and `scope` includes 'openid', a random `nonce` will be
      generated and included in the request. You may access that `nonce` in the `nonce` attribute
      from this request.
    - `code_verifier`: if `None`, and `code_challenge_method` is `'S256'` or `'plain'`,
      a valid `code_challenge` and `code_verifier` for PKCE will be automatically generated,
      and the `code_challenge` will be included in the request.
      You may pass your own `code_verifier` as a `str` parameter, in which case the
      appropriate `code_challenge` will be included in the request, according to the
      `code_challenge_method`.
    - `authorization_response_iss_parameter_supported` and `issuer`:
       those are used for Server Issuer Identification. If `ìssuer` is set and an issuer is
       included in the Authorization Response, then the consistency between those 2 values will be
       checked when using `validate_callback()`. If issuer is not included in the response, and
       `authorization_response_iss_parameter_supported` is `False` (default), then no issuer check
       is performed. Set `authorization_response_iss_parameter_supported`
       to `True` to enforce server identification: if no issuer is included in the Authorization
       Response, then an error will be raised instead.

    Args:
        authorization_endpoint: the uri for the authorization endpoint.
        client_id: the client_id to include in the request.
        redirect_uri: the redirect_uri to include in the request. This is required in OAuth 2.0 and optional
            in OAuth 2.1. Pass `None` if you don't need any redirect_uri in the Authorization
            Request.
        scope: the scope to include in the request, as an iterable of `str`, or a single space-separated `str`.
        response_type: the response type to include in the request.
        state: the state to include in the request, or `GENERATE` to autogenerate one (default).
        nonce: the nonce to include in the request, or `GENERATE` to autogenerate one (default).
        code_verifier: the code verifier to include in the request.
            If left as `None` and `code_challenge_method` is set, a valid code_verifier
            will be generated.
        code_challenge_method: the method to use to derive the `code_challenge` from the `code_verifier`.
        acr_values: requested Authentication Context Class Reference values.
        issuer: Issuer Identifier value from the OAuth/OIDC Server, if using Server Issuer Identification.
        **kwargs: extra parameters to include in the request, as-is.

    """

    authorization_endpoint: str

    client_id: str = field(metadata={"query": True})
    redirect_uri: str | None = field(metadata={"query": True}, default=None)
    scope: tuple[str, ...] | None = field(metadata={"query": True}, default=("openid",))
    response_type: str = field(metadata={"query": True}, default="code")
    state: str | None = field(metadata={"query": True}, default=None)
    nonce: str | None = field(metadata={"query": True}, default=None)
    code_challenge_method: str | None = field(metadata={"query": True}, default="S256")
    acr_values: Sequence[str] | None = field(metadata={"query": True}, default=None)
    max_age: int | None = field(metadata={"query": True}, default=None)
    kwargs: dict[str, Any] = Factory(dict)

    code_verifier: str | None = None
    code_challenge: str | None = field(init=False, metadata={"query": True})
    authorization_response_iss_parameter_supported: bool = False
    issuer: str | None = None

    exception_classes: ClassVar[dict[str, type[Exception]]] = {
        "interaction_required": InteractionRequired,
        "login_required": LoginRequired,
        "session_selection_required": SessionSelectionRequired,
        "consent_required": ConsentRequired,
    }

    @classmethod
    def generate_state(cls) -> str:
        """Generate a random `state` parameter."""
        return secrets.token_urlsafe(32)

    @classmethod
    def generate_nonce(cls) -> str:
        """Generate a random `nonce`."""
        return secrets.token_urlsafe(32)

    def __init__(  # noqa: PLR0913, C901
        self,
        authorization_endpoint: str,
        *,
        client_id: str,
        redirect_uri: str | None = None,
        scope: None | str | Iterable[str] = "openid",
        response_type: str = "code",
        state: str | GENERATE | None = GENERATE,  # type: ignore[valid-type]
        nonce: str | GENERATE | None = GENERATE,  # type: ignore[valid-type]
        code_verifier: str | None = None,
        code_challenge_method: str | None = "S256",
        acr_values: str | Iterable[str] | None = None,
        max_age: int | None = None,
        issuer: str | None = None,
        authorization_response_iss_parameter_supported: bool = False,
        **kwargs: Any,
    ) -> None:
        if authorization_response_iss_parameter_supported and not issuer:
            msg = (
                "When 'authorization_response_iss_parameter_supported' is `True`, you must"
                " provide the expected `issuer` as parameter."
            )
            raise ValueError(msg)

        if state is GENERATE:
            state = self.generate_state()

        if nonce is GENERATE:
            nonce = self.generate_nonce() if scope is not None and "openid" in scope else None

        if not scope:
            scope = None

        if scope is not None:
            scope = tuple(scope.split(" ")) if isinstance(scope, str) else tuple(scope)

        if acr_values is not None:
            acr_values = tuple(acr_values.split()) if isinstance(acr_values, str) else tuple(acr_values)

        if max_age is not None and max_age < 0:
            msg = "The `max_age` parameter is a number of seconds and cannot be negative."
            raise ValueError(msg)

        if "code_challenge" in kwargs:
            msg = (
                "A `code_challenge` must not be passed as parameter. Pass the `code_verifier`"
                " instead, and the appropriate `code_challenge` will automatically be derived"
                " from it and included in the request, based on `code_challenge_method`."
            )
            raise ValueError(msg)

        code_challenge: str | None = None
        if code_challenge_method:
            if not code_verifier:
                code_verifier = PkceUtils.generate_code_verifier()
            code_challenge = PkceUtils.derive_challenge(code_verifier, code_challenge_method)
        else:
            code_verifier = None

        self.__attrs_init__(
            authorization_endpoint=authorization_endpoint,
            client_id=client_id,
            redirect_uri=redirect_uri,
            issuer=issuer,
            response_type=response_type,
            scope=scope,
            state=state,
            nonce=nonce,
            code_verifier=code_verifier,
            code_challenge_method=code_challenge_method,
            acr_values=acr_values,
            max_age=max_age,
            authorization_response_iss_parameter_supported=authorization_response_iss_parameter_supported,
            kwargs=kwargs,
        )
        object.__setattr__(self, "code_challenge", code_challenge)

    def as_dict(self) -> dict[str, Any]:
        """Return the full argument dict.

        This can be used to serialize this request and/or to initialize a similar request.

        """
        d = asdict(self)
        d.update(**d.pop("kwargs", {}))
        d.pop("code_challenge")
        return d

    @property
    def args(self) -> dict[str, Any]:
        """Return a dict with all the query parameters from this AuthorizationRequest.

        Returns:
            a dict of parameters

        """
        d = {field.name: getattr(self, field.name) for field in fields(type(self)) if field.metadata.get("query")}
        if d["scope"]:
            d["scope"] = " ".join(d["scope"])
        d.update(self.kwargs)

        return {key: val for key, val in d.items() if val is not None}

    def validate_callback(self, response: str) -> AuthorizationResponse:
        """Validate an Authorization Response against this Request.

        Validate a given Authorization Response URI against this Authorization Request, and return
        an
        [AuthorizationResponse][requests_oauth2client.authorization_request.AuthorizationResponse].

        This includes matching the `state` parameter, checking for returned errors, and extracting
        the returned `code` and other parameters.

        Args:
            response: the Authorization Response URI. This can be the full URL, or just the
                query parameters (still encoded as x-www-form-urlencoded).

        Returns:
            the extracted code, if all checks are successful

        Raises:
            MismatchingIssuer: if the 'iss' received from the response does not match the
                expected value.
            MismatchingState: if the response `state` does not match the expected value.
            OAuth2Error: if the response includes an error.
            MissingAuthCode: if the response does not contain a `code`.
            NotImplementedError: if response_type anything else than 'code'.

        """
        try:
            response_url = furl(response)
        except ValueError:
            return self.on_response_error(response)

        # validate 'iss' according to RFC9207
        received_issuer = response_url.args.get("iss")
        if self.authorization_response_iss_parameter_supported or received_issuer:
            if received_issuer is None:
                raise MissingIssuer()
            if self.issuer and received_issuer != self.issuer:
                raise MismatchingIssuer(self.issuer, received_issuer)

        # validate state
        requested_state = self.state
        if requested_state:
            received_state = response_url.args.get("state")
            if requested_state != received_state:
                raise MismatchingState(requested_state, received_state)

        error = response_url.args.get("error")
        if error:
            return self.on_response_error(response)

        if "code" in self.response_type:
            code: str = response_url.args.get("code")
            if code is None:
                raise MissingAuthCode()
        else:
            raise NotImplementedError()

        return AuthorizationResponse(
            code_verifier=self.code_verifier,
            redirect_uri=self.redirect_uri,
            nonce=self.nonce,
            acr_values=self.acr_values,
            max_age=self.max_age,
            **response_url.args,
        )

    def sign_request_jwt(
        self,
        jwk: Jwk | dict[str, Any],
        alg: str | None = None,
        lifetime: int | None = None,
    ) -> SignedJwt:
        """Sign the `request` object that matches this Authorization Request parameters.

        Args:
            jwk: the JWK to use to sign the request
            alg: the alg to use to sign the request, if the provided `jwk` has no `alg` parameter.
            lifetime: an optional number of seconds of validity for the signed request.
                If present, `iat` an `exp` claims will be included in the signed JWT.

        Returns:
            a `Jwt` that contains the signed request object.

        """
        claims = self.args
        if lifetime:
            claims["iat"] = Jwt.timestamp()
            claims["exp"] = Jwt.timestamp(lifetime)
        return Jwt.sign(
            claims,
            key=jwk,
            alg=alg,
        )

    def sign(
        self,
        jwk: Jwk | dict[str, Any],
        alg: str | None = None,
        lifetime: int | None = None,
    ) -> RequestParameterAuthorizationRequest:
        """Sign this Authorization Request and return a new one.

        This replaces all parameters with a signed `request` JWT.

        Args:
            jwk: the JWK to use to sign the request
            alg: the alg to use to sign the request, if the provided `jwk` has no `alg` parameter.
            lifetime: lifetime of the resulting Jwt (used to calculate the 'exp' claim).
                By default, don't use an 'exp' claim.

        Returns:
            the signed Authorization Request

        """
        request_jwt = self.sign_request_jwt(jwk, alg, lifetime)
        return RequestParameterAuthorizationRequest(
            authorization_endpoint=self.authorization_endpoint,
            client_id=self.client_id,
            request=str(request_jwt),
            expires_at=request_jwt.expires_at,
        )

    def sign_and_encrypt_request_jwt(
        self,
        sign_jwk: Jwk | dict[str, Any],
        enc_jwk: Jwk | dict[str, Any],
        sign_alg: str | None = None,
        enc_alg: str | None = None,
        enc: str = "A128CBC-HS256",
        lifetime: int | None = None,
    ) -> JweCompact:
        """Sign and encrypt a `request` object for this Authorization Request.

        The signed `request` will contain the same parameters as this AuthorizationRequest.

        Args:
            sign_jwk: the JWK to use to sign the request
            enc_jwk: the JWK to use to encrypt the request
            sign_alg: the alg to use to sign the request, if `sign_jwk` has no `alg` parameter.
            enc_alg: the alg to use to encrypt the request, if `enc_jwk` has no `alg` parameter.
            enc: the encoding to use to encrypt the request.
            lifetime: lifetime of the resulting Jwt (used to calculate the 'exp' claim).
                By default, do not include an 'exp' claim.

        Returns:
            the signed and encrypted request object, as a `jwskate.Jwt`

        """
        claims = self.args
        if lifetime:
            claims["iat"] = Jwt.timestamp()
            claims["exp"] = Jwt.timestamp(lifetime)
        return Jwt.sign_and_encrypt(
            claims=claims,
            sign_key=sign_jwk,
            sign_alg=sign_alg,
            enc_key=enc_jwk,
            enc_alg=enc_alg,
            enc=enc,
        )

    def sign_and_encrypt(
        self,
        sign_jwk: Jwk | dict[str, Any],
        enc_jwk: Jwk | dict[str, Any],
        sign_alg: str | None = None,
        enc_alg: str | None = None,
        enc: str = "A128CBC-HS256",
        lifetime: int | None = None,
    ) -> RequestParameterAuthorizationRequest:
        """Sign and encrypt the current Authorization Request.

        This replaces all parameters with a matching `request` object.

        Args:
            sign_jwk: the JWK to use to sign the request
            enc_jwk: the JWK to use to encrypt the request
            sign_alg: the alg to use to sign the request, if `sign_jwk` has no `alg` parameter.
            enc_alg: the alg to use to encrypt the request, if `enc_jwk` has no `alg` parameter.
            enc: the encoding to use to encrypt the request.
            lifetime: lifetime of the resulting Jwt (used to calculate the 'exp' claim).
                By default, do not include an 'exp' claim.

        Returns:
            a `RequestParameterAuthorizationRequest`, with a request object as parameter

        """
        request_jwt = self.sign_and_encrypt_request_jwt(
            sign_jwk=sign_jwk,
            enc_jwk=enc_jwk,
            sign_alg=sign_alg,
            enc_alg=enc_alg,
            enc=enc,
            lifetime=lifetime,
        )
        return RequestParameterAuthorizationRequest(
            authorization_endpoint=self.authorization_endpoint,
            client_id=self.client_id,
            request=str(request_jwt),
        )

    def on_response_error(self, response: str) -> AuthorizationResponse:
        """Error handler for Authorization Response errors.

        Triggered by
        [validate_callback()][requests_oauth2client.authorization_request.AuthorizationRequest.validate_callback]
        if the response uri contains an error.

        Args:
            response: the Authorization Response URI. This can be the full URL, or just the query parameters.

        Returns:
            may return a default code that will be returned by `validate_callback`. But this method
            will most likely raise exceptions instead.

        """
        response_url = furl(response)
        error = response_url.args.get("error")
        error_description = response_url.args.get("error_description")
        error_uri = response_url.args.get("error_uri")
        exception_class = self.exception_classes.get(error, AuthorizationResponseError)
        raise exception_class(error, error_description, error_uri)

    @property
    def furl(self) -> furl:
        """Return the Authorization Request URI, as a `furl`."""
        return furl(
            self.authorization_endpoint,
            args=self.args,
        )

    @property
    def uri(self) -> str:
        """Return the Authorization Request URI, as a `str`."""
        return str(self.furl.url)

    def __repr__(self) -> str:
        """Return the Authorization Request URI, as a `str`."""
        return self.uri


class RequestParameterAuthorizationRequest:
    """Represent an Authorization Request that includes a `request` JWT.

    Args:
        authorization_endpoint: the Authorization Endpoint uri
        client_id: the client_id
        request: the request JWT
        expires_at: the expiration date for this request

    """

    @accepts_expires_in
    def __init__(
        self,
        authorization_endpoint: str,
        client_id: str,
        request: str,
        expires_at: datetime | None = None,
    ):
        self.authorization_endpoint = authorization_endpoint
        self.client_id = client_id
        self.request = request
        self.expires_at = expires_at

    @property
    def furl(self) -> furl:
        """Return the Authorization Request URI, as a `furl` instance."""
        return furl(
            self.authorization_endpoint,
            args={"client_id": self.client_id, "request": self.request},
        )

    @property
    def uri(self) -> str:
        """Return the Authorization Request URI, as a `str`."""
        return str(self.furl.url)

    def __repr__(self) -> str:
        """Return the Authorization Request URI, as a `str`.

        Returns:
             the Authorization Request URI

        """
        return self.uri


class RequestUriParameterAuthorizationRequest:
    """Represent an Authorization Request that includes a `request_uri` parameter.

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
        expires_at: datetime | None = None,
    ):
        self.authorization_endpoint = authorization_endpoint
        self.client_id = client_id
        self.request_uri = request_uri
        self.expires_at = expires_at

    @property
    def furl(self) -> furl:
        """Return the Authorization Request URI, as a `furl` instance."""
        return furl(
            self.authorization_endpoint,
            args={"client_id": self.client_id, "request_uri": self.request_uri},
        )

    @property
    def uri(self) -> str:
        """Return the Authorization Request URI, as a `str`."""
        return str(self.furl.url)

    def __repr__(self) -> str:
        """Return the Authorization Request URI, as a `str`."""
        return self.uri


class AuthorizationRequestSerializer:
    """(De)Serializer for `AuthorizationRequest` instances.

    You might need to store pending authorization requests in session, either server-side or client-
    side. This class is here to help you do that.

    """

    def __init__(
        self,
        dumper: Callable[[AuthorizationRequest], str] | None = None,
        loader: Callable[[str], AuthorizationRequest] | None = None,
    ):
        self.dumper = dumper or self.default_dumper
        self.loader = loader or self.default_loader

    @staticmethod
    def default_dumper(azr: AuthorizationRequest) -> str:
        """Provide a default dumper implementation.

        Serialize an AuthorizationRequest as JSON, then compress with deflate, then encodes as
        base64url.

        Args:
            azr: the `AuthorizationRequest` to serialize

        Returns:
            the serialized value

        """
        d = asdict(azr)
        d.update(**d.pop("kwargs", {}))
        d.pop("code_challenge")
        return BinaPy.serialize_to("json", d).to("deflate").to("b64u").ascii()

    def default_loader(
        self, serialized: str, azr_class: type[AuthorizationRequest] = AuthorizationRequest
    ) -> AuthorizationRequest:
        """Provide a default deserializer implementation.

        This does the opposite operations than `default_dumper`.

        Args:
            serialized: the serialized AuthorizationRequest
            azr_class: the class to deserialize the Authorization Request to

        Returns:
            an AuthorizationRequest

        """
        args = BinaPy(serialized).decode_from("b64u").decode_from("deflate").parse_from("json")
        return azr_class(**args)

    def dumps(self, azr: AuthorizationRequest) -> str:
        """Serialize and compress a given AuthorizationRequest for easier storage.

        Args:
            azr: an AuthorizationRequest to serialize

        Returns:
            the serialized AuthorizationRequest, as a str

        """
        return self.dumper(azr)

    def loads(self, serialized: str) -> AuthorizationRequest:
        """Deserialize a serialized AuthorizationRequest.

        Args:
            serialized: the serialized AuthorizationRequest

        Returns:
            the deserialized AuthorizationRequest

        """
        return self.loader(serialized)
