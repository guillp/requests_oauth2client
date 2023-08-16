"""This module contains the `OAuth2Client` class."""
from __future__ import annotations

from typing import Any, Iterable

import requests
from jwskate import Jwk, JwkSet, Jwt
from typing_extensions import Literal

from .auth import BearerAuth
from .authorization_request import (
    AuthorizationRequest,
    AuthorizationResponse,
    RequestUriParameterAuthorizationRequest,
)
from .backchannel_authentication import BackChannelAuthenticationResponse
from .client_authentication import ClientSecretPost, PrivateKeyJwt, client_auth_factory
from .device_authorization import DeviceAuthorizationResponse
from .discovery import oidc_discovery_document_url
from .exceptions import (
    AccessDenied,
    AuthorizationPending,
    BackChannelAuthenticationError,
    DeviceAuthorizationError,
    ExpiredToken,
    IntrospectionError,
    InvalidBackChannelAuthenticationResponse,
    InvalidClient,
    InvalidDeviceAuthorizationResponse,
    InvalidGrant,
    InvalidPushedAuthorizationResponse,
    InvalidRequest,
    InvalidScope,
    InvalidTarget,
    InvalidTokenResponse,
    RevocationError,
    ServerError,
    SlowDown,
    UnauthorizedClient,
    UnknownIntrospectionError,
    UnknownTokenEndpointError,
    UnsupportedTokenType,
)
from .tokens import BearerToken, IdToken
from .utils import validate_endpoint_uri


class OAuth2Client:
    """An OAuth 2.x client, that can send requests to an OAuth 2.x Authorization Server.

    `OAuth2Client` is able to obtain tokens from the Token Endpoint using any of the standardised Grant Types,
    and to communicate with the various backend endpoints like the Revocation, Introspection, and UserInfo Endpoint.

    To init an OAuth2Client, you only need the url to the Token Endpoint and the Credentials that will be used to authenticate
    to that endpoint. Other endpoint urls, such as the  can be passed as parameter as well if you intend to use them.


    This class is not intended to help with the end-user authentication or any request that goes in a browser.
    For authentication requests, see [AuthorizationRequest][requests_oauth2client.authorization_request.AuthorizationRequest].
    You may use the helper method `authorization_request()` to generate `AuthorizationRequest`s with the preconfigured
    `authorization_endpoint`, `client_id` and `redirect_uri' from this client.

    Args:
        token_endpoint: the Token Endpoint URI where this client will get access tokens
        auth: the authentication handler to use for client authentication on the token endpoint. Can be a [requests.auth.AuthBase][] instance (which will be as-is), or a tuple of `(client_id, client_secret)` which will initialize an instance of [ClientSecretPost][requests_oauth2client.client_authentication.ClientSecretPost], a `(client_id, jwk)` to initialize a [PrivateKeyJwt][requests_oauth2client.client_authentication.PrivateKeyJwt], or a `client_id` which will use [PublicApp][requests_oauth2client.client_authentication.PublicApp] authentication.
        client_id: client ID
        client_secret: client secret
        private_key: private_key to use for client authentication
        revocation_endpoint: the Revocation Endpoint URI to use for revoking tokens
        introspection_endpoint: the Introspection Endpoint URI to use to get info about tokens
        userinfo_endpoint: the Userinfo Endpoint URI to use to get information about the user
        authorization_endpoint: the Authorization Endpoint URI for initializing Authorization Requests
        redirect_uri: the redirect_uri for this client
        backchannel_authentication_endpoint: the BackChannel Authentication URI
        device_authorization_endpoint: the Device Authorization Endpoint URI to use to authorize devices
        jwks_uri: the JWKS URI to use to obtain the AS public keys
        code_challenge_method: challenge method to use for PKCE (should always be 'S256')
        session: a requests Session to use when sending HTTP requests. Useful if some extra parameters such as proxy or client certificate must be used to connect to the AS.
        **extra_metadata: additional metadata for this client, unused by this class, but may be used by subclasses. Those will be accessible with the `extra_metadata` attribute.

    Usage:
        ```python
        client = OAuth2Client(
            token_endpoint="https://my.as.local/token",
            revocation_endpoint="https://my.as.local/revoke",
            auth=("client_id", "client_secret"),
        )

        # once initialized, a client can send requests to its configured endpoints
        cc_token = client.client_credentials(scope="my_scope")
        ac_token = client.authorization_code(code="my_code")
        client.revoke_access_token(cc_token)
        ```
    """

    exception_classes: dict[str, type[Exception]] = {
        "server_error": ServerError,
        "invalid_request": InvalidRequest,
        "invalid_client": InvalidClient,
        "invalid_scope": InvalidScope,
        "invalid_target": InvalidTarget,
        "invalid_grant": InvalidGrant,
        "access_denied": AccessDenied,
        "unauthorized_client": UnauthorizedClient,
        "authorization_pending": AuthorizationPending,
        "slow_down": SlowDown,
        "expired_token": ExpiredToken,
        "unsupported_token_type": UnsupportedTokenType,
    }

    token_class: type[BearerToken] = BearerToken

    def __init__(
        self,
        token_endpoint: str,
        auth: (
            requests.auth.AuthBase
            | tuple[str, str]
            | tuple[str, Jwk]
            | tuple[str, dict[str, Any]]
            | str
            | None
        ) = None,
        *,
        client_id: str | None = None,
        client_secret: str | None = None,
        private_key: Jwk | dict[str, Any] | None = None,
        revocation_endpoint: str | None = None,
        introspection_endpoint: str | None = None,
        userinfo_endpoint: str | None = None,
        authorization_endpoint: str | None = None,
        redirect_uri: str | None = None,
        backchannel_authentication_endpoint: str | None = None,
        device_authorization_endpoint: str | None = None,
        pushed_authorization_request_endpoint: str | None = None,
        jwks_uri: str | None = None,
        authorization_server_jwks: JwkSet | dict[str, Any] | None = None,
        issuer: str | None = None,
        id_token_signed_response_alg: str | None = "RS256",
        id_token_encrypted_response_alg: str | None = None,
        id_token_decryption_key: Jwk | dict[str, Any] | None = None,
        code_challenge_method: str = "S256",
        authorization_response_iss_parameter_supported: bool = False,
        session: requests.Session | None = None,
        **extra_metadata: Any,
    ):
        if authorization_response_iss_parameter_supported and not issuer:
            raise ValueError(
                "If the Authorization Server supports Issuer Identification, "
                "as specified by `authorization_response_iss_parameter_supported=True`, "
                "then you must specify the expected `issuer` value with parameter `issuer`."
            )
        self.token_endpoint = str(token_endpoint)
        self.revocation_endpoint = str(revocation_endpoint) if revocation_endpoint else None
        self.introspection_endpoint = (
            str(introspection_endpoint) if introspection_endpoint else None
        )
        self.userinfo_endpoint = str(userinfo_endpoint) if userinfo_endpoint else None
        self.authorization_endpoint = (
            str(authorization_endpoint) if authorization_endpoint else None
        )
        self.redirect_uri = str(redirect_uri) if redirect_uri else None
        self.backchannel_authentication_endpoint = (
            str(backchannel_authentication_endpoint)
            if backchannel_authentication_endpoint
            else None
        )
        self.device_authorization_endpoint = (
            str(device_authorization_endpoint) if device_authorization_endpoint else None
        )
        self.pushed_authorization_request_endpoint = (
            str(pushed_authorization_request_endpoint)
            if pushed_authorization_request_endpoint
            else None
        )
        self.jwks_uri = str(jwks_uri) if jwks_uri else None
        self.authorization_server_jwks = (
            JwkSet(authorization_server_jwks) if authorization_server_jwks else None
        )
        self.issuer = str(issuer) if issuer else None
        self.session = session or requests.Session()
        self.auth = client_auth_factory(
            auth,
            client_id=client_id,
            client_secret=client_secret,
            private_key=private_key,
            default_auth_handler=ClientSecretPost,
        )
        self.id_token_signed_response_alg = id_token_signed_response_alg
        self.id_token_encrypted_response_alg = id_token_encrypted_response_alg
        self.id_token_decryption_key = (
            Jwk(id_token_decryption_key) if id_token_decryption_key else None
        )
        self.code_challenge_method = code_challenge_method
        self.authorization_response_iss_parameter_supported = (
            authorization_response_iss_parameter_supported
        )
        self.extra_metadata = extra_metadata

    @property
    def client_id(self) -> str:
        """Client ID."""
        if hasattr(self.auth, "client_id"):
            return self.auth.client_id  # type: ignore[no-any-return]
        raise AttributeError(  # pragma: no cover
            "This client uses a custom authentication method without client_id."
        )

    @property
    def client_secret(self) -> str | None:
        """Client Secret."""
        if hasattr(self.auth, "client_secret"):
            return self.auth.client_secret  # type: ignore[no-any-return]
        return None

    @property
    def client_jwks(self) -> JwkSet:
        """A `JwkSet` containing the public keys for this client.

        Keys are:

        - the public key for client assertion signature verification (if using private_key_jwt)
        - the ID Token encryption key
        """
        jwks = JwkSet()
        if isinstance(self.auth, PrivateKeyJwt):
            jwks.add_jwk(self.auth.private_jwk.public_jwk().with_usage_parameters())
        if self.id_token_decryption_key:
            jwks.add_jwk(self.id_token_decryption_key.public_jwk().with_usage_parameters())
        return jwks

    def token_request(
        self, data: dict[str, Any], timeout: int = 10, **requests_kwargs: Any
    ) -> BearerToken:
        """Send a request to the token endpoint.

        Authentication will be added automatically based on the defined `auth` for this client.

        Args:
             data: parameters to send to the token endpoint. Items with a None or empty value will not be sent in the request.
             timeout: a timeout value for the call
             **requests_kwargs: additional parameters for requests.post()

        Returns:
            the token endpoint response, as [`BearerToken`][requests_oauth2client.tokens.BearerToken] instance.
        """
        token_endpoint = self._require_endpoint("token_endpoint")

        requests_kwargs = {
            key: value
            for key, value in requests_kwargs.items()
            if value is not None and value != ""
        }

        response = self.session.post(
            token_endpoint,
            auth=self.auth,
            data=data,
            timeout=timeout,
            **requests_kwargs,
        )
        if response.ok:
            return self.parse_token_response(response)

        return self.on_token_error(response)

    def parse_token_response(self, response: requests.Response) -> BearerToken:
        """Parse a Response returned by the Token Endpoint.

        Invoked by [token_request][requests_oauth2client.client.OAuth2Client.token_request] to parse responses returned by the Token Endpoint.
        Those response contain an `access_token` and additional attributes.

        Args:
            response: the [Response][requests.Response] returned by the Token Endpoint.

        Returns:
            a [`BearerToken`][requests_oauth2client.tokens.BearerToken] based on the response contents.
        """
        try:
            token_response = self.token_class(**response.json())
            return token_response
        except Exception as response_class_exc:
            try:
                return self.on_token_error(response)
            except Exception as token_error_exc:
                raise token_error_exc from response_class_exc

    def on_token_error(self, response: requests.Response) -> BearerToken:
        """Error handler for `token_request()`.

        Invoked by [token_request][requests_oauth2client.client.OAuth2Client.token_request] when the Token Endpoint returns an error.

        Args:
            response: the [Response][requests.Response] returned by the Token Endpoint.

        Returns:
            nothing, and raises an exception instead. But a subclass may return a [`BearerToken`][requests_oauth2client.tokens.BearerToken] to implement a default behaviour if needed.
        """
        try:
            data = response.json()
            error = data["error"]
            error_description = data.get("error_description")
            error_uri = data.get("error_uri")
            exception_class = self.exception_classes.get(error, UnknownTokenEndpointError)
            exception = exception_class(response, error, error_description, error_uri)
        except Exception as exc:
            raise InvalidTokenResponse(response) from exc
        raise exception

    def client_credentials(
        self,
        scope: str | Iterable[str] | None = None,
        requests_kwargs: dict[str, Any] | None = None,
        **token_kwargs: Any,
    ) -> BearerToken:
        """Send a request to the token endpoint using the `client_credentials` grant.

        Args:
            scope: the scope to send with the request. Can be a str, or an iterable of str.
                to pass that way include `scope`, `audience`, `resource`, etc.
            requests_kwargs: additional parameters for the call to requests
            **token_kwargs: additional parameters for the token endpoint, alongside `grant_type`. Common parameters

        Returns:
            a TokenResponse
        """
        requests_kwargs = requests_kwargs or {}

        if scope is not None and not isinstance(scope, str):
            try:
                scope = " ".join(scope)
            except Exception as exc:
                raise ValueError("Unsupported scope value") from exc

        data = dict(grant_type="client_credentials", scope=scope, **token_kwargs)
        return self.token_request(data, **requests_kwargs)

    def authorization_code(
        self,
        code: str | AuthorizationResponse,
        validate: bool = True,
        requests_kwargs: dict[str, Any] | None = None,
        **token_kwargs: Any,
    ) -> BearerToken:
        """Send a request to the token endpoint with the `authorization_code` grant.

        Args:
             code: an authorization code or an `AuthorizationResponse` to exchange for tokens
             validate: if `True`, validate the received ID Token (this works only if `code` is an AuthorizationResponse)
             requests_kwargs: additional parameters for the call to requests
             **token_kwargs: additional parameters for the token endpoint, alongside `grant_type`, `code`, etc.

        Returns:
            a `BearerToken`
        """
        azr: AuthorizationResponse | None = None
        if isinstance(code, AuthorizationResponse):
            token_kwargs.setdefault("code_verifier", code.code_verifier)
            token_kwargs.setdefault("redirect_uri", code.redirect_uri)
            azr = code
            code = code.code

        requests_kwargs = requests_kwargs or {}

        data = dict(grant_type="authorization_code", code=code, **token_kwargs)
        token = self.token_request(data, **requests_kwargs)
        if validate and token.id_token and isinstance(azr, AuthorizationResponse):
            token.validate_id_token(self, azr)
        return token

    def refresh_token(
        self,
        refresh_token: str | BearerToken,
        requests_kwargs: dict[str, Any] | None = None,
        **token_kwargs: Any,
    ) -> BearerToken:
        """Send a request to the token endpoint with the `refresh_token` grant.

        Args:
            refresh_token: a refresh_token, as a string, or as a `BearerToken`. That `BearerToken` must have a `refresh_token`.
            requests_kwargs: additional parameters for the call to `requests`
            **token_kwargs: additional parameters for the token endpoint, alongside `grant_type`, `refresh_token`, etc.

        Returns:
            a `BearerToken`
        """
        if isinstance(refresh_token, BearerToken):
            if refresh_token.refresh_token is None or not isinstance(
                refresh_token.refresh_token, str
            ):
                raise ValueError("This BearerToken doesn't have a refresh_token")
            refresh_token = refresh_token.refresh_token

        requests_kwargs = requests_kwargs or {}
        data = dict(grant_type="refresh_token", refresh_token=refresh_token, **token_kwargs)
        return self.token_request(data, **requests_kwargs)

    def device_code(
        self,
        device_code: str | DeviceAuthorizationResponse,
        requests_kwargs: dict[str, Any] | None = None,
        **token_kwargs: Any,
    ) -> BearerToken:
        """Send a request to the token endpoint using the Device Code grant.

        The grant_type is `urn:ietf:params:oauth:grant-type:device_code`.
        This needs a Device Code, or a `DeviceAuthorizationResponse` as parameter.

        Args:
            device_code: a device code, or a `DeviceAuthorizationResponse`
            requests_kwargs: additional parameters for the call to requests
            **token_kwargs: additional parameters for the token endpoint, alongside `grant_type`, `device_code`, etc.

        Returns:
            a `BearerToken`
        """
        if isinstance(device_code, DeviceAuthorizationResponse):
            if device_code.device_code is None or not isinstance(device_code.device_code, str):
                raise ValueError("This DeviceAuthorizationResponse doesn't have a device_code")
            device_code = device_code.device_code

        requests_kwargs = requests_kwargs or {}
        data = dict(
            grant_type="urn:ietf:params:oauth:grant-type:device_code",
            device_code=device_code,
            **token_kwargs,
        )
        return self.token_request(data, **requests_kwargs)

    def ciba(
        self,
        auth_req_id: str | BackChannelAuthenticationResponse,
        requests_kwargs: dict[str, Any] | None = None,
        **token_kwargs: Any,
    ) -> BearerToken:
        """Send a CIBA request to the Token Endpoint.

        A CIBA request is a Token Request using the `urn:openid:params:grant-type:ciba` grant.

        Args:
            auth_req_id: an authentication request ID, as returned by the AS
            requests_kwargs: additional parameters for the call to requests
            **token_kwargs: additional parameters for the token endpoint, alongside `grant_type`, `auth_req_id`, etc.

        Returns:
            a `BearerToken`
        """
        if isinstance(auth_req_id, BackChannelAuthenticationResponse):
            if auth_req_id.auth_req_id is None or not isinstance(auth_req_id.auth_req_id, str):
                raise ValueError(
                    "This BackChannelAuthenticationResponse doesn't have an auth_req_id"
                )
            auth_req_id = auth_req_id.auth_req_id

        requests_kwargs = requests_kwargs or {}
        data = dict(
            grant_type="urn:openid:params:grant-type:ciba",
            auth_req_id=auth_req_id,
            **token_kwargs,
        )
        return self.token_request(data, **requests_kwargs)

    def token_exchange(
        self,
        subject_token: str | BearerToken | IdToken,
        subject_token_type: str | None = None,
        actor_token: None | str | BearerToken | IdToken = None,
        actor_token_type: str | None = None,
        requested_token_type: str | None = None,
        requests_kwargs: dict[str, Any] | None = None,
        **token_kwargs: Any,
    ) -> BearerToken:
        """Send a Token Exchange request.

        A Token Exchange request is actually a request to the Token Endpoint with a grant_type `urn:ietf:params:oauth:grant-type:token-exchange`.

        Args:
            subject_token: the subject token to exchange for a new token.
            subject_token_type: a token type identifier for the subject_token, mandatory if it cannot be guessed based
                on `type(subject_token)`.
            actor_token: the actor token to include in the request, if any.
            actor_token_type: a token type identifier for the actor_token, mandatory if it cannot be guessed based
                on `type(actor_token)`.
            requested_token_type: a token type identifier for the requested token.
            requests_kwargs: additional parameters to pass to the underlying `requests.post()` call.
            **token_kwargs: additional parameters to include in the request body.

        Returns:
            a `BearerToken` as returned by the Authorization Server.
        """
        requests_kwargs = requests_kwargs or {}

        try:
            subject_token_type = self.get_token_type(subject_token_type, subject_token)
        except ValueError:
            raise TypeError(
                "Cannot determine the kind of 'subject_token' you provided. "
                "Please specify a 'subject_token_type'."
            )
        if actor_token:  # pragma: no branch
            try:
                actor_token_type = self.get_token_type(actor_token_type, actor_token)
            except ValueError:
                raise TypeError(
                    "Cannot determine the kind of 'actor_token' you provided. "
                    "Please specify an 'actor_token_type'."
                )

        data = dict(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=subject_token,
            subject_token_type=subject_token_type,
            actor_token=actor_token,
            actor_token_type=actor_token_type,
            requested_token_type=requested_token_type,
            **token_kwargs,
        )
        return self.token_request(data, **requests_kwargs)

    def jwt_bearer(
        self,
        assertion: Jwt | str,
        requests_kwargs: dict[str, Any] | None = None,
        **token_kwargs: Any,
    ) -> BearerToken:
        """Send a request using a JWT as authorization grant.

        This is a defined in (RFC7523 $2.1)[https://www.rfc-editor.org/rfc/rfc7523.html#section-2.1).

        Args:
            assertion: a JWT (as an instance of `jwskate.Jwt` or as a `str`) to use as authorization grant.
            requests_kwargs: additional parameters to pass to the underlying `requests.post()` call.
            **token_kwargs: additional parameters to include in the request body.

        Returns:
            a `BearerToken` as returned by the Authorization Server.
        """
        requests_kwargs = requests_kwargs or {}

        if not isinstance(assertion, Jwt):
            assertion = Jwt(assertion)

        data = dict(
            grant_type="urn:ietf:params:oauth:grant-type:jwt-bearer",
            assertion=assertion,
            **token_kwargs,
        )

        return self.token_request(data, **requests_kwargs)

    def resource_owner_password(
        self,
        username: str,
        password: str,
        requests_kwargs: dict[str, Any] | None = None,
        **token_kwargs: Any,
    ) -> BearerToken:
        """Send a request using the Resource Owner Password Grant.

        This Grant Type is deprecated and should only be used when there is no other choice.

        Args:
            username: the resource owner user name
            password: the resource owner password
            requests_kwargs: additional parameters to pass to the underlying `requests.post()` call.
            **token_kwargs: additional parameters to include in the request body.

        Returns:
            a `BearerToken` as returned by the Authorization Server
        """
        requests_kwargs = requests_kwargs or {}
        data = dict(
            grant_type="password",
            username=username,
            password=password,
            **token_kwargs,
        )

        return self.token_request(data, **requests_kwargs)

    def authorization_request(
        self,
        scope: None | str | Iterable[str] = "openid",
        response_type: str = "code",
        redirect_uri: str | None = None,
        state: str | Literal[True] | None = True,
        nonce: str | Literal[True] | None = True,
        code_verifier: str | None = None,
        **kwargs: Any,
    ) -> AuthorizationRequest:
        """Generate an Authorization Request for this client.

        Args:
            scope: the scope to use
            response_type: the response_type to use
            redirect_uri: the redirect_uri to include in the request. By default, the redirect_uri defined at init time is used.
            state: the state parameter to use. Leave default to generate a random value.
            nonce: a nonce. Leave default to generate a random value.
            code_verifier: the PKCE code verifier to use. Leave default to generate a random value.
            **kwargs: additional parameters to include in the auth request

        Returns:
            an AuthorizationRequest with the supplied parameters
        """
        authorization_endpoint = self._require_endpoint("authorization_endpoint")

        redirect_uri = redirect_uri or self.redirect_uri
        if not redirect_uri:
            raise AttributeError(
                "No 'redirect_uri' defined for this client. "
                "You must either pass a redirect_uri as parameter to this method, "
                "or include a redirect_uri when initializing your OAuth2Client."
            )

        if response_type != "code":
            raise ValueError("Only response_type=code is supported.")

        return AuthorizationRequest(
            authorization_endpoint=authorization_endpoint,
            client_id=self.client_id,
            redirect_uri=redirect_uri,
            issuer=self.issuer,
            response_type=response_type,
            scope=scope,
            state=state,
            nonce=nonce,
            code_verifier=code_verifier,
            code_challenge_method=self.code_challenge_method,
            **kwargs,
        )

    def pushed_authorization_request(
        self, authorization_request: AuthorizationRequest
    ) -> RequestUriParameterAuthorizationRequest:
        """Send a Pushed Authorization Request.

        This sends a request to the Pushed Authorization Request Endpoint, and returns a
        `RequestUriParameterAuthorizationRequest` initialized with the AS response.

        Args:
            authorization_request: the authorization request to send

        Returns:
            the `RequestUriParameterAuthorizationRequest` initialized based on the AS response
        """
        pushed_authorization_request_endpoint = self._require_endpoint(
            "pushed_authorization_request_endpoint"
        )

        response = self.session.post(
            pushed_authorization_request_endpoint,
            data=authorization_request.args,
            auth=self.auth,
        )
        if not response.ok:
            return self.on_pushed_authorization_request_error(response)

        response_json = response.json()
        request_uri = response_json.get("request_uri")
        expires_in = response_json.get("expires_in")

        return RequestUriParameterAuthorizationRequest(
            authorization_endpoint=authorization_request.authorization_endpoint,
            client_id=authorization_request.client_id,
            request_uri=request_uri,
            expires_in=expires_in,
        )

    def on_pushed_authorization_request_error(
        self, response: requests.Response
    ) -> RequestUriParameterAuthorizationRequest:
        """Error Handler for Pushed Authorization Endpoint errors.

        Args:
            response: the HTTP response as returned by the AS PAR endpoint.

        Returns:
            a RequestUriParameterAuthorizationRequest, if the error is recoverable

        Raises:
            EndpointError: a subclass of this error depending on the error returned by the AS
            InvalidPushedAuthorizationResponse: if the returned response is not following the specifications
            UnknownTokenEndpointError: for unknown/unhandled errors
        """
        try:
            data = response.json()
            error = data["error"]
            error_description = data.get("error_description")
            error_uri = data.get("error_uri")
            exception_class = self.exception_classes.get(error, UnknownTokenEndpointError)
            exception = exception_class(response, error, error_description, error_uri)
        except Exception as exc:
            raise InvalidPushedAuthorizationResponse(response) from exc
        raise exception

    def userinfo(self, access_token: BearerToken | str) -> Any:
        """Call the UserInfo endpoint.

        This sends a request to the UserInfo endpoint, with the specified access_token, and returns the parsed result.

        Args:
            access_token: the access token to use

        Returns:
            the [Response][requests.Response] returned by the userinfo endpoint.
        """
        userinfo_endpoint = self._require_endpoint("userinfo_endpoint")
        response = self.session.post(userinfo_endpoint, auth=BearerAuth(access_token))
        return self.parse_userinfo_response(response)

    def parse_userinfo_response(self, resp: requests.Response) -> Any:
        """Parse the response obtained by `userinfo()`.

        Invoked by [userinfo()][requests_oauth2client.client.OAuth2Client.userinfo] to parse the response from the UserInfo endpoint, this will extract and return its JSON
        content.

        Args:
            resp: a [Response][requests.Response] returned from the UserInfo endpoint.

        Returns:
            the parsed JSON content from this response.
        """
        return resp.json()

    @classmethod
    def get_token_type(
        cls,
        token_type: str | None = None,
        token: None | str | BearerToken | IdToken = None,
    ) -> str:
        """Get standardised token type identifiers.

        Return a standardised token type identifier, based on a short `token_type`
        hint and/or a token value.

        Args:
            token_type: a token_type hint, as `str`. May be "access_token", "refresh_token" or "id_token" (optional)
            token: a token value, as an instance of `BearerToken` or IdToken, or as a `str`.

        Returns:
            the token_type as defined in the Token Exchange RFC8693.
        """
        if not (token_type or token):
            raise ValueError(
                "Cannot determine type of an empty token without a token_type hint"
            )

        if token_type is None:
            if isinstance(token, str):
                raise ValueError(
                    "Cannot determine the type of provided token when it is a bare str. "
                    "Please specify a token_type."
                )
            elif isinstance(token, BearerToken):
                return "urn:ietf:params:oauth:token-type:access_token"
            elif isinstance(token, IdToken):
                return "urn:ietf:params:oauth:token-type:id_token"
            else:
                raise TypeError(
                    "Unexpected type of token, please provide a string or a BearerToken or an IdToken.",
                    type(token),
                )
        elif token_type == "access_token":
            if token is not None and not isinstance(token, (str, BearerToken)):
                raise TypeError(
                    "The supplied token is not a BearerToken or a string representation of it.",
                    type(token),
                )
            return "urn:ietf:params:oauth:token-type:access_token"
        elif token_type == "refresh_token":
            if token is not None and isinstance(token, BearerToken) and not token.refresh_token:
                raise ValueError("The supplied BearerToken doesn't have a refresh_token.")
            return "urn:ietf:params:oauth:token-type:refresh_token"
        elif token_type == "id_token":
            if token is not None and not isinstance(token, (str, IdToken)):
                raise TypeError(
                    "The supplied token is not an IdToken or a string representation of it.",
                    type(token),
                )
            return "urn:ietf:params:oauth:token-type:id_token"
        else:
            return {
                "saml1": "urn:ietf:params:oauth:token-type:saml1",
                "saml2": "urn:ietf:params:oauth:token-type:saml2",
                "jwt": "urn:ietf:params:oauth:token-type:jwt",
            }.get(token_type, token_type)

    def revoke_access_token(
        self,
        access_token: BearerToken | str,
        requests_kwargs: dict[str, Any] | None = None,
        **revoke_kwargs: Any,
    ) -> bool:
        """Send a request to the Revocation Endpoint to revoke an access token.

        Args:
            access_token: the access token to revoke
            requests_kwargs: additional parameters for the underlying requests.post() call
            **revoke_kwargs: additional parameters to pass to the revocation endpoint
        """
        return self.revoke_token(
            access_token,
            token_type_hint="access_token",
            requests_kwargs=requests_kwargs,
            **revoke_kwargs,
        )

    def revoke_refresh_token(
        self,
        refresh_token: str | BearerToken,
        requests_kwargs: dict[str, Any] | None = None,
        **revoke_kwargs: Any,
    ) -> bool:
        """Send a request to the Revocation Endpoint to revoke a refresh token.

        Args:
            refresh_token: the refresh token to revoke.
            requests_kwargs: additional parameters to pass to the revocation endpoint.
            **revoke_kwargs: additional parameters to pass to the revocation endpoint.

        Returns:
            `True` if the revocation request is successful, `False` if this client has no configured revocation endpoint.
        """
        if isinstance(refresh_token, BearerToken):
            if refresh_token.refresh_token is None:
                raise ValueError("The supplied BearerToken doesn't have a refresh token.")
            refresh_token = refresh_token.refresh_token

        return self.revoke_token(
            refresh_token,
            token_type_hint="refresh_token",
            requests_kwargs=requests_kwargs,
            **revoke_kwargs,
        )

    def revoke_token(
        self,
        token: str | BearerToken,
        token_type_hint: str | None = None,
        requests_kwargs: dict[str, Any] | None = None,
        **revoke_kwargs: Any,
    ) -> bool:
        """Send a Token Revocation request.

        By default, authentication will be the same than the one used for the Token Endpoint.

        Args:
            token: the token to revoke.
            token_type_hint: a token_type_hint to send to the revocation endpoint.
            requests_kwargs: additional parameters to the underling call to requests.post()
            **revoke_kwargs: additional parameters to send to the revocation endpoint.

        Returns:
            `True` if the revocation succeeds,
            `False` if no revocation endpoint is present or a non-standardised error is returned.
        """
        if not self.revocation_endpoint:
            return False

        requests_kwargs = requests_kwargs or {}

        if token_type_hint == "refresh_token" and isinstance(token, BearerToken):
            if token.refresh_token is None:
                raise ValueError("The supplied BearerToken doesn't have a refresh token.")
            token = token.refresh_token

        data = dict(revoke_kwargs, token=str(token))
        if token_type_hint:
            data["token_type_hint"] = token_type_hint

        response = self.session.post(
            self.revocation_endpoint,
            data=data,
            auth=self.auth,
            **requests_kwargs,
        )
        if response.ok:
            return True

        return self.on_revocation_error(response)

    def on_revocation_error(self, response: requests.Response) -> bool:
        """Error handler for `revoke_token()`.

        Invoked by [revoke_token()][requests_oauth2client.client.OAuth2Client.revoke_token] when the revocation endpoint returns an error.

        Args:
            response: the [Response][requests.Response] as returned by the Revocation Endpoint

        Returns:
            `False` to signal that an error occurred. May raise exceptions instead depending on the revocation response.
        """
        try:
            data = response.json()
            error = data["error"]
            error_description = data.get("error_description")
            error_uri = data.get("error_uri")
            exception_class = self.exception_classes.get(error, RevocationError)
            exception = exception_class(error, error_description, error_uri)
        except Exception:
            return False
        raise exception

    def introspect_token(
        self,
        token: str | BearerToken,
        token_type_hint: str | None = None,
        requests_kwargs: dict[str, Any] | None = None,
        **introspect_kwargs: Any,
    ) -> Any:
        """Send a request to the configured Introspection Endpoint.

        Args:
            token_type_hint: the token_type_hint to include in the request.
            requests_kwargs: additional parameters to the underling call to requests.post()
            **introspect_kwargs: additional parameters to send to the introspection endpoint.

        Returns:
            the response as returned by the Introspection Endpoint.
        """
        introspection_endpoint = self._require_endpoint("introspection_endpoint")

        requests_kwargs = requests_kwargs or {}

        if token_type_hint == "refresh_token" and isinstance(token, BearerToken):
            if token.refresh_token is None:
                raise ValueError("The supplied BearerToken doesn't have a refresh token.")
            token = token.refresh_token

        data = dict(introspect_kwargs, token=str(token))
        if token_type_hint:
            data["token_type_hint"] = token_type_hint

        response = self.session.post(
            introspection_endpoint,
            data=data,
            auth=self.auth,
            **requests_kwargs,
        )
        if response.ok:
            return self.parse_introspection_response(response)

        return self.on_introspection_error(response)

    def parse_introspection_response(self, response: requests.Response) -> Any:
        """Parse Token Introspection Responses received by `introspect_token()`.

        Invoked by [introspect_token()][requests_oauth2client.client.OAuth2Client.introspect_token] to parse the returned response.
        This decodes the JSON content if possible, otherwise it returns the response as a string.

        Args:
            response: the [Response][requests.Response] as returned by the Introspection Endpoint.

        Returns:
            the decoded JSON content, or a `str` with the content.
        """
        try:
            return response.json()
        except ValueError:
            return response.text

    def on_introspection_error(self, response: requests.Response) -> Any:
        """Error handler for `introspect_token()`.

        Invoked by [introspect_token()][requests_oauth2client.client.OAuth2Client.introspect_token] to parse the returned response in the case an error is returned.

        Args:
            response: the response as returned by the Introspection Endpoint.

        Returns:
            usually raises exeptions. A subclass can return a default response instead.
        """
        try:
            data = response.json()
            error = data["error"]
            error_description = data.get("error_description")
            error_uri = data.get("error_uri")
            exception_class = self.exception_classes.get(error, IntrospectionError)
            exception = exception_class(error, error_description, error_uri)
        except Exception as exc:
            raise UnknownIntrospectionError(response) from exc
        raise exception

    def backchannel_authentication_request(
        self,
        scope: None | str | Iterable[str] = "openid",
        client_notification_token: str | None = None,
        acr_values: None | str | Iterable[str] = None,
        login_hint_token: str | None = None,
        id_token_hint: str | None = None,
        login_hint: str | None = None,
        binding_message: str | None = None,
        user_code: str | None = None,
        requested_expiry: int | None = None,
        private_jwk: Jwk | dict[str, Any] | None = None,
        alg: str | None = None,
        requests_kwargs: dict[str, Any] | None = None,
        **ciba_kwargs: Any,
    ) -> BackChannelAuthenticationResponse:
        """Send a CIBA Authentication Request.

        Args:
             scope: the scope to include in the request.
             client_notification_token: the Client Notification Token to include in the request.
             acr_values: the acr values to include in the request.
             login_hint_token: the Login Hint Token to include in the request.
             id_token_hint: the ID Token Hint to include in the request.
             login_hint: the Login Hint to include in the request.
             binding_message: the Binding Message to include in the request.
             user_code: the User Code to include in the request
             requested_expiry: the Requested Expiry, in seconds, to include in the request.
             private_jwk: the JWK to use to sign the request (optional)
             alg: the alg to use to sign the request, if the provided JWK does not include an "alg" parameter.
             requests_kwargs: additional parameters for
             **ciba_kwargs: additional parameters to include in the request.

        Returns:
            a BackChannelAuthenticationResponse as returned by AS
        """
        backchannel_authentication_endpoint = self._require_endpoint(
            "backchannel_authentication_endpoint"
        )

        if not (login_hint or login_hint_token or id_token_hint):
            raise ValueError(
                "One of `login_hint`, `login_hint_token` or `ìd_token_hint` must be provided"
            )

        if (
            (login_hint_token and id_token_hint)
            or (login_hint and id_token_hint)
            or (login_hint_token and login_hint)
        ):
            raise ValueError(
                "Only one of `login_hint`, `login_hint_token` or `ìd_token_hint` must be provided"
            )

        requests_kwargs = requests_kwargs or {}

        if scope is not None and not isinstance(scope, str):
            try:
                scope = " ".join(scope)
            except Exception as exc:
                raise ValueError("Unsupported `scope` value") from exc

        if acr_values is not None and not isinstance(acr_values, str):
            try:
                acr_values = " ".join(acr_values)
            except Exception as exc:
                raise ValueError("Unsupported `acr_values`") from exc

        data = dict(
            ciba_kwargs,
            scope=scope,
            client_notification_token=client_notification_token,
            acr_values=acr_values,
            login_hint_token=login_hint_token,
            id_token_hint=id_token_hint,
            login_hint=login_hint,
            binding_message=binding_message,
            user_code=user_code,
            requested_expiry=requested_expiry,
        )

        if private_jwk is not None:
            data = {"request": str(Jwt.sign(data, key=private_jwk, alg=alg))}

        response = self.session.post(
            backchannel_authentication_endpoint,
            data=data,
            auth=self.auth,
            **requests_kwargs,
        )

        if response.ok:
            return self.parse_backchannel_authentication_response(response)

        return self.on_backchannel_authentication_error(response)

    def parse_backchannel_authentication_response(
        self, response: requests.Response
    ) -> BackChannelAuthenticationResponse:
        """Parse a response received by `backchannel_authentication_request()`.

        Invoked by [backchannel_authentication_request()][requests_oauth2client.client.OAuth2Client.backchannel_authentication_request] to parse the response
        returned by the BackChannel Authentication Endpoint.

        Args:
            response: the response returned by the BackChannel Authentication Endpoint.

        Returns:
            a `BackChannelAuthenticationResponse`
        """
        try:
            return BackChannelAuthenticationResponse(**response.json())
        except TypeError as exc:
            raise InvalidBackChannelAuthenticationResponse(response) from exc

    def on_backchannel_authentication_error(
        self, response: requests.Response
    ) -> BackChannelAuthenticationResponse:
        """Error handler for `backchannel_authentication_request()`.

        Invoked by [backchannel_authentication_request()][requests_oauth2client.client.OAuth2Client.backchannel_authentication_request] to parse the response
        returned by the BackChannel Authentication Endpoint, when it is an error.

        Args:
            response: the response returned by the BackChannel Authentication Endpoint.

        Returns:
            usually raises an exception. But a subclass can return a default response instead.
        """
        try:
            data = response.json()
            error = data["error"]
            error_description = data.get("error_description")
            error_uri = data.get("error_uri")
            exception_class = self.exception_classes.get(error, BackChannelAuthenticationError)
            exception = exception_class(error, error_description, error_uri)
        except Exception as exc:
            raise InvalidBackChannelAuthenticationResponse(response) from exc
        raise exception

    def authorize_device(self, **data: Any) -> DeviceAuthorizationResponse:
        """Send a Device Authorization Request.

        Args:
            **data: additional data to send to the Device Authorization Endpoint

        Returns:
            a Device Authorization Response
        """
        device_authorization_endpoint = self._require_endpoint("device_authorization_endpoint")

        response = self.session.post(device_authorization_endpoint, data=data, auth=self.auth)

        if response.ok:
            return self.parse_device_authorization_response(response)

        return self.on_device_authorization_error(response)

    def parse_device_authorization_response(
        self, response: requests.Response
    ) -> DeviceAuthorizationResponse:
        """Parse a Device Authorization Response received by `authorize_device()`.

        Invoked by [authorize_device()][requests_oauth2client.client.OAuth2Client.authorize_device] to parse the response returned by the Device Authorization Endpoint.

        Args:
            response: the response returned by the Device Authorization Endpoint.

        Returns:
            a `DeviceAuthorizationResponse` as returned by AS
        """
        device_authorization_response = DeviceAuthorizationResponse(**response.json())
        return device_authorization_response

    def on_device_authorization_error(
        self, response: requests.Response
    ) -> DeviceAuthorizationResponse:
        """Error handler for `authorize_device()`.

        Invoked by [authorize_device()][requests_oauth2client.client.OAuth2Client.authorize_device] to parse the response returned by the Device Authorization Endpoint, when that response is an error.

        Args:
            response: the response returned by the Device Authorization Endpoint.

        Returns:
            usually raises an Exception. But a subclass may return a default response instead.
        """
        try:
            data = response.json()
            error = data["error"]
            error_description = data.get("error_description")
            error_uri = data.get("error_uri")
            exception_class = self.exception_classes.get(error, DeviceAuthorizationError)
            exception = exception_class(response, error, error_description, error_uri)
        except Exception as exc:
            raise InvalidDeviceAuthorizationResponse(response) from exc
        raise exception

    def update_authorization_server_public_keys(self) -> JwkSet:
        """Update the cached AS public keys by retrieving them from its `jwks_uri`.

        Public keys are returned by this method, as a [JwkSet][jwskate.JwkSet].
        They are also available in attribute `authorization_server_jwks`.

        Returns:
            the retrieved public keys

        Raises:
            ValueError: if no jwks_uri is configured
        """
        jwks_uri = self._require_endpoint("jwks_uri")

        jwks = self.session.get(jwks_uri, auth=None).json()
        self.authorization_server_jwks = JwkSet(jwks)
        return self.authorization_server_jwks

    @classmethod
    def from_discovery_endpoint(
        cls,
        url: str | None = None,
        issuer: str | None = None,
        auth: requests.auth.AuthBase | tuple[str, str] | str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        private_key: Jwk | dict[str, Any] | None = None,
        session: requests.Session | None = None,
        **kwargs: Any,
    ) -> OAuth2Client:
        """Initialise an OAuth2Client based on Authorization Server Metadata.

        This will retrieve the standardised metadata document available at `url`, and will extract all Endpoint Uris
        from that document, will fetch the current public keys from its `jwks_uri`, then will initialize an OAuth2Client
        based on those endpoints.

        Args:
             url: the url where the server metadata will be retrieved
             auth: the authentication handler to use for client authentication
             client_id: client ID
             client_secret: client secret to use to authenticate the client
             private_key: private key to sign client assertions
             session: a requests Session to use to retrieve the document and initialise the client with
             issuer: if an issuer is given, check that it matches the one from the retrieved document

        Returns:
            an OAuth2Client with endpoint initialized based on the obtained metadata

        Raises:
            ValueError: if neither `url` or `issuer` are suitable urls.
            requests.HTTPError: if an error happens while fetching the documents
        """
        if url is None and issuer is not None:
            url = oidc_discovery_document_url(issuer)
        if url is None:
            raise ValueError("Please specify at least one of `issuer` or `url`")

        validate_endpoint_uri(url, path=False)

        session = session or requests.Session()
        discovery = session.get(url).json()

        jwks_uri = discovery.get("jwks_uri")
        if jwks_uri:
            jwks = JwkSet(session.get(jwks_uri).json())

        return cls.from_discovery_document(
            discovery,
            issuer=issuer,
            auth=auth,
            session=session,
            client_id=client_id,
            client_secret=client_secret,
            private_key=private_key,
            authorization_server_jwks=jwks,
            **kwargs,
        )

    @classmethod
    def from_discovery_document(
        cls,
        discovery: dict[str, Any],
        issuer: str | None = None,
        auth: requests.auth.AuthBase | tuple[str, str] | str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        private_key: Jwk | dict[str, Any] | None = None,
        authorization_server_jwks: JwkSet | dict[str, Any] | None = None,
        session: requests.Session | None = None,
        https: bool = True,
        **kwargs: Any,
    ) -> OAuth2Client:
        """Initialise an OAuth2Client, based on the server metadata from `discovery`.

        Args:
             discovery: a dict of server metadata, in the same format as retrieved from a discovery endpoint.
             issuer: if an issuer is given, check that it matches the one mentioned in the document
             auth: the authentication handler to use for client authentication
             client_id: client ID
             client_secret: client secret to use to authenticate the client
             private_key: private key to sign client assertions
             authorization_server_jwks: the current authorization server JWKS keys
             session: a requests Session to use to retrieve the document and initialise the client with
             https: if True, validates that urls in the discovery document use the https scheme

        Returns:
            an OAuth2Client
        """
        if issuer and discovery.get("issuer") != issuer:
            raise ValueError(
                "Mismatching issuer value in discovery document: ",
                issuer,
                discovery.get("issuer"),
            )
        elif issuer is None:
            issuer = discovery.get("issuer")

        token_endpoint = discovery.get("token_endpoint")
        if token_endpoint is None:
            raise ValueError("token_endpoint not found in that discovery document")
        validate_endpoint_uri(token_endpoint, https=https)
        authorization_endpoint = discovery.get("authorization_endpoint")
        if authorization_endpoint is not None:
            validate_endpoint_uri(authorization_endpoint, https=https)
        validate_endpoint_uri(token_endpoint, https=https)
        revocation_endpoint = discovery.get("revocation_endpoint")
        if revocation_endpoint is not None:
            validate_endpoint_uri(revocation_endpoint, https=https)
        introspection_endpoint = discovery.get("introspection_endpoint")
        if introspection_endpoint is not None:
            validate_endpoint_uri(introspection_endpoint, https=https)
        userinfo_endpoint = discovery.get("userinfo_endpoint")
        if userinfo_endpoint is not None:
            validate_endpoint_uri(userinfo_endpoint, https=https)
        jwks_uri = discovery.get("jwks_uri")
        if jwks_uri is not None:
            validate_endpoint_uri(userinfo_endpoint, https=https)
        authorization_response_iss_parameter_supported = discovery.get(
            "authorization_response_iss_parameter_supported", False
        )

        return cls(
            token_endpoint=token_endpoint,
            authorization_endpoint=authorization_endpoint,
            revocation_endpoint=revocation_endpoint,
            introspection_endpoint=introspection_endpoint,
            userinfo_endpoint=userinfo_endpoint,
            jwks_uri=jwks_uri,
            authorization_server_jwks=authorization_server_jwks,
            auth=auth,
            client_id=client_id,
            client_secret=client_secret,
            private_key=private_key,
            session=session,
            issuer=issuer,
            authorization_response_iss_parameter_supported=authorization_response_iss_parameter_supported,
            **kwargs,
        )

    def __enter__(self) -> OAuth2Client:
        """Allow using OAuth2Client as a context-manager.

        The Authorization Server public keys are retrieved on __enter__.
        """
        self.update_authorization_server_public_keys()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:  # noqa: D105
        return True

    def _require_endpoint(self, endpoint: str) -> str:
        """Check that a required endpoint url is set."""
        url = getattr(self, endpoint, None)
        if not url:
            raise AttributeError(
                f"No '{endpoint}' defined for this client. "
                f"Please provide the URL for that endpoint when initializing your {self.__class__.__name__} instance."
            )

        return str(url)
