"""This module contains the `OAuth2Client` class."""

from __future__ import annotations

import warnings
from enum import Enum
from typing import TYPE_CHECKING, Any, Callable, ClassVar, Iterable, TypeVar

import requests
from attrs import Attribute, field, frozen
from jwskate import Jwk, JwkSet, Jwt, SignatureAlgs
from typing_extensions import Self

from .authorization_request import (
    AuthorizationRequest,
    AuthorizationResponse,
    CodeChallengeMethods,
    MissingIssuerParam,
    RequestUriParameterAuthorizationRequest,
    ResponseTypes,
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
    EndpointError,
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
from .tokens import BearerToken, IdToken, TokenResponse, TokenType
from .utils import InvalidUri, validate_endpoint_uri, validate_issuer_uri

if TYPE_CHECKING:
    from types import TracebackType

T = TypeVar("T")


class InvalidParam(ValueError):
    """Base class for invalid parameters errors."""


class MissingIdTokenEncryptedResponseAlgParam(InvalidParam):
    """Raised when an ID Token encryption is required but not provided."""

    def __init__(self) -> None:
        super().__init__("""\
An ID Token decryption key has been provided but no decryption algorithm is defined.
You can either pass an `id_token_encrypted_response_alg` parameter with the alg identifier,
or include an `alg` attribute in the decryption key, if it is in Jwk format.
""")


class InvalidEndpointUri(InvalidParam):
    """Raised when an invalid endpoint uri is provided."""

    def __init__(self, endpoint: str, uri: str, exc: InvalidUri) -> None:
        super().__init__(f"Invalid endpoint uri '{uri}' for '{endpoint}': {exc}")
        self.endpoint = endpoint
        self.uri = uri


class InvalidIssuer(InvalidEndpointUri):
    """Raised when an invalid issuer parameter is provided."""


class InvalidScopeParam(InvalidParam):
    """Raised when an invalid scope parameter is provided."""

    def __init__(self, scope: object) -> None:
        super().__init__("""\
Unsupported scope value. It must be one of:
- a space separated `str` of scopes names
- an iterable of scope names as `str`
""")
        self.scope = scope


class MissingRefreshToken(ValueError):
    """Raised when a refresh token is required but not present."""

    def __init__(self, token: TokenResponse) -> None:
        super().__init__("A refresh_token is required but is not present in this Access Token.")
        self.token = token


class MissingDeviceCode(ValueError):
    """Raised when a device_code is required but not provided."""

    def __init__(self, dar: DeviceAuthorizationResponse) -> None:
        super().__init__("A device_code is missing in this DeviceAuthorizationResponse")
        self.device_authorization_response = dar


class MissingAuthRequestId(ValueError):
    """Raised when an 'auth_req_id' is missing in a BackChannelAuthenticationResponse."""

    def __init__(self, bcar: BackChannelAuthenticationResponse) -> None:
        super().__init__("An 'auth_req_id' is required but is missing from this BackChannelAuthenticationResponse.")
        self.backchannel_authentication_response = bcar


class UnknownTokenType(InvalidParam, TypeError):
    """Raised when the type of a token cannot be determined automatically."""

    def __init__(self, message: str, token: object, token_type: str | None) -> None:
        super().__init__(f"Unable to determine the type of token provided: {message}")
        self.token = token
        self.token_type = token_type


class UnknownSubjectTokenType(UnknownTokenType):
    """Raised when the type of subject_token cannot be determined automatically."""

    def __init__(self, subject_token: object, subject_token_type: str | None) -> None:
        super().__init__("subject_token", subject_token, subject_token_type)


class UnknownActorTokenType(UnknownTokenType):
    """Raised when the type of actor_token cannot be determined automatically."""

    def __init__(self, actor_token: object, actor_token_type: str | None) -> None:
        super().__init__("actor_token", token=actor_token, token_type=actor_token_type)


class InvalidBackchannelAuthenticationRequestHintParam(InvalidParam):
    """Raised when an invalid hint is provided in a backchannel authentication request."""


class InvalidAcrValuesParam(InvalidParam):
    """Raised when an invalid 'acr_values' parameter is provided."""

    def __init__(self, acr_values: object) -> None:
        super().__init__(f"Invalid 'acr_values' parameter: {acr_values}")
        self.acr_values = acr_values


class InvalidDiscoveryDocument(ValueError):
    """Raised when handling an invalid Discovery Document."""

    def __init__(self, message: str, discovery_document: dict[str, Any]) -> None:
        super().__init__(f"Invalid discovery document: {message}")
        self.discovery_document = discovery_document


class Endpoints(str, Enum):
    """All standardised OAuth 2.0 and extensions endpoints.

    If an endpoint is not mentioned here, then its usage is not supported by OAuth2Client.

    """

    TOKEN = "token_endpoint"
    AUTHORIZATION = "authorization_endpoint"
    BACKCHANNEL_AUTHENTICATION = "backchannel_authentication_endpoint"
    DEVICE_AUTHORIZATION = "device_authorization_endpoint"
    INSTROSPECTION = "introspection_endpoint"
    REVOCATION = "revocation_endpoint"
    PUSHED_AUTHORIZATION_REQUEST = "pushed_authorization_request_endpoint"
    JWKS = "jwks_uri"
    USER_INFO = "userinfo_endpoint"


class MissingEndpointUri(AttributeError):
    """Raised when a required endpoint uri is not known."""

    def __init__(self, endpoint: str) -> None:
        super().__init__(f"No '{endpoint}' defined for this client.")


class GrantTypes(str, Enum):
    """An enum of standardized `grant_type` values."""

    CLIENT_CREDENTIALS = "client_credentials"
    AUTHORIZATION_CODE = "authorization_code"
    REFRESH_TOKEN = "refresh_token"
    RESOURCE_OWNER_PASSWORD = "password"
    TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
    JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
    CLIENT_INITIATED_BACKCHANNEL_AUTHENTICATION = "urn:openid:params:grant-type:ciba"
    DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code"


@frozen(init=False)
class OAuth2Client:
    """An OAuth 2.x Client, that can send requests to an OAuth 2.x Authorization Server.

    `OAuth2Client` is able to obtain tokens from the Token Endpoint using any of the standardised
    Grant Types, and to communicate with the various backend endpoints like the Revocation,
    Introspection, and UserInfo Endpoint.

    To init an OAuth2Client, you only need the url to the Token Endpoint and the Credentials
    (a client_id and one of a secret or private_key) that will be used to authenticate to that endpoint.
    Other endpoint urls, such as the Authorization Endpoint, Revocation Endpoint, etc. can be passed as
    parameter as well if you intend to use them.


    This class is not intended to help with the end-user authentication or any request that goes in
    a browser. For authentication requests, see
    [AuthorizationRequest][requests_oauth2client.authorization_request.AuthorizationRequest]. You
    may use the method `authorization_request()` to generate `AuthorizationRequest`s with the
    preconfigured `authorization_endpoint`, `client_id` and `redirect_uri' from this client.

    Args:
        token_endpoint: the Token Endpoint URI where this client will get access tokens
        auth: the authentication handler to use for client authentication on the token endpoint.
            Can be:

            - a [requests.auth.AuthBase][] instance (which will be used as-is)
            - a tuple of `(client_id, client_secret)` which will initialize an instance
            of [ClientSecretPost][requests_oauth2client.client_authentication.ClientSecretPost]
            - a `(client_id, jwk)` to initialize
            a [PrivateKeyJwt][requests_oauth2client.client_authentication.PrivateKeyJwt],
            - or a `client_id` which will
            use [PublicApp][requests_oauth2client.client_authentication.PublicApp] authentication.

        client_id: client ID (use either this or `auth`)
        client_secret: client secret (use either this or `auth`)
        private_key: private_key to use for client authentication (use either this or `auth`)
        revocation_endpoint: the Revocation Endpoint URI to use for revoking tokens
        introspection_endpoint: the Introspection Endpoint URI to use to get info about tokens
        userinfo_endpoint: the Userinfo Endpoint URI to use to get information about the user
        authorization_endpoint: the Authorization Endpoint URI, used for initializing Authorization Requests
        redirect_uri: the redirect_uri for this client
        backchannel_authentication_endpoint: the BackChannel Authentication URI
        device_authorization_endpoint: the Device Authorization Endpoint URI to use to authorize devices
        jwks_uri: the JWKS URI to use to obtain the AS public keys
        code_challenge_method: challenge method to use for PKCE (should always be 'S256')
        session: a requests Session to use when sending HTTP requests.
            Useful if some extra parameters such as proxy or client certificate must be used
            to connect to the AS.
        testing: if `True`, don't verify the validity of the endpoint urls that are passed as parameter.
        **extra_metadata: additional metadata for this client, unused by this class, but may be
            used by subclasses. Those will be accessible with the `extra_metadata` attribute.

    Example:
        ```python
        client = OAuth2Client(
            token_endpoint="https://my.as.local/token",
            revocation_endpoint="https://my.as.local/revoke",
            client_id="client_id",
            client_secret="client_secret",
        )

        # once initialized, a client can send requests to its configured endpoints
        cc_token = client.client_credentials(scope="my_scope")
        ac_token = client.authorization_code(code="my_code")
        client.revoke_access_token(cc_token)
        ```

    Raises:
        MissingIDTokenEncryptedResponseAlgParam: if an `id_token_decryption_key` is provided
            but no decryption alg is provided, either:

            - using `id_token_encrypted_response_alg`,
            - or in the `alg` parameter of the `Jwk` key
        MissingIssuerParam: if `authorization_response_iss_parameter_supported` is set to `True`
            but the `issuer` is not provided.
        InvalidEndpointUri: if a provided endpoint uri is not considered valid. For the rare cases
            where those checks must be disabled, you can use `testing=True`.
        InvalidIssuer: if the `issuer` value is not considered valid.

    """

    auth: requests.auth.AuthBase = field(converter=client_auth_factory)
    token_endpoint: str = field()
    revocation_endpoint: str | None = field()
    introspection_endpoint: str | None = field()
    userinfo_endpoint: str | None = field()
    authorization_endpoint: str | None = field()
    redirect_uri: str | None = field()
    backchannel_authentication_endpoint: str | None = field()
    device_authorization_endpoint: str | None = field()
    pushed_authorization_request_endpoint: str | None = field()
    jwks_uri: str | None = field()
    authorization_server_jwks: JwkSet
    issuer: str | None = field()
    id_token_signed_response_alg: str | None = SignatureAlgs.RS256
    id_token_encrypted_response_alg: str | None = None
    id_token_decryption_key: Jwk | None = None
    code_challenge_method: str | None = CodeChallengeMethods.S256
    authorization_response_iss_parameter_supported: bool = False
    session: requests.Session = field(factory=requests.Session)
    extra_metadata: dict[str, Any] = field(factory=dict)
    testing: bool = False

    token_class: type[BearerToken] = BearerToken

    exception_classes: ClassVar[dict[str, type[EndpointError]]] = {
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

    def __init__(  # noqa: PLR0913
        self,
        token_endpoint: str,
        auth: (
            requests.auth.AuthBase | tuple[str, str] | tuple[str, Jwk] | tuple[str, dict[str, Any]] | str | None
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
        id_token_signed_response_alg: str | None = SignatureAlgs.RS256,
        id_token_encrypted_response_alg: str | None = None,
        id_token_decryption_key: Jwk | dict[str, Any] | None = None,
        code_challenge_method: str = CodeChallengeMethods.S256,
        authorization_response_iss_parameter_supported: bool = False,
        token_class: type[BearerToken] = BearerToken,
        session: requests.Session | None = None,
        testing: bool = False,
        **extra_metadata: Any,
    ) -> None:
        if authorization_response_iss_parameter_supported and not issuer:
            raise MissingIssuerParam

        auth = client_auth_factory(
            auth,
            client_id=client_id,
            client_secret=client_secret,
            private_key=private_key,
            default_auth_handler=ClientSecretPost,
        )

        if authorization_server_jwks is None:
            authorization_server_jwks = JwkSet()
        elif not isinstance(authorization_server_jwks, JwkSet):
            authorization_server_jwks = JwkSet(authorization_server_jwks)

        if id_token_decryption_key is not None and not isinstance(id_token_decryption_key, Jwk):
            id_token_decryption_key = Jwk(id_token_decryption_key)

        if id_token_decryption_key is not None and id_token_encrypted_response_alg is None:
            if id_token_decryption_key.alg:
                id_token_encrypted_response_alg = id_token_decryption_key.alg
            else:
                raise MissingIdTokenEncryptedResponseAlgParam

        if session is None:
            session = requests.Session()

        self.__attrs_init__(
            testing=testing,
            token_endpoint=token_endpoint,
            revocation_endpoint=revocation_endpoint,
            introspection_endpoint=introspection_endpoint,
            userinfo_endpoint=userinfo_endpoint,
            authorization_endpoint=authorization_endpoint,
            redirect_uri=redirect_uri,
            backchannel_authentication_endpoint=backchannel_authentication_endpoint,
            device_authorization_endpoint=device_authorization_endpoint,
            pushed_authorization_request_endpoint=pushed_authorization_request_endpoint,
            jwks_uri=jwks_uri,
            authorization_server_jwks=authorization_server_jwks,
            issuer=issuer,
            session=session,
            auth=auth,
            id_token_signed_response_alg=id_token_signed_response_alg,
            id_token_encrypted_response_alg=id_token_encrypted_response_alg,
            id_token_decryption_key=id_token_decryption_key,
            code_challenge_method=code_challenge_method,
            authorization_response_iss_parameter_supported=authorization_response_iss_parameter_supported,
            extra_metadata=extra_metadata,
            token_class=token_class,
        )

    @token_endpoint.validator
    @revocation_endpoint.validator
    @introspection_endpoint.validator
    @userinfo_endpoint.validator
    @authorization_endpoint.validator
    @backchannel_authentication_endpoint.validator
    @device_authorization_endpoint.validator
    @pushed_authorization_request_endpoint.validator
    @jwks_uri.validator
    def validate_endpoint_uri(self, attribute: Attribute[str | None], uri: str | None) -> str | None:
        """Validate that an endpoint URI is suitable for use.

        If you need to disable some checks (for AS testing purposes only!), provide a different
        method here.

        """
        if self.testing or uri is None:
            return uri
        try:
            return validate_endpoint_uri(uri)
        except InvalidUri as exc:
            raise InvalidEndpointUri(endpoint=attribute.name, uri=uri, exc=exc) from exc

    @issuer.validator
    def validate_issuer_uri(self, attribute: Attribute[str | None], uri: str | None) -> str | None:
        """Validate that an Issuer identifier is suitable for use.

        This is the same check as an endpoint URI, but the path may be (and usually is) empty.

        """
        if self.testing or uri is None:
            return uri
        try:
            return validate_issuer_uri(uri)
        except InvalidUri as exc:
            raise InvalidIssuer(attribute.name, uri, exc) from exc

    @property
    def client_id(self) -> str:
        """Client ID."""
        if hasattr(self.auth, "client_id"):
            return self.auth.client_id  # type: ignore[no-any-return]
        msg = "This client uses a custom authentication method without client_id."
        raise AttributeError(msg)  # pragma: no cover

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

    def _request(
        self,
        endpoint: str,
        on_success: Callable[[requests.Response], T],
        on_failure: Callable[[requests.Response], T],
        accept: str = "application/json",
        method: str = "POST",
        **requests_kwargs: Any,
    ) -> T:
        """Send a request to one of the endpoints.

        This is a helper method that takes care of the following tasks:

        - make sure the endpoint as been configured
        - set `Accept: application/json` header
        - send the HTTP POST request, then
            - apply `on_success` to a successful response
            - or apply `on_failure` otherwise
        - return the result

        Args:
            endpoint: name of the endpoint to use
            on_success: a callable to apply to successful responses
            on_failure: a callable to apply to error responses
            accept: the Accept header to include in the request
            method: the HTTP method to use
            **requests_kwargs: keyword arguments for the request

        """
        endpoint_uri = self._require_endpoint(endpoint)
        requests_kwargs.setdefault("headers", {})
        requests_kwargs["headers"]["Accept"] = accept

        response = self.session.request(
            method,
            endpoint_uri,
            **requests_kwargs,
        )
        if response.ok:
            return on_success(response)

        return on_failure(response)

    def token_request(
        self,
        data: dict[str, Any],
        timeout: int = 10,
        **requests_kwargs: Any,
    ) -> BearerToken:
        """Send a request to the token endpoint.

        Authentication will be added automatically based on the defined `auth` for this client.

        Args:
          data: parameters to send to the token endpoint. Items with a `None`
               or empty value will not be sent in the request.
          timeout: a timeout value for the call
          **requests_kwargs: additional parameters for requests.post()

        Returns:
            the token endpoint response, as
            [`BearerToken`][requests_oauth2client.tokens.BearerToken] instance.

        """
        return self._request(
            Endpoints.TOKEN,
            auth=self.auth,
            data=data,
            timeout=timeout,
            on_success=self.parse_token_response,
            on_failure=self.on_token_error,
            **requests_kwargs,
        )

    def parse_token_response(self, response: requests.Response) -> BearerToken:
        """Parse a Response returned by the Token Endpoint.

        Invoked by [token_request][requests_oauth2client.client.OAuth2Client.token_request] to parse
        responses returned by the Token Endpoint. Those responses contain an `access_token` and
        additional attributes.

        Args:
            response: the [Response][requests.Response] returned by the Token Endpoint.

        Returns:
            a [`BearerToken`][requests_oauth2client.tokens.BearerToken] based on the response
            contents.

        """
        try:
            token_response = self.token_class(**response.json())
        except Exception:  # noqa: BLE001
            return self.on_token_error(response)
        else:
            return token_response

    def on_token_error(self, response: requests.Response) -> BearerToken:
        """Error handler for `token_request()`.

        Invoked by [token_request][requests_oauth2client.client.OAuth2Client.token_request] when the
        Token Endpoint returns an error.

        Args:
            response: the [Response][requests.Response] returned by the Token Endpoint.

        Returns:
            nothing, and raises an exception instead. But a subclass may return a
            [`BearerToken`][requests_oauth2client.tokens.BearerToken] to implement a default
            behaviour if needed.

        Raises:
            InvalidTokenResponse: if the error response does not contain an OAuth 2.0 standard
                error response.

        """
        try:
            data = response.json()
            error = data["error"]
            error_description = data.get("error_description")
            error_uri = data.get("error_uri")
            exception_class = self.exception_classes.get(error, UnknownTokenEndpointError)
            exception = exception_class(
                response=response,
                client=self,
                error=error,
                description=error_description,
                uri=error_uri,
            )
        except Exception as exc:
            raise InvalidTokenResponse(response=response, client=self) from exc
        raise exception

    def client_credentials(
        self,
        scope: str | Iterable[str] | None = None,
        *,
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
            a BearerToken

        Raises:
            InvalidScopeParam: if the `scope` parameter is not suitable

        """
        requests_kwargs = requests_kwargs or {}

        if scope and not isinstance(scope, str):
            try:
                scope = " ".join(scope)
            except Exception as exc:
                raise InvalidScopeParam(scope) from exc

        data = dict(grant_type=GrantTypes.CLIENT_CREDENTIALS, scope=scope, **token_kwargs)
        return self.token_request(data, **requests_kwargs)

    def authorization_code(
        self,
        code: str | AuthorizationResponse,
        *,
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

        data = dict(grant_type=GrantTypes.AUTHORIZATION_CODE, code=code, **token_kwargs)
        token = self.token_request(data, **requests_kwargs)
        if validate and token.id_token and isinstance(azr, AuthorizationResponse):
            return token.validate_id_token(self, azr)
        return token

    def refresh_token(
        self,
        refresh_token: str | BearerToken,
        requests_kwargs: dict[str, Any] | None = None,
        **token_kwargs: Any,
    ) -> BearerToken:
        """Send a request to the token endpoint with the `refresh_token` grant.

        Args:
            refresh_token: a refresh_token, as a string, or as a `BearerToken`.
                That `BearerToken` must have a `refresh_token`.
            requests_kwargs: additional parameters for the call to `requests`
            **token_kwargs: additional parameters for the token endpoint,
                alongside `grant_type`, `refresh_token`, etc.

        Returns:
            a `BearerToken`

        Raises:
            MissingRefreshToken: if `refresh_token` is a BearerToken instance but does not
                contain a `refresh_token`

        """
        if isinstance(refresh_token, BearerToken):
            if refresh_token.refresh_token is None or not isinstance(refresh_token.refresh_token, str):
                raise MissingRefreshToken(refresh_token)
            refresh_token = refresh_token.refresh_token

        requests_kwargs = requests_kwargs or {}
        data = dict(grant_type=GrantTypes.REFRESH_TOKEN, refresh_token=refresh_token, **token_kwargs)
        return self.token_request(data, **requests_kwargs)

    def device_code(
        self,
        device_code: str | DeviceAuthorizationResponse,
        requests_kwargs: dict[str, Any] | None = None,
        **token_kwargs: Any,
    ) -> BearerToken:
        """Send a request to the token endpoint using the Device Code grant.

        The grant_type is `urn:ietf:params:oauth:grant-type:device_code`. This needs a Device Code,
        or a `DeviceAuthorizationResponse` as parameter.

        Args:
            device_code: a device code, or a `DeviceAuthorizationResponse`
            requests_kwargs: additional parameters for the call to requests
            **token_kwargs: additional parameters for the token endpoint, alongside `grant_type`, `device_code`, etc.

        Returns:
            a `BearerToken`

        Raises:
            MissingDeviceCode: if `device_code` is a DeviceAuthorizationResponse but does not
                contain a `device_code`.

        """
        if isinstance(device_code, DeviceAuthorizationResponse):
            if device_code.device_code is None or not isinstance(device_code.device_code, str):
                raise MissingDeviceCode(device_code)
            device_code = device_code.device_code

        requests_kwargs = requests_kwargs or {}
        data = dict(
            grant_type=GrantTypes.DEVICE_CODE,
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

        Raises:
            MissingAuthRequestId: if `auth_req_id` is a BackChannelAuthenticationResponse but does not contain
                an `auth_req_id`.

        """
        if isinstance(auth_req_id, BackChannelAuthenticationResponse):
            if auth_req_id.auth_req_id is None or not isinstance(auth_req_id.auth_req_id, str):
                raise MissingAuthRequestId(auth_req_id)
            auth_req_id = auth_req_id.auth_req_id

        requests_kwargs = requests_kwargs or {}
        data = dict(
            grant_type=GrantTypes.CLIENT_INITIATED_BACKCHANNEL_AUTHENTICATION,
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

        A Token Exchange request is actually a request to the Token Endpoint with a grant_type
        `urn:ietf:params:oauth:grant-type:token-exchange`.

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

        Raises:
            UnknownSubjectTokenType: if the type of `subject_token` cannot be determined automatically.
            UnknownActorTokenType: if the type of `actor_token` cannot be determined automaticatlly.

        """
        requests_kwargs = requests_kwargs or {}

        try:
            subject_token_type = self.get_token_type(subject_token_type, subject_token)
        except ValueError as exc:
            raise UnknownSubjectTokenType(subject_token, subject_token_type) from exc
        if actor_token:  # pragma: no branch
            try:
                actor_token_type = self.get_token_type(actor_token_type, actor_token)
            except ValueError as exc:
                raise UnknownActorTokenType(actor_token, actor_token_type) from exc

        data = dict(
            grant_type=GrantTypes.TOKEN_EXCHANGE,
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

        This is defined in (RFC7523 $2.1)[https://www.rfc-editor.org/rfc/rfc7523.html#section-2.1).

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
            grant_type=GrantTypes.JWT_BEARER,
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
            grant_type=GrantTypes.RESOURCE_OWNER_PASSWORD,
            username=username,
            password=password,
            **token_kwargs,
        )

        return self.token_request(data, **requests_kwargs)

    def authorization_request(
        self,
        *,
        scope: None | str | Iterable[str] = "openid",
        response_type: str = ResponseTypes.CODE,
        redirect_uri: str | None = None,
        state: str | ellipsis | None = ...,  # noqa: F821
        nonce: str | ellipsis | None = ...,  # noqa: F821
        code_verifier: str | None = None,
        **kwargs: Any,
    ) -> AuthorizationRequest:
        """Generate an Authorization Request for this client.

        Args:
            scope: the `scope` to use
            response_type: the `response_type` to use
            redirect_uri: the `redirect_uri` to include in the request. By default,
                the `redirect_uri` defined at init time is used.
            state: the `state` parameter to use. Leave default to generate a random value.
            nonce: a `nonce`. Leave default to generate a random value.
            code_verifier: the PKCE `code_verifier` to use. Leave default to generate a random value.
            **kwargs: additional parameters to include in the auth request

        Returns:
            an AuthorizationRequest with the supplied parameters

        """
        authorization_endpoint = self._require_endpoint("authorization_endpoint")

        redirect_uri = redirect_uri or self.redirect_uri

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
        self,
        authorization_request: AuthorizationRequest,
        requests_kwargs: dict[str, Any] | None = None,
    ) -> RequestUriParameterAuthorizationRequest:
        """Send a Pushed Authorization Request.

        This sends a request to the Pushed Authorization Request Endpoint, and returns a
        `RequestUriParameterAuthorizationRequest` initialized with the AS response.

        Args:
            authorization_request: the authorization request to send
            requests_kwargs: additional parameters for `requests.request()`

        Returns:
            the `RequestUriParameterAuthorizationRequest` initialized based on the AS response

        """
        requests_kwargs = requests_kwargs or {}
        return self._request(
            Endpoints.PUSHED_AUTHORIZATION_REQUEST,
            data=authorization_request.args,
            auth=self.auth,
            on_success=self.parse_pushed_authorization_response,
            on_failure=self.on_pushed_authorization_request_error,
            **requests_kwargs,
        )

    def parse_pushed_authorization_response(
        self,
        response: requests.Response,
    ) -> RequestUriParameterAuthorizationRequest:
        """Parse the response obtained by `pushed_authorization_request()`.

        Args:
            response: the `requests.Response` returned by the PAR endpoint

        Returns:
            a RequestUriParameterAuthorizationRequest instance

        """
        response_json = response.json()
        request_uri = response_json.get("request_uri")
        expires_in = response_json.get("expires_in")

        return RequestUriParameterAuthorizationRequest(
            authorization_endpoint=self.authorization_endpoint,
            client_id=self.client_id,
            request_uri=request_uri,
            expires_in=expires_in,
        )

    def on_pushed_authorization_request_error(
        self,
        response: requests.Response,
    ) -> RequestUriParameterAuthorizationRequest:
        """Error Handler for Pushed Authorization Endpoint errors.

        Args:
            response: the HTTP response as returned by the AS PAR endpoint.

        Returns:
            a RequestUriParameterAuthorizationRequest, if the error is recoverable

        Raises:
            EndpointError: a subclass of this error depending on the error returned by the AS
            InvalidPushedAuthorizationResponse: if the returned response is not following the
                specifications
            UnknownTokenEndpointError: for unknown/unhandled errors

        """
        try:
            data = response.json()
            error = data["error"]
            error_description = data.get("error_description")
            error_uri = data.get("error_uri")
            exception_class = self.exception_classes.get(error, UnknownTokenEndpointError)
            exception = exception_class(
                response=response,
                client=self,
                error=error,
                description=error_description,
                uri=error_uri,
            )
        except Exception as exc:
            raise InvalidPushedAuthorizationResponse(response=response, client=self) from exc
        raise exception

    def userinfo(self, access_token: BearerToken | str) -> Any:
        """Call the UserInfo endpoint.

        This sends a request to the UserInfo endpoint, with the specified access_token, and returns
        the parsed result.

        Args:
            access_token: the access token to use

        Returns:
            the [Response][requests.Response] returned by the userinfo endpoint.

        """
        if isinstance(access_token, str):
            access_token = BearerToken(access_token)
        return self._request(
            Endpoints.USER_INFO,
            auth=access_token,
            on_success=self.parse_userinfo_response,
            on_failure=self.on_userinfo_error,
        )

    def parse_userinfo_response(self, resp: requests.Response) -> Any:
        """Parse the response obtained by `userinfo()`.

        Invoked by [userinfo()][requests_oauth2client.client.OAuth2Client.userinfo] to parse the
        response from the UserInfo endpoint, this will extract and return its JSON content.

        Args:
            resp: a [Response][requests.Response] returned from the UserInfo endpoint.

        Returns:
            the parsed JSON content from this response.

        """
        return resp.json()

    def on_userinfo_error(self, resp: requests.Response) -> Any:
        """Parse UserInfo error response.

        Args:
            resp: a [Response][requests.Response] returned from the UserInfo endpoint.

        Returns:
            nothing, raises exception instead.

        """
        resp.raise_for_status()

    @classmethod
    def get_token_type(  # noqa: C901
        cls,
        token_type: str | None = None,
        token: None | str | BearerToken | IdToken = None,
    ) -> str:
        """Get standardized token type identifiers.

        Return a standardized token type identifier, based on a short `token_type` hint and/or a
        token value.

        Args:
            token_type: a token_type hint, as `str`. May be "access_token", "refresh_token"
                or "id_token"
            token: a token value, as an instance of `BearerToken` or IdToken, or as a `str`.

        Returns:
            the token_type as defined in the Token Exchange RFC8693.

        Raises:
            UnknownTokenType: if the type of token cannot be determined

        """
        if not (token_type or token):
            msg = "Cannot determine type of an empty token without a token_type hint"
            raise UnknownTokenType(msg, token, token_type)

        if token_type is None:
            if isinstance(token, str):
                msg = """\
Cannot determine the type of provided token when it is a bare `str`. Please specify a 'token_type'.
"""
                raise UnknownTokenType(msg, token, token_type)
            if isinstance(token, BearerToken):
                return "urn:ietf:params:oauth:token-type:access_token"
            if isinstance(token, IdToken):
                return "urn:ietf:params:oauth:token-type:id_token"
            msg = f"Unknown token type {type(token)}"
            raise UnknownTokenType(msg, token, token_type)
        if token_type == TokenType.ACCESS_TOKEN:
            if token is not None and not isinstance(token, (str, BearerToken)):
                msg = f"""\
The supplied token is of type '{type(token)}' which is inconsistent with token_type '{token_type}'.
A BearerToken or an access_token as a `str` is expected.
"""
                raise UnknownTokenType(msg, token, token_type)
            return "urn:ietf:params:oauth:token-type:access_token"
        if token_type == TokenType.REFRESH_TOKEN:
            if token is not None and isinstance(token, BearerToken) and not token.refresh_token:
                msg = f"""\
The supplied BearerToken does not contain a refresh_token, which is inconsistent with token_type '{token_type}'.
A BearerToken containing a refresh_token is expected.
"""
                raise UnknownTokenType(msg, token, token_type)
            return "urn:ietf:params:oauth:token-type:refresh_token"
        if token_type == TokenType.ID_TOKEN:
            if token is not None and not isinstance(token, (str, IdToken)):
                msg = f"""\
The supplied token is of type '{type(token)}' which is inconsistent with token_type '{token_type}'.
An IdToken or a string representation of it is expected.
"""
                raise UnknownTokenType(msg, token, token_type)
            return "urn:ietf:params:oauth:token-type:id_token"

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
            token_type_hint=TokenType.ACCESS_TOKEN,
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
            `True` if the revocation request is successful, `False` if this client has no configured
            revocation endpoint.

        Raises:
            MissingRefreshToken: when `refresh_token` is a [BearerToken][requests_oauth2client.tokens.BearerToken]
                but does not contain a `refresh_token`.

        """
        if isinstance(refresh_token, BearerToken):
            if refresh_token.refresh_token is None:
                raise MissingRefreshToken(refresh_token)
            refresh_token = refresh_token.refresh_token

        return self.revoke_token(
            refresh_token,
            token_type_hint=TokenType.REFRESH_TOKEN,
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
            `True` if the revocation succeeds, `False` if no revocation endpoint is present or a
            non-standardised error is returned.

        Raises:
            MissingEndpointUri: if the Revocation Endpoint URI is not configured.
            MissingRefreshToken: if `token_type_hint` is `"refresh_token"` and `token` is a BearerToken
                but does not contain a `refresh_token`.

        """
        requests_kwargs = requests_kwargs or {}

        if token_type_hint == TokenType.REFRESH_TOKEN and isinstance(token, BearerToken):
            if token.refresh_token is None:
                raise MissingRefreshToken(token)
            token = token.refresh_token

        data = dict(revoke_kwargs, token=str(token))
        if token_type_hint:
            data["token_type_hint"] = token_type_hint

        return self._request(
            Endpoints.REVOCATION,
            data=data,
            auth=self.auth,
            on_success=lambda _: True,
            on_failure=self.on_revocation_error,
            **requests_kwargs,
        )

    def on_revocation_error(self, response: requests.Response) -> bool:
        """Error handler for `revoke_token()`.

        Invoked by [revoke_token()][requests_oauth2client.client.OAuth2Client.revoke_token] when the
        revocation endpoint returns an error.

        Args:
            response: the [Response][requests.Response] as returned by the Revocation Endpoint

        Returns:
            `False` to signal that an error occurred. May raise exceptions instead depending on the
            revocation response.

        Raises:
            EndpointError: if the response contains a standardised OAuth 2.0 error.

        """
        try:
            data = response.json()
            error = data["error"]
            error_description = data.get("error_description")
            error_uri = data.get("error_uri")
            exception_class = self.exception_classes.get(error, RevocationError)
            exception = exception_class(
                response=response,
                client=self,
                error=error,
                description=error_description,
                uri=error_uri,
            )
        except Exception:  # noqa: BLE001
            return False
        raise exception

    def introspect_token(
        self,
        token: str | BearerToken,
        token_type_hint: str | None = None,
        requests_kwargs: dict[str, Any] | None = None,
        **introspect_kwargs: Any,
    ) -> Any:
        """Send a request to the Introspection Endpoint.

        Parameter `token` can be:

        - a `str`
        - a `BearerToken` instance

        You may pass any arbitrary `token` and `token_type_hint` values as `str`. Those will
        be included in the request, as-is.
        If `token` is a `BearerToken`, then `token_type_hint` must be either:

        - `None`: the access_token will be instrospected and no token_type_hint will be included
        in the request
        - `access_token`: same as `None`, but the token_type_hint will be included
        - or `refresh_token`: only available if a Refresh Token is present in the BearerToken.

        Args:
            token: the token to instrospect
            token_type_hint: the `token_type_hint` to include in the request.
            requests_kwargs: additional parameters to the underling call to requests.post()
            **introspect_kwargs: additional parameters to send to the introspection endpoint.

        Returns:
            the response as returned by the Introspection Endpoint.

        Raises:
            MissingRefreshToken: if `token_type_hint` is `"refresh_token"` and `token` is a BearerToken
                but does not contain a `refresh_token`.
            UnknownTokenType: if `token_type_hint` is neither `None`, `"access_token"` or `"refresh_token"`.

        """
        requests_kwargs = requests_kwargs or {}

        if isinstance(token, BearerToken):
            if token_type_hint is None or token_type_hint == TokenType.ACCESS_TOKEN:
                token = token.access_token
            elif token_type_hint == TokenType.REFRESH_TOKEN:
                if token.refresh_token is None:
                    raise MissingRefreshToken(token)

                token = token.refresh_token
            else:
                msg = """\
Invalid `token_type_hint`. To test arbitrary `token_type_hint` values, you must provide `token` as a `str`."""
                raise UnknownTokenType(msg, token, token_type_hint)

        data = dict(introspect_kwargs, token=str(token))
        if token_type_hint:
            data["token_type_hint"] = token_type_hint

        return self._request(
            Endpoints.INSTROSPECTION,
            data=data,
            auth=self.auth,
            on_success=self.parse_introspection_response,
            on_failure=self.on_introspection_error,
            **requests_kwargs,
        )

    def parse_introspection_response(self, response: requests.Response) -> Any:
        """Parse Token Introspection Responses received by `introspect_token()`.

        Invoked by [introspect_token()][requests_oauth2client.client.OAuth2Client.introspect_token]
        to parse the returned response. This decodes the JSON content if possible, otherwise it
        returns the response as a string.

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

        Invoked by [introspect_token()][requests_oauth2client.client.OAuth2Client.introspect_token]
        to parse the returned response in the case an error is returned.

        Args:
            response: the response as returned by the Introspection Endpoint.

        Returns:
            usually raises exceptions. A subclass can return a default response instead.

        Raises:
            EndpointError: (or one of its subclasses) if the response contains a standard OAuth 2.0 error.
            UnknownIntrospectionError: if the response is not a standard error response.

        """
        try:
            data = response.json()
            error = data["error"]
            error_description = data.get("error_description")
            error_uri = data.get("error_uri")
            exception_class = self.exception_classes.get(error, IntrospectionError)
            exception = exception_class(
                response=response,
                client=self,
                error=error,
                description=error_description,
                uri=error_uri,
            )
        except Exception as exc:
            raise UnknownIntrospectionError(response=response, client=self) from exc
        raise exception

    def backchannel_authentication_request(  # noqa: PLR0913
        self,
        scope: None | str | Iterable[str] = "openid",
        *,
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

        Raises:
            InvalidBackchannelAuthenticationRequestHintParam: if none of `login_hint`, `login_hint_token`
                or `id_token_hint` is provided, or more than one of them is provided.
            InvalidScopeParam: if the `scope` parameter is invalid.
            InvalidAcrValuesParam: if the `acr_values` parameter is invalid.

        """
        if not (login_hint or login_hint_token or id_token_hint):
            msg = "One of `login_hint`, `login_hint_token` or `ìd_token_hint` must be provided"
            raise InvalidBackchannelAuthenticationRequestHintParam(msg)

        if (login_hint_token and id_token_hint) or (login_hint and id_token_hint) or (login_hint_token and login_hint):
            msg = "Only one of `login_hint`, `login_hint_token` or `ìd_token_hint` must be provided"
            raise InvalidBackchannelAuthenticationRequestHintParam(msg)

        requests_kwargs = requests_kwargs or {}

        if scope is not None and not isinstance(scope, str):
            try:
                scope = " ".join(scope)
            except Exception as exc:
                raise InvalidScopeParam(scope) from exc

        if acr_values is not None and not isinstance(acr_values, str):
            try:
                acr_values = " ".join(acr_values)
            except Exception as exc:
                raise InvalidAcrValuesParam(acr_values) from exc

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

        return self._request(
            Endpoints.BACKCHANNEL_AUTHENTICATION,
            data=data,
            auth=self.auth,
            on_success=self.parse_backchannel_authentication_response,
            on_failure=self.on_backchannel_authentication_error,
            **requests_kwargs,
        )

    def parse_backchannel_authentication_response(
        self,
        response: requests.Response,
    ) -> BackChannelAuthenticationResponse:
        """Parse a response received by `backchannel_authentication_request()`.

        Invoked by
        [backchannel_authentication_request()][requests_oauth2client.client.OAuth2Client.backchannel_authentication_request]
        to parse the response returned by the BackChannel Authentication Endpoint.

        Args:
            response: the response returned by the BackChannel Authentication Endpoint.

        Returns:
            a `BackChannelAuthenticationResponse`

        Raises:
            InvalidBackChannelAuthenticationResponse: if the response does not contain a standard
                BackChannel Authentication response.

        """
        try:
            return BackChannelAuthenticationResponse(**response.json())
        except TypeError as exc:
            raise InvalidBackChannelAuthenticationResponse(response=response, client=self) from exc

    def on_backchannel_authentication_error(self, response: requests.Response) -> BackChannelAuthenticationResponse:
        """Error handler for `backchannel_authentication_request()`.

        Invoked by
        [backchannel_authentication_request()][requests_oauth2client.client.OAuth2Client.backchannel_authentication_request]
        to parse the response returned by the BackChannel Authentication Endpoint, when it is an
        error.

        Args:
            response: the response returned by the BackChannel Authentication Endpoint.

        Returns:
            usually raises an exception. But a subclass can return a default response instead.

        Raises:
            EndpointError: (or one of its subclasses) if the response contains a standard OAuth 2.0 error.
            InvalidBackChannelAuthenticationResponse: for non-standard error responses.

        """
        try:
            data = response.json()
            error = data["error"]
            error_description = data.get("error_description")
            error_uri = data.get("error_uri")
            exception_class = self.exception_classes.get(error, BackChannelAuthenticationError)
            exception = exception_class(
                response=response,
                client=self,
                error=error,
                description=error_description,
                uri=error_uri,
            )
        except Exception as exc:
            raise InvalidBackChannelAuthenticationResponse(response=response, client=self) from exc
        raise exception

    def authorize_device(
        self,
        requests_kwargs: dict[str, Any] | None = None,
        **data: Any,
    ) -> DeviceAuthorizationResponse:
        """Send a Device Authorization Request.

        Args:
            **data: additional data to send to the Device Authorization Endpoint
            requests_kwargs: additional parameters for `requests.request()`

        Returns:
            a Device Authorization Response

        Raises:
            MissingEndpointUri: if the Device Authorization URI is not configured

        """
        requests_kwargs = requests_kwargs or {}

        return self._request(
            Endpoints.DEVICE_AUTHORIZATION,
            data=data,
            auth=self.auth,
            on_success=self.parse_device_authorization_response,
            on_failure=self.on_device_authorization_error,
            **requests_kwargs,
        )

    def parse_device_authorization_response(self, response: requests.Response) -> DeviceAuthorizationResponse:
        """Parse a Device Authorization Response received by `authorize_device()`.

        Invoked by [authorize_device()][requests_oauth2client.client.OAuth2Client.authorize_device]
        to parse the response returned by the Device Authorization Endpoint.

        Args:
            response: the response returned by the Device Authorization Endpoint.

        Returns:
            a `DeviceAuthorizationResponse` as returned by AS

        """
        return DeviceAuthorizationResponse(**response.json())

    def on_device_authorization_error(self, response: requests.Response) -> DeviceAuthorizationResponse:
        """Error handler for `authorize_device()`.

        Invoked by [authorize_device()][requests_oauth2client.client.OAuth2Client.authorize_device]
        to parse the response returned by the Device Authorization Endpoint, when that response is
        an error.

        Args:
            response: the response returned by the Device Authorization Endpoint.

        Returns:
            usually raises an Exception. But a subclass may return a default response instead.

        Raises:
            EndpointError: for standard OAuth 2.0 errors
            InvalidDeviceAuthorizationResponse: for non-standard error responses.

        """
        try:
            data = response.json()
            error = data["error"]
            error_description = data.get("error_description")
            error_uri = data.get("error_uri")
            exception_class = self.exception_classes.get(error, DeviceAuthorizationError)
            exception = exception_class(
                response=response,
                client=self,
                error=error,
                description=error_description,
                uri=error_uri,
            )
        except Exception as exc:
            raise InvalidDeviceAuthorizationResponse(response=response, client=self) from exc
        raise exception

    def update_authorization_server_public_keys(self, requests_kwargs: dict[str, Any] | None = None) -> JwkSet:
        """Update the cached AS public keys by retrieving them from its `jwks_uri`.

        Public keys are returned by this method, as a `jwskate.JwkSet`. They are also
        available in attribute `authorization_server_jwks`.

        Returns:
            the retrieved public keys

        Raises:
            ValueError: if no `jwks_uri` is configured

        """
        requests_kwargs = requests_kwargs or {}

        jwks = self._request(
            Endpoints.JWKS,
            auth=None,
            method="GET",
            on_success=lambda resp: resp.json(),
            on_failure=lambda resp: resp.raise_for_status(),
            **requests_kwargs,
        )
        self.authorization_server_jwks.update(jwks)
        return self.authorization_server_jwks

    @classmethod
    def from_discovery_endpoint(
        cls,
        url: str | None = None,
        issuer: str | None = None,
        *,
        auth: requests.auth.AuthBase | tuple[str, str] | str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        private_key: Jwk | dict[str, Any] | None = None,
        session: requests.Session | None = None,
        testing: bool = False,
        **kwargs: Any,
    ) -> OAuth2Client:
        """Initialise an OAuth2Client based on Authorization Server Metadata.

        This will retrieve the standardised metadata document available at `url`, and will extract
        all Endpoint Uris from that document, will fetch the current public keys from its
        `jwks_uri`, then will initialise an OAuth2Client based on those endpoints.

        Args:
             url: the url where the server metadata will be retrieved
             auth: the authentication handler to use for client authentication
             client_id: client ID
             client_secret: client secret to use to authenticate the client
             private_key: private key to sign client assertions
             session: a `requests.Session` to use to retrieve the document and initialise the client with
             issuer: if an issuer is given, check that it matches the one from the retrieved document
             testing: if True, don't try to validate the endpoint urls that are part of the document
             **kwargs: additional keyword parameters to pass to OAuth2Client

        Returns:
            an OAuth2Client with endpoint initialised based on the obtained metadata

        Raises:
            InvalidParam: if neither `url` nor `issuer` are suitable urls
            requests.HTTPError: if an error happens while fetching the documents

        Example:
            ```python
            from requests_oauth2client import OAuth2Client

            client = OAuth2Client.from_discovery_endpoint(
                issuer="https://myserver.net",
                client_id="my_client_id,
                client_secret="my_client_secret"
            )
            ```

        """
        if url is None and issuer is not None:
            url = oidc_discovery_document_url(issuer)
        if url is None:
            msg = "Please specify at least one of `issuer` or `url`"
            raise InvalidParam(msg)

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
            testing=testing,
            **kwargs,
        )

    @classmethod
    def from_discovery_document(
        cls,
        discovery: dict[str, Any],
        issuer: str | None = None,
        *,
        auth: requests.auth.AuthBase | tuple[str, str] | str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        private_key: Jwk | dict[str, Any] | None = None,
        authorization_server_jwks: JwkSet | dict[str, Any] | None = None,
        session: requests.Session | None = None,
        https: bool = True,
        testing: bool = False,
        **kwargs: Any,
    ) -> OAuth2Client:
        """Initialize an OAuth2Client, based on the server metadata from `discovery`.

        Args:
             discovery: a dict of server metadata, in the same format as retrieved from a discovery endpoint.
             issuer: if an issuer is given, check that it matches the one mentioned in the document
             auth: the authentication handler to use for client authentication
             client_id: client ID
             client_secret: client secret to use to authenticate the client
             private_key: private key to sign client assertions
             authorization_server_jwks: the current authorization server JWKS keys
             session: a requests Session to use to retrieve the document and initialise the client with
             https: (deprecated) if `True`, validates that urls in the discovery document use the https scheme
             testing: if True, don't try to validate the endpoint urls that are part of the document
             **kwargs: additional args that will be passed to OAuth2Client

        Returns:
            an `OAuth2Client` initialized with the endpoints from the discovery document

        Raises:
            InvalidDiscoveryDocument: if the document does not contain at least a `"token_endpoint"`.

        """
        if not https:
            warnings.warn(
                """\
The https parameter is deprecated.
To disable endpoint uri validation, set `testing=True` when initializing your `OAuth2Client`.""",
                stacklevel=1,
            )
            testing = True
        if issuer and discovery.get("issuer") != issuer:
            msg = (
                f"Mismatching `issuer` value in discovery document"
                f" (received '{discovery.get('issuer')}', expected '{issuer}')"
            )
            raise InvalidParam(
                msg,
                issuer,
                discovery.get("issuer"),
            )
        if issuer is None:
            issuer = discovery.get("issuer")

        token_endpoint = discovery.get(Endpoints.TOKEN)
        if token_endpoint is None:
            msg = "token_endpoint not found in that discovery document"
            raise InvalidDiscoveryDocument(msg, discovery)
        authorization_endpoint = discovery.get(Endpoints.AUTHORIZATION)
        revocation_endpoint = discovery.get(Endpoints.REVOCATION)
        introspection_endpoint = discovery.get(Endpoints.INSTROSPECTION)
        userinfo_endpoint = discovery.get(Endpoints.USER_INFO)
        jwks_uri = discovery.get(Endpoints.JWKS)
        if jwks_uri is not None:
            validate_endpoint_uri(jwks_uri, https=https)
        authorization_response_iss_parameter_supported = discovery.get(
            "authorization_response_iss_parameter_supported",
            False,
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
            testing=testing,
            **kwargs,
        )

    def __enter__(self) -> Self:
        """Allow using `OAuth2Client` as a context-manager.

        The Authorization Server public keys are retrieved on `__enter__`.

        """
        self.update_authorization_server_public_keys()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> bool:
        return True

    def _require_endpoint(self, endpoint: str) -> str:
        """Check that a required endpoint url is set."""
        url = getattr(self, endpoint, None)
        if not url:
            raise MissingEndpointUri(endpoint)

        return str(url)
