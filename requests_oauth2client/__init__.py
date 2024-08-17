"""Main module for `requests_oauth2client`.

You can import any class from any submodule directly from this main module.

"""

import requests
from jwskate import EncryptionAlgs, KeyManagementAlgs, SignatureAlgs

from .api_client import ApiClient, InvalidBoolFieldsParam, InvalidPathParam
from .auth import (
    BaseOAuth2RenewableTokenAuth,
    NonRenewableTokenError,
    OAuth2AccessTokenAuth,
    OAuth2AuthorizationCodeAuth,
    OAuth2ClientCredentialsAuth,
    OAuth2DeviceCodeAuth,
    OAuth2ResourceOwnerPasswordAuth,
)
from .authorization_request import (
    AuthorizationRequest,
    AuthorizationRequestSerializer,
    AuthorizationResponse,
    CodeChallengeMethods,
    InvalidCodeVerifierParam,
    InvalidMaxAgeParam,
    PkceUtils,
    RequestParameterAuthorizationRequest,
    RequestUriParameterAuthorizationRequest,
    ResponseTypes,
    UnsupportedCodeChallengeMethod,
    UnsupportedResponseTypeParam,
)
from .backchannel_authentication import (
    BackChannelAuthenticationPoolingJob,
    BackChannelAuthenticationResponse,
)
from .client import (
    Endpoints,
    GrantTypes,
    OAuth2Client,
)
from .client_authentication import (
    BaseClientAssertionAuthenticationMethod,
    BaseClientAuthenticationMethod,
    ClientSecretBasic,
    ClientSecretJwt,
    ClientSecretPost,
    InvalidClientAssertionSigningKeyOrAlg,
    InvalidRequestForClientAuthentication,
    PrivateKeyJwt,
    PublicApp,
    UnsupportedClientCredentials,
)
from .device_authorization import (
    DeviceAuthorizationPoolingJob,
    DeviceAuthorizationResponse,
)
from .discovery import (
    oauth2_discovery_document_url,
    oidc_discovery_document_url,
    well_known_uri,
)
from .exceptions import (
    AccessDenied,
    AccountSelectionRequired,
    AuthorizationPending,
    AuthorizationResponseError,
    BackChannelAuthenticationError,
    ConsentRequired,
    DeviceAuthorizationError,
    EndpointError,
    ExpiredToken,
    InteractionRequired,
    IntrospectionError,
    InvalidAuthResponse,
    InvalidBackChannelAuthenticationResponse,
    InvalidClient,
    InvalidDeviceAuthorizationResponse,
    InvalidGrant,
    InvalidPushedAuthorizationResponse,
    InvalidRequest,
    InvalidScope,
    InvalidTarget,
    InvalidTokenResponse,
    LoginRequired,
    MismatchingIssuer,
    MismatchingState,
    MissingAuthCode,
    MissingIdToken,
    MissingIssuer,
    OAuth2Error,
    RevocationError,
    ServerError,
    SessionSelectionRequired,
    SlowDown,
    TokenEndpointError,
    UnauthorizedClient,
    UnknownIntrospectionError,
    UnknownTokenEndpointError,
    UnsupportedTokenType,
)
from .pooling import (
    BaseTokenEndpointPoolingJob,
)
from .tokens import (
    BearerToken,
    BearerTokenSerializer,
    ExpiredAccessToken,
    ExpiredIdToken,
    IdToken,
    InvalidIdToken,
    MismatchingAcr,
    MismatchingAudience,
    MismatchingAzp,
    MismatchingIdTokenAlg,
    MismatchingNonce,
)
from .utils import (
    InvalidUri,
    validate_endpoint_uri,
    validate_issuer_uri,
)

__all__ = [
    "AccessDenied",
    "AccountSelectionRequired",
    "ApiClient",
    "AuthorizationPending",
    "AuthorizationRequest",
    "AuthorizationRequestSerializer",
    "AuthorizationResponse",
    "AuthorizationResponseError",
    "BackChannelAuthenticationError",
    "BackChannelAuthenticationPoolingJob",
    "BackChannelAuthenticationResponse",
    "BaseClientAuthenticationMethod",
    "BaseOAuth2RenewableTokenAuth",
    "BaseTokenEndpointPoolingJob",
    "BearerToken",
    "BearerTokenSerializer",
    "BaseClientAssertionAuthenticationMethod",
    "ClientSecretBasic",
    "ClientSecretJwt",
    "ClientSecretPost",
    "CodeChallengeMethods",
    "ConsentRequired",
    "DeviceAuthorizationError",
    "DeviceAuthorizationPoolingJob",
    "DeviceAuthorizationResponse",
    "EncryptionAlgs",
    "EndpointError",
    "Endpoints",
    "ExpiredAccessToken",
    "ExpiredIdToken",
    "ExpiredToken",
    "GrantTypes",
    "IdToken",
    "InteractionRequired",
    "IntrospectionError",
    "InvalidAuthResponse",
    "InvalidBackChannelAuthenticationResponse",
    "InvalidBoolFieldsParam",
    "InvalidClient",
    "InvalidClientAssertionSigningKeyOrAlg",
    "InvalidCodeVerifierParam",
    "InvalidDeviceAuthorizationResponse",
    "InvalidGrant",
    "InvalidIdToken",
    "InvalidMaxAgeParam",
    "InvalidPathParam",
    "InvalidPushedAuthorizationResponse",
    "InvalidRequest",
    "InvalidRequestForClientAuthentication",
    "InvalidScope",
    "InvalidTarget",
    "InvalidTokenResponse",
    "InvalidUri",
    "KeyManagementAlgs",
    "LoginRequired",
    "MismatchingAcr",
    "MismatchingAudience",
    "MismatchingAzp",
    "MismatchingIdTokenAlg",
    "MismatchingIssuer",
    "MismatchingNonce",
    "MismatchingState",
    "MissingAuthCode",
    "MissingIdToken",
    "MissingIssuer",
    "NonRenewableTokenError",
    "OAuth2AccessTokenAuth",
    "OAuth2AuthorizationCodeAuth",
    "OAuth2Client",
    "OAuth2ClientCredentialsAuth",
    "OAuth2DeviceCodeAuth",
    "OAuth2Error",
    "OAuth2ResourceOwnerPasswordAuth",
    "PkceUtils",
    "PrivateKeyJwt",
    "PublicApp",
    "RequestParameterAuthorizationRequest",
    "RequestUriParameterAuthorizationRequest",
    "ResponseTypes",
    "RevocationError",
    "ServerError",
    "SessionSelectionRequired",
    "SignatureAlgs",
    "SlowDown",
    "TokenEndpointError",
    "UnauthorizedClient",
    "UnknownIntrospectionError",
    "UnknownTokenEndpointError",
    "UnsupportedClientCredentials",
    "UnsupportedCodeChallengeMethod",
    "UnsupportedResponseTypeParam",
    "UnsupportedTokenType",
    "requests",
    "oauth2_discovery_document_url",
    "oidc_discovery_document_url",
    "validate_endpoint_uri",
    "validate_issuer_uri",
    "well_known_uri",
]
