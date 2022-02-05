"""Main module for `requests_oauth2client`. You can import any class from any submodule directly from this main module."""

import requests

from .api_client import ApiClient
from .auth import (
    BearerAuth,
    OAuth2AccessTokenAuth,
    OAuth2AuthorizationCodeAuth,
    OAuth2ClientCredentialsAuth,
    OAuth2DeviceCodeAuth,
)
from .authorization_request import (
    AuthorizationRequest,
    AuthorizationResponse,
    PkceUtils,
)
from .backchannel_authentication import (
    BackChannelAuthenticationPoolingJob,
    BackChannelAuthenticationResponse,
)
from .client import OAuth2Client
from .client_authentication import (
    BaseClientAuthenticationMethod,
    ClientSecretBasic,
    ClientSecretJWT,
    ClientSecretJwt,
    ClientSecretPost,
    PrivateKeyJWT,
    PrivateKeyJwt,
    PublicApp,
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
    ConsentRequired,
    DeviceAuthorizationError,
    EndpointError,
    ExpiredAccessToken,
    ExpiredToken,
    InteractionRequired,
    InvalidBackChannelAuthenticationResponse,
    InvalidDeviceAuthorizationResponse,
    InvalidGrant,
    InvalidIdToken,
    InvalidScope,
    InvalidTokenResponse,
    LoginRequired,
    MismatchingIssuer,
    MismatchingState,
    MissingAuthCode,
    OAuth2Error,
    ServerError,
    SessionSelectionRequired,
    SlowDown,
    UnauthorizedClient,
    UnknownIntrospectionError,
    UnknownTokenEndpointError,
    UnsupportedTokenType,
)
from .jwskate import (
    ECJwk,
    ExpiredJwt,
    InvalidClaim,
    InvalidJwk,
    InvalidJws,
    InvalidJwt,
    InvalidSignature,
    Jwk,
    JwkSet,
    JwsCompact,
    Jwt,
    JwtSigner,
    OKPJwk,
    PrivateKeyRequired,
    RSAJwk,
    SignedJwt,
    SymetricJwk,
)
from .tokens import BearerToken, BearerTokenSerializer, IdToken
