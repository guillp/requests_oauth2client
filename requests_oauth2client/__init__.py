import requests  # type: ignore

from .api_client import ApiClient
from .auth import (
    BearerAuth,
    OAuth2AccessTokenAuth,
    OAuth2AuthorizationCodeAuth,
    OAuth2ClientCredentialsAuth,
    OAuth2DeviceCodeAuth,
)
from .authorization_request import AuthorizationRequest, PkceUtils
from .backchannel_authentication import (
    BackChannelAuthenticationPoolingJob,
    BackChannelAuthenticationResponse,
)
from .client import OAuth2Client
from .client_authentication import (
    ClientSecretBasic,
    ClientSecretJWT,
    ClientSecretPost,
    PrivateKeyJWT,
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
from .utils import (
    accepts_expires_in,
    b64_decode,
    b64_encode,
    b64u_decode,
    b64u_encode,
    json_encode,
    validate_endpoint_uri,
)
