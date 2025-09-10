"""Contains enumerations of standardised OAuth-related parameters and values.

Most are taken from https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml .

"""

from __future__ import annotations

from enum import Enum


class AccessTokenTypes(str, Enum):
    """An enum of standardised `access_token` types."""

    BEARER = "Bearer"
    DPOP = "DPoP"


class CodeChallengeMethods(str, Enum):
    """All standardised `code_challenge_method` values.

    You should always use `S256`.

    """

    S256 = "S256"
    plain = "plain"


class Endpoints(str, Enum):
    """All standardised OAuth 2.0 and extensions endpoints.

    If an endpoint is not mentioned here, then its usage is not supported by OAuth2Client.

    """

    TOKEN = "token_endpoint"
    AUTHORIZATION = "authorization_endpoint"
    BACKCHANNEL_AUTHENTICATION = "backchannel_authentication_endpoint"
    DEVICE_AUTHORIZATION = "device_authorization_endpoint"
    INTROSPECTION = "introspection_endpoint"
    REVOCATION = "revocation_endpoint"
    PUSHED_AUTHORIZATION_REQUEST = "pushed_authorization_request_endpoint"
    JWKS = "jwks_uri"
    USER_INFO = "userinfo_endpoint"


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


class ResponseTypes(str, Enum):
    """All standardised `response_type` values.

    Note that you should always use `code`. All other values are deprecated.

    """

    CODE = "code"
    NONE = "none"
    TOKEN = "token"
    IDTOKEN = "id_token"
    CODE_IDTOKEN = "code id_token"
    CODE_TOKEN = "code token"
    CODE_IDTOKEN_TOKEN = "code id_token token"
    IDTOKEN_TOKEN = "id_token token"


class TokenType(str, Enum):
    """An enum of standardised `token_type` values."""

    ACCESS_TOKEN = "access_token"
    REFRESH_TOKEN = "refresh_token"
    ID_TOKEN = "id_token"
