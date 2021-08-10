from typing import Optional


class OAuth2Error(Exception):
    pass


class TokenResponseError(OAuth2Error):
    def __init__(
        self, error: str, description: Optional[str] = None, uri: Optional[str] = None
    ):
        self.error = error
        self.description = description
        self.uri = uri


class InvalidTokenResponse(OAuth2Error):
    pass


class ExpiredToken(OAuth2Error):
    pass


class UnknownTokenResponseError(TokenResponseError):
    pass


class UnsupportedTokenType(TokenResponseError):
    pass


class InvalidScope(TokenResponseError):
    pass


class InvalidGrant(TokenResponseError):
    pass


class InvalidState(TokenResponseError):
    pass


class AccessDenied(TokenResponseError):
    pass


class UnauthorizedClient(TokenResponseError):
    pass


class DeviceAuthorizationError(TokenResponseError):
    pass


class AuthorizationPending(DeviceAuthorizationError):
    pass


class SlowDown(DeviceAuthorizationError):
    pass


class ExpiredDeviceCode(DeviceAuthorizationError):
    pass


class InvalidDeviceAuthorizationResponse(OAuth2Error):
    pass


class InvalidUrl(ValueError):
    pass
