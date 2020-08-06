class OAuth2Error(Exception):
    pass


class TokenResponseError(OAuth2Error):
    def __init__(self, error, description, uri):
        self.error = error
        self.description = description
        self.uri = uri


class InvalidTokenResponse(OAuth2Error):
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


class ExpiredToken(OAuth2Error):
    pass
