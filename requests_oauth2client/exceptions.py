from typing import Optional


class OAuth2Error(Exception):
    """
    Base class for Exceptions raised by requests_oauth2client.
    """


class EndpointError(OAuth2Error):
    """
    Base class for exceptions raised when a token endpoint returns a standardised error.
    """

    def __init__(
        self, error: str, description: Optional[str] = None, uri: Optional[str] = None
    ):
        self.error = error
        self.description = description
        self.uri = uri


class InvalidTokenResponse(OAuth2Error):
    """
    Base class for exceptions raised when a token endpoint returns a non-standardised response.
    """


class ExpiredAccessToken(OAuth2Error):
    """
    Raised when an expired access token is used.
    """


class UnknownEndpointError(EndpointError):
    """
    Raised when an otherwise unknown error is returned by the token endpoint.
    """


class ServerError(EndpointError):
    """
    Raised when the token endpoint returns error = server_error
    """


class TokenEndpointError(EndpointError):
    """
    Base class for errors that are specific to the token endpoint.
    """


class InvalidScope(TokenEndpointError):
    pass


class InvalidTarget(TokenEndpointError):
    pass


class InvalidGrant(TokenEndpointError):
    pass


class AccessDenied(EndpointError):
    pass


class UnauthorizedClient(EndpointError):
    pass


class RevocationError(EndpointError):
    pass


class UnsupportedTokenType(RevocationError):
    pass


class IntrospectionError(EndpointError):
    pass


class UnknownIntrospectionError(OAuth2Error):
    pass


class DeviceAuthorizationError(EndpointError):
    pass


class AuthorizationPending(TokenEndpointError):
    pass


class SlowDown(TokenEndpointError):
    pass


class ExpiredToken(TokenEndpointError):
    pass


class InvalidDeviceAuthorizationResponse(OAuth2Error):
    pass


class InvalidUrl(ValueError):
    pass


class InvalidJWT(ValueError):
    pass


class InvalidIdToken(InvalidJWT):
    pass


class InvalidSignature(ValueError):
    pass


class InvalidClaim(ValueError):
    pass


class AuthorizationResponseError(Exception):
    def __init__(
        self, error: str, description: Optional[str] = None, uri: Optional[str] = None
    ):
        self.error = error
        self.description = description
        self.uri = uri


class InteractionRequired(AuthorizationResponseError):
    pass


class LoginRequired(InteractionRequired):
    pass


class AccountSelectionRequired(InteractionRequired):
    pass


class SessionSelectionRequired(InteractionRequired):
    pass


class ConsentRequired(InteractionRequired):
    pass


class InvalidAuthResponse(OAuth2Error):
    """
    Base class for errors due to Auth Responses that don't obey the standard (e.g. missing mandatory params)
    """


class MissingAuthCode(InvalidAuthResponse):
    """
    Raised when the authorization code is missing from the auth response and no error is returned.
    """


class MismatchingState(InvalidAuthResponse):
    """
    Raised when an auth response contains a state parameter that doesn't match the expected state.
    """


class BackChannelAuthenticationError(EndpointError):
    pass


class InvalidBackChannelAuthenticationResponse(OAuth2Error):
    pass
