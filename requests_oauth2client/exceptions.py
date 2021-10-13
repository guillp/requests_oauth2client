"""This module contains all exceptions that can be raised by methods from `requests_oauth2client`."""

from typing import Optional

from requests_oauth2client.jwskate import InvalidJwt


class OAuth2Error(Exception):
    """Base class for Exceptions raised by requests_oauth2client."""


class EndpointError(OAuth2Error):
    """Base class for exceptions raised when a token endpoint returns a standardised error."""

    def __init__(
        self, error: str, description: Optional[str] = None, uri: Optional[str] = None
    ):
        """
        Initialize an `EndpointError`.

        An `EndpointError` contains the error message, description and uri that are returned by the AS.

        :param error: the `error` identifier as returned by the AS
        :param description: the `error_description` as returned by the AS
        :param uri: the `error_uri` as returned by the AS
        """
        self.error = error
        self.description = description
        self.uri = uri


class InvalidTokenResponse(OAuth2Error):
    """Base class for exceptions raised when a token endpoint returns a non-standardised response."""


class ExpiredAccessToken(OAuth2Error):
    """Raised when an expired access token is used."""


class UnknownTokenEndpointError(EndpointError):
    """Raised when an otherwise unknown error is returned by the token endpoint."""


class ServerError(EndpointError):
    """Raised when the token endpoint returns `error = server_error`."""


class TokenEndpointError(EndpointError):
    """Base class for errors that are specific to the token endpoint."""


class InvalidScope(TokenEndpointError):
    """Raised when the Token Endpoint returns `error = invalid_scope`."""


class InvalidTarget(TokenEndpointError):
    """Raised when the Token Endpoint returns `error = invalid_target`."""


class InvalidGrant(TokenEndpointError):
    """Raised when the Token Endpoint returns `error = invalid_grant`."""


class AccessDenied(EndpointError):
    """Raised when the Authorization Server returns `error = access_denied`."""


class UnauthorizedClient(EndpointError):
    """Raised when the Authorization Server returns `error = unauthorized_client`."""


class RevocationError(EndpointError):
    """Base class for Revocation Endpoint errors."""


class UnsupportedTokenType(RevocationError):
    """Raised when the Revocation endpoint returns `error = unsupported_token_type`."""


class IntrospectionError(EndpointError):
    """Base class for Introspection Endpoint errors."""


class UnknownIntrospectionError(OAuth2Error):
    """Raised when the Introspection Endpoint retuns a non-standard error."""


class DeviceAuthorizationError(EndpointError):
    """Base class for Device Authorization Endpoint errors."""


class AuthorizationPending(TokenEndpointError):
    """Raised when the Token Endpoint returns `error = authorization_pending`."""


class SlowDown(TokenEndpointError):
    """Raised when the Token Endpoint returns `error = slow_down`."""


class ExpiredToken(TokenEndpointError):
    """Raised when the Token Endpoint returns `error = expired_token`."""


class InvalidDeviceAuthorizationResponse(OAuth2Error):
    """Raised when the Device Authorization Endpoint returns a non-standard error response."""


class InvalidIdToken(InvalidJwt):
    """Raised when trying to validate an invalid Id Token value."""


class AuthorizationResponseError(Exception):
    """Base class for error responses returned by the Authorization endpoint."""

    def __init__(
        self, error: str, description: Optional[str] = None, uri: Optional[str] = None
    ):
        """
        Initialize an `AuthorizationResponseError`.

        An `AuthorizationResponseError` contains the error message, description and uri that are returned by the AS.

        :param error: the `error` identifier as returned by the AS
        :param description: the `error_description` as returned by the AS
        :param uri: the `error_uri` as returned by the AS
        """
        self.error = error
        self.description = description
        self.uri = uri


class InteractionRequired(AuthorizationResponseError):
    """Raised when the Authorization Endpoint returns `error = interaction_required`."""


class LoginRequired(InteractionRequired):
    """Raised when the Authorization Endpoint returns `error = login_required`."""


class AccountSelectionRequired(InteractionRequired):
    """Raised when the Authorization Endpoint returns `error = account_selection_required`."""


class SessionSelectionRequired(InteractionRequired):
    """Raised when the Authorization Endpoint returns `error = session_selection_required`."""


class ConsentRequired(InteractionRequired):
    """Raised when the Authorization Endpoint returns `error = consent_required`."""


class InvalidAuthResponse(OAuth2Error):
    """Base class for errors due to Auth Responses that don't obey the standard (e.g. missing mandatory params)."""


class MissingAuthCode(InvalidAuthResponse):
    """Raised when the authorization code is missing from the auth response and no error is returned."""


class MismatchingState(InvalidAuthResponse):
    """Raised when an auth response contains a state parameter that doesn't match the expected state."""


class BackChannelAuthenticationError(EndpointError):
    """Base class for errors returned by the BackChannel Authentication endpoint."""


class InvalidBackChannelAuthenticationResponse(OAuth2Error):
    """Raised when the BackChannel Authentication endpoint returns non-standardised errors."""
