"""This module contains all exception classes from `requests_oauth2client`."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import requests

    from requests_oauth2client.authorization_request import AuthorizationRequest
    from requests_oauth2client.client import OAuth2Client


class OAuth2Error(Exception):
    """Base class for Exceptions raised when a backend endpoint returns an error.

    Args:
        response: the HTTP response containing the error
        client : the OAuth2Client used to send the request

    """

    def __init__(self, response: requests.Response, client: OAuth2Client) -> None:
        super().__init__("The remote endpoint returned an error")
        self.response = response
        self.client = client

    @property
    def request(self) -> requests.PreparedRequest:
        """The request leading to the error."""
        return self.response.request


class EndpointError(OAuth2Error):
    """Base class for exceptions raised from backend endpoint errors.

    This contains the error message, description and uri that are returned
    by the AS in the OAuth 2.0 standardised way.

    Args:
        response: the raw response containing the error.
        error: the `error` identifier as returned by the AS.
        description: the `error_description` as returned by the AS.
        uri: the `error_uri` as returned by the AS.

    """

    def __init__(
        self,
        response: requests.Response,
        client: OAuth2Client,
        error: str,
        description: str | None = None,
        uri: str | None = None,
    ) -> None:
        super().__init__(response=response, client=client)
        self.error = error
        self.description = description
        self.uri = uri


class InvalidTokenResponse(OAuth2Error):
    """Raised when the Token Endpoint returns a non-standard response."""


class UnknownTokenEndpointError(EndpointError):
    """Raised when an otherwise unknown error is returned by the token endpoint."""


class ServerError(EndpointError):
    """Raised when the token endpoint returns `error = server_error`."""


class TokenEndpointError(EndpointError):
    """Base class for errors that are specific to the token endpoint."""


class InvalidRequest(TokenEndpointError):
    """Raised when the Token Endpoint returns `error = invalid_request`."""


class InvalidClient(TokenEndpointError):
    """Raised when the Token Endpoint returns `error = invalid_client`."""


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
    """Raised when the Introspection Endpoint returns a non-standard error."""


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


class AuthorizationResponseError(Exception):
    """Base class for error responses returned by the Authorization endpoint.

    An `AuthorizationResponseError` contains the error message, description and uri that are
    returned by the AS.

    Args:
        error: the `error` identifier as returned by the AS
        description: the `error_description` as returned by the AS
        uri: the `error_uri` as returned by the AS

    """

    def __init__(
        self,
        request: AuthorizationRequest,
        response: str,
        error: str,
        description: str | None = None,
        uri: str | None = None,
    ) -> None:
        self.error = error
        self.description = description
        self.uri = uri
        self.request = request
        self.response = response


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


class InvalidAuthResponse(ValueError):
    """Raised when the Authorization Endpoint returns an invalid response."""

    def __init__(self, message: str, request: AuthorizationRequest, response: str) -> None:
        super().__init__(f"The Authorization Response is invalid: {message}")
        self.request = request
        self.response = response


class MissingAuthCode(InvalidAuthResponse):
    """Raised when the Authorization Endpoint does not return the mandatory `code`.

    This happens when the Authorization Endpoint does not return an error, but does not return an
    authorization `code` either.

    """

    def __init__(self, request: AuthorizationRequest, response: str) -> None:
        super().__init__("missing `code` query parameter in response", request, response)


class MissingIssuer(InvalidAuthResponse):
    """Raised when the Authorization Endpoint does not return an `iss` parameter as expected.

    The Authorization Server advertises its support with a flag
    `authorization_response_iss_parameter_supported` in its discovery document. If it is set to
    `true`, it must include an `iss` parameter in its authorization responses, containing its issuer
    identifier.

    """

    def __init__(self, request: AuthorizationRequest, response: str) -> None:
        super().__init__("missing `iss` query parameter in response", request, response)


class MismatchingState(InvalidAuthResponse):
    """Raised on mismatching `state` value.

    This happens when the Authorization Endpoints returns a 'state' parameter that doesn't match the
    value passed in the Authorization Request.

    """

    def __init__(self, received: str, expected: str, request: AuthorizationRequest, response: str) -> None:
        super().__init__(f"mismatching `state` (received '{received}', expected '{expected}')", request, response)
        self.received = received
        self.expected = expected


class MismatchingIssuer(InvalidAuthResponse):
    """Raised on mismatching `iss` value.

    This happens when the Authorization Endpoints returns an 'iss' that doesn't match the expected
    value.

    """

    def __init__(self, received: str, expected: str, request: AuthorizationRequest, response: str) -> None:
        super().__init__(f"mismatching `iss` (received '{received}', expected '{expected}')", request, response)
        self.received = received
        self.expected = expected


class BackChannelAuthenticationError(EndpointError):
    """Base class for errors returned by the BackChannel Authentication endpoint."""


class InvalidBackChannelAuthenticationResponse(OAuth2Error):
    """Raised when the BackChannel Authentication endpoint returns a non-standard response."""


class InvalidPushedAuthorizationResponse(OAuth2Error):
    """Raised when the Pushed Authorization Endpoint returns an error."""
