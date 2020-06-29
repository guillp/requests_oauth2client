import requests

from .auth import BearerAuthorization
from .exceptions import (AccessDenied, InvalidGrant, InvalidScope, InvalidTokenResponse,
                         UnauthorizedClient, UnknownTokenResponseError)
from .token_response import TokenResponse


class OAuth20Client:
    """
    An OAuth20 client, able to obtain tokens from the Token Endpoint using one of the standardised Grant Types.
    """

    exception_classes = {
        "invalid_scope": InvalidScope,
        "invalid_grant": InvalidGrant,
        "access_denied": AccessDenied,
        "unauthorized_client": UnauthorizedClient,
    }

    token_response_class = TokenResponse

    def __init__(self, token_endpoint, auth_method, revocation_endpoint=None, session=None):
        """
        :param token_endpoint: the token endpoint where this client will get access tokens
        :param auth_method: the authentication handler to use for client authentication on the token endpoint
        :param revocation_endpoint: the revocation endpoint url to use for revoking tokens
        :param session: a requests Session to use when sending HTTP requests
        """
        self.token_endpoint = token_endpoint
        self.revocation_endpoint = revocation_endpoint
        self.auth_method = auth_method
        self.session = session or requests.Session()

    def token_request(self, kwargs):
        """
        Sends a authenticated request to the token endpoint.
        :param kwargs: parameters to send to the token endpoint
        :return: the token endpoint response, as TokenResponse instance.
        """
        response = self.session.post(self.token_endpoint, auth=self.auth_method, data=kwargs)
        if response.ok:
            token_response = self.token_response_class(**response.json())
            return token_response

        # error handling
        error_json = response.json()
        error = error_json.get("error")
        error_description = error_json.get("error_description")
        error_uri = error_json.get("error_uri")
        if error:
            exception_class = self.exception_classes.get(error)
            if exception_class:
                raise exception_class(error_description, error_uri)
            else:
                raise UnknownTokenResponseError(error, error_description, error_uri)

        if error_description or error_uri:
            raise InvalidTokenResponse(
                "error_message or error_uri returned without error",
                error_description,
                error_uri,
            )

    def client_credentials(self, **token_kwargs):
        """
        Sends a request to the token endpoint with the client_credentials grant.
        :param token_kwargs: additional args to pass to the token endpoint
        :return: a TokenResponse
        """
        data = dict(grant_type="client_credentials", **token_kwargs)
        return self.token_request(data)

    def authorization_code(self, code, **token_kwargs):
        """
        Sends a request to the token endpoint with the authorization_code grant.
        :param code: an authorization code to exchange for tokens
        :param token_kwargs: additional args to pass to the token endpoint
        :return: a TokenResponse
        """
        data = dict(grant_type="authorization_code", code=code, **token_kwargs)
        return self.token_request(data)

    def refresh_token(self, refresh_token, **token_kwargs):
        """
        Sends a request to the token endpoint with the refresh_token grant.
        :param refresh_token: a refresh_token
        :param token_kwargs: additional args to pass to the token endpoint
        :return: a TokenResponse
        """
        data = dict(grant_type="refresh_token", refresh_token=refresh_token, **token_kwargs)
        return self.token_request(data)

    def revoke_access_token(self, access_token, **requests_kwargs):
        """
        Sends a request to the revocation endpoint to revoke an access token.
        :param access_token: the access token to revoke
        :param requests_kwargs: additional parameters to pass to the revocation endpoint
        """
        if self.revocation_endpoint:
            self.session.post(
                data={"token": str(access_token), "token_type_hint": "access_token"},
                **requests_kwargs,
            ).raise_for_status()

    def revoke_refresh_token(self, refresh_token, **requests_kwargs):
        """
        Sends a request to the revocation endpoint to revoke a refresh token.
        :param refresh_token: the refresh token to revoke
        :param requests_kwargs: additional parameters to pass to the revocation endpoint
        """
        if self.revocation_endpoint:
            self.session.post(
                data={"token": refresh_token, "token_type_hint": "refresh_token"},
                **requests_kwargs,
            ).raise_for_status()

    @classmethod
    def from_discovery_endpoint(cls, url, auth_method, session=None):
        """
        Initialise an OAuth20Client, retrieving server metadata from a discovery document.
        :param url: the url where the server metadata will be retrieved
        :param auth_method: the authentication handler to use for client authentication
        :param session: a requests Session to use to retrieve the document and initialise the client with
        :return: a OAuth20Client
        """
        session = session or requests.Session()
        discovery = session.get(url)
        return cls.from_discovery_document(discovery, auth_method=auth_method, session=session)

    @classmethod
    def from_discovery_document(cls, discovery, auth_method, session=None):
        """
        Initialises an OAuth20Client, based on the server metadata from `discovery`.
        :param discovery: a dict of server metadata, in the same format as retrieved from a discvovery endpoint.
        :param auth_method: the authentication handler to use for client authentication
        :param session: a requests Session to use to retrieve the document and initialise the client with
        :return: an OAuth20Client
        """
        return cls(
            token_endpoint=discovery["token_endpoint"], auth_method=auth_method, session=session
        )


class OpenIdConnectClient(OAuth20Client):
    """
    An OIDC compatible client. It can do everything an OAuth20Client can do, and call the userinfo endpoint.
    """

    def __init__(
            self, token_endpoint, userinfo_endpoint, jwks_endpoint, auth_method, session=None
    ):
        super().__init__(
            token_endpoint=token_endpoint, auth_method=auth_method, session=session
        )
        self.userinfo_endpoint = userinfo_endpoint
        self.jwks_endpoint = jwks_endpoint

    def userinfo(self, access_token):
        """
        Calls the userinfo endpoint with the specified access_token and returns the result.
        :param access_token: the access token to use
        :return: the requests Response returned by the userinfo endpoint.
        """
        return self.session.post(auth=BearerAuthorization(access_token))

    @classmethod
    def from_discovery_document(cls, discovery, auth_method, session=None):
        return cls(
            token_endpoint=discovery["token_endpoint"],
            userinfo_endpoint=discovery["userinfo_endpoint"],
            jwks_endpoint=discovery["jwks_endpoint"],
            auth_method=auth_method,
            session=session,
        )
