from datetime import datetime

import requests

from .exceptions import ExpiredToken


class BearerToken:
    """
    A wrapper around a Bearer Token and associated expiration date and refresh token,
    as returned by an OAuth20 or OIDC Token Endpoint.
    """

    def __init__(self, access_token, expires_at=None, refresh_token=None):
        self.access_token = access_token
        self.expires_at = expires_at
        self.refresh_token = refresh_token

    def is_expired(self):
        """
        Returns true if the access token is expired at the time of the call.
        :return:
        """
        if self.expires_at:
            return datetime.now() > self.expires_at

    def authorization_header(self):
        """
        Returns the Authorization Header value containing this access token, correctly formatted as per RFC6750.
        :return: the value to use in a HTTP Authorization Header
        """
        return f"Bearer {self.access_token}"

    def __str__(self):
        """
        Returns the access token
        :return: the access token string
        """
        return self.access_token


class BearerAuthorization(requests.auth.AuthBase):
    """
    A Requests compatible Authentication helper for API protected with Bearer tokens.
    """

    def __init__(self, token):
        self.token = token

    @property
    def token(self):
        return self._token

    @token.setter
    def token(self, token):
        if token is not None and not isinstance(token, BearerToken):
            token = BearerToken(str(token))
        self._token = token

    def __call__(self, request):
        if self.token is None:
            return request
        if self.token.is_expired():
            raise ExpiredToken(self.token)
        request.headers["Authorization"] = self.token.authorization_header()
        return request


class OAuth2ClientCredentials(BearerAuthorization):
    """
    A Requests Authentication handler that automatically gets access tokens from an OAuth20 Token Endpoint
    with the Client Credentials grant (and can get a new one once it is expired).
    """

    def __init__(self, client, **token_kwargs):
        super().__init__(None)
        self.client = client
        self.token_kwargs = token_kwargs

    def __call__(self, request):
        if self.token is None or self.token.is_expired():
            self.token = self.client.client_credentials(**self.token_kwargs).access_token()
        return super().__call__(request)


class OAuth20AccessAndRefreshToken(BearerAuthorization):
    """
    A Requests Authentication handler that handles a Bearer access token and automatically it them when expired.
    """

    def __init__(self, client, token, **token_kwargs):
        super().__init__(token)
        self.client = client
        self.token_kwargs = token_kwargs

    def __call__(self, request):
        if self.token.is_expired():
            if self.token.refresh_token:
                self.token = self.client.refresh_token(
                    refresh_token=self.token.refresh_token, **self.token_kwargs
                ).access_token()
        return super().__call__(request)


class OAuth2AuthorizationCode(OAuth20AccessAndRefreshToken):
    """
    A Requests Authentication handler that exchanges an authorization code for an access token,
    then automatically refreshes it once it is expired.
    """

    def __init__(self, client, code, **token_kwargs):
        super().__init__(None)
        self.client = client
        self.code = code
        self.token_kwargs = token_kwargs

    def __call__(self, request):
        if self.token is None or self.token.is_expired():
            if self.code:
                self.token = self.client.authorization_code(
                    code=self.code, **self.token_kwargs
                ).access_token()
                self.code = None
        return super().__call__(request)
