from typing import TYPE_CHECKING, Any, Optional, Union

import requests

from .exceptions import ExpiredToken
from .token_response import BearerToken

if TYPE_CHECKING:
    from .client import OAuth2Client


class BearerAuth(requests.auth.AuthBase):
    """
    A Requests compatible Authentication helper for API protected with Bearer tokens.
    """

    def __init__(self, token: Union[str, BearerToken] = None) -> None:
        self.token = token  # type: ignore[assignment] # until https://github.com/python/mypy/issues/3004 is fixed

    @property
    def token(self) -> Optional[BearerToken]:
        return self._token

    @token.setter
    def token(self, token: Union[str, BearerToken]) -> None:
        if token is not None and not isinstance(token, BearerToken):
            token = BearerToken(token)
        self._token = token

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        if self.token is None:
            return request
        if self.token.is_expired():
            raise ExpiredToken(self.token)
        request.headers["Authorization"] = self.token.authorization_header()
        return request


class OAuth2ClientCredentialsAuth(BearerAuth):
    """
    A Requests Authentication handler that automatically gets access tokens from an OAuth20 Token Endpoint
    with the Client Credentials grant (and can get a new one once it is expired).
    """

    def __init__(self, client: OAuth2Client, **token_kwargs: Any):
        super().__init__(None)
        self.client = client
        self.token_kwargs = token_kwargs

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        token = self.token
        if token is None or token.is_expired():
            self.token = self.client.client_credentials(**self.token_kwargs)
        return super().__call__(request)


class OAuth20AccessAndRefreshTokenAuth(BearerAuth):
    """
    A Requests Authentication handler that handles a Bearer access token and automatically it them when expired.
    """

    def __init__(self, client: OAuth2Client, token: str = None, **token_kwargs: Any) -> None:
        super().__init__(token)
        self.client = client
        self.token_kwargs = token_kwargs

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        token = self.token
        if token is not None and token.is_expired() and token.refresh_token:
            self.token = self.client.refresh_token(
                refresh_token=token.refresh_token, **self.token_kwargs
            )
        return super().__call__(request)


class OAuth2AuthorizationCodeAuth(OAuth20AccessAndRefreshTokenAuth):
    """
    A Requests Authentication handler that exchanges an authorization code for an access token,
    then automatically refreshes it once it is expired.
    """

    def __init__(self, client: OAuth2Client, code: str, **token_kwargs: Any) -> None:
        super().__init__(client, None)
        self.code: Optional[str] = code
        self.token_kwargs = token_kwargs

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        token = self.token
        if token is None or token.is_expired():
            if self.code:
                self.token = self.client.authorization_code(code=self.code, **self.token_kwargs)
                self.code = None
        return super().__call__(request)
