from typing import TYPE_CHECKING, Any, Optional, Union

import requests

from .exceptions import ExpiredAccessToken
from .tokens import BearerToken

if TYPE_CHECKING:  # pragma: no cover
    from .client import OAuth2Client


class BearerAuth(requests.auth.AuthBase):
    """
    A Requests compatible Authentication helper for API protected with Bearer tokens.
    Using this AuthBase, you have to obtain an access token manually.

    Usage:
    ```python
    auth = BearerAuth("my_access_token")
    resp = requests.post("https://my.api.local/resource", auth=auth)
    ```
    """

    def __init__(self, token: Optional[Union[str, BearerToken]] = None) -> None:
        """
        Initialize an Auth Handler with an existing Access Token.
        :param token: a :class:`BearerToken` to use for this Auth Handler. If `None`, this Auth Handler does nothing.
        """
        self.token = token  # type: ignore[assignment] # until https://github.com/python/mypy/issues/3004 is fixed

    @property
    def token(self) -> Optional[BearerToken]:
        """
        The token that is used for authorization against the API.
        :return: the configured :class:`BearerToken` used with this AuthHandler.
        """
        return self._token

    @token.setter
    def token(self, token: Union[str, BearerToken]) -> None:
        """
        Changes the access token used with this AuthHandler. Accepts a :class:`BearerToken` or an access token as `str`.
        :param token: an access token to use for this Auth Handler
        """
        if token is not None and not isinstance(token, BearerToken):
            token = BearerToken(token)
        self._token = token

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        if self.token is None:
            return request
        if self.token.is_expired():
            raise ExpiredAccessToken(self.token)
        request.headers["Authorization"] = self.token.authorization_header()
        return request


class OAuth2ClientCredentialsAuth(BearerAuth):
    """
    A Requests Authentication handler that automatically gets access tokens from an OAuth 2.0 Token Endpoint
    with the Client Credentials grant, then will get a new one once the current one is expired.

    Usage:
    ```python
    client = OAuth2Client(
        token_endpoint="https://my.as.local/token", auth=("client_id", "client_secret")
    )
    oauth2cc = OAuth2ClientCredentialsAuth(client, scope="my_scope")
    resp = requests.post("https://my.api.local/resource", auth=oauth2cc)
    ```
    """

    def __init__(self, client: "OAuth2Client", **token_kwargs: Any):
        """
        Initializes an OAuth2ClientCredentialsAuth.
        :param client: the :class:`OAuth2Client` to use to obtain Access Tokens.
        :param token_kwargs: extra kw parameters to pass to the Token Endpoint. May include `scope`, `resource`, etc.
        """
        super().__init__(None)
        self.client = client
        self.token_kwargs = token_kwargs

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        token = self.token
        if token is None or token.is_expired():
            self.token = self.client.client_credentials(**self.token_kwargs)
        return super().__call__(request)


class OAuth2AccessTokenAuth(BearerAuth):
    """
    A Requests Authentication handler using a Bearer access token, and can automatically refreshes it when expired.

    Usage:
    ```python
    client = OAuth2Client(token_endpoint="https://my.as.local/token", auth=("client_id", "client_secret"))
    token = BearerToken(
        access_token="access_token",
        expires_in=600,
        refresh_token="refresh_token")  # obtain a BearerToken any way you see fit, including a refresh token
    oauth2at_auth = OAuth2ClientCredentialsAuth(client, token, scope="my_scope")
    resp = requests.post("https://my.api.local/resource", auth=oauth2at_auth)
    ````
    """

    def __init__(
        self,
        client: "OAuth2Client",
        token: Optional[Union[str, BearerToken]] = None,
        **token_kwargs: Any,
    ) -> None:
        """
        Initializes an `OAuth2AccessTokenAuth`, with an (optional) initial token.
        :param client: an :class:`OAuth2Client` configured to talk to the token endpoint.
        :param token: a :class:`BearerToken` that has been retrieved from the token endpoint manually
        :param token_kwargs: additional kwargs to pass to the token endpoint
        """
        super().__init__(token)
        self.client = client
        self.token_kwargs = token_kwargs

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        token = self.token
        if (
            token is not None
            and token.is_expired()
            and token.refresh_token
            and self.client is not None
        ):
            self.token = self.client.refresh_token(
                refresh_token=token.refresh_token, **self.token_kwargs
            )
        return super().__call__(request)


class OAuth2AuthorizationCodeAuth(OAuth2AccessTokenAuth):
    """
    A Requests Auth handler that exchanges an Authorization Code for an access token,
    then automatically refreshes it once it is expired.

    Usage:
    ```python
    client = OAuth2Client(token_endpoint="https://my.as.local/token", auth=("client_id", "client_secret"))
    code = "my_code"
    oauth2ac_auth = OAuth2AuthorizationCodeAuth(client, code)
    resp = requests.post("https://my.api.local/resource", auth=oauth2ac_auth)
    ````
    """

    def __init__(self, client: "OAuth2Client", code: str, **token_kwargs: Any) -> None:
        """
        Initializes an `OAuth2AuthorizationCodeAuth` with a given Authorization Code.
        :param client: an :class:`OAuth2Client` configured to talk to the token endpoint.
        :param code: an Authorization Code that has been manually obtained from the AS.
        :param token_kwargs: additional kwargs to pass to the token endpoint
        """
        super().__init__(client, None)
        self.code: Optional[str] = code
        self.token_kwargs = token_kwargs

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        token = self.token
        if token is None or token.is_expired():
            if self.code:  # pragma: no branch
                self.token = self.client.authorization_code(
                    code=self.code, **self.token_kwargs
                )
                self.code = None
        return super().__call__(request)


class OAuth2DeviceCodeAuth(OAuth2AccessTokenAuth):
    """
    A Requests Auth handler that exchanges a Device Code for an access token,
    then automatically refreshes it once it is expired.

    Usage:
    ```python
    client = OAuth2Client(token_endpoint="https://my.as.local/token", auth=("client_id", "client_secret"))
    device_code = "my_device_code"
    oauth2ac_auth = OAuth2DeviceCodeAuth(client, device_code)
    resp = requests.post("https://my.api.local/resource", auth=oauth2ac_auth)
    ````
    """

    def __init__(
        self,
        client: "OAuth2Client",
        device_code: str,
        interval: int = 5,
        expires_in: int = 360,
        **token_kwargs: Any,
    ) -> None:
        """
        Initializes an :class:`OAuth2DeviceCodeAuth`.
        :param client: an :class:`OAuth2Client` configured to talk to the token endpoint.
        :param device_code: a Device Code obtained from the AS.
        :param interval: the interval to use to pool the Token Endpoint, in seconds.
        :param expires_in: the lifetime of the token, in seconds
        :param token_kwargs: additional kwargs to pass to the token endpoint
        """
        super().__init__(client, None)
        self.device_code: Optional[str] = device_code
        self.interval = interval
        self.expires_in = expires_in
        self.token_kwargs = token_kwargs

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        from .device_authorization import DeviceAuthorizationPoolingJob

        token = self.token
        if token is None or token.is_expired():
            if self.device_code:  # pragma: no branch
                pooling_job = DeviceAuthorizationPoolingJob(
                    client=self.client,
                    device_code=self.device_code,
                    interval=self.interval,
                )
                while self.token is None:
                    self.token = pooling_job()
                self.device_code = None
        return super().__call__(request)
