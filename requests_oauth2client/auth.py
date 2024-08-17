"""This module contains `requests`-compatible Auth Handlers that implement OAuth 2.0."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import requests
from attrs import define, field, setters
from typing_extensions import override

from .tokens import BearerToken

if TYPE_CHECKING:
    from .authorization_request import AuthorizationResponse
    from .client import OAuth2Client
    from .device_authorization import DeviceAuthorizationResponse


class NonRenewableTokenError(Exception):
    """Raised when attempting to renew a token non-interactively when missing renewing material."""


@define(init=False)
class BaseOAuth2RenewableTokenAuth(requests.auth.AuthBase):
    """Base class for BearerToken-based Auth Handlers, with an obtainable or renewable token.

    In addition to adding a properly formatted `Authorization` header, this will obtain a new token
    once the current token is expired. Expiration is detected based on the `expires_in` hint
    returned by the AS. A configurable `leeway`, in number of seconds, will make sure that a new
    token is obtained some seconds before the actual expiration is reached. This may help in
    situations where the client, AS and RS have slightly offset clocks.

    """

    client: OAuth2Client = field(on_setattr=setters.frozen)
    token: BearerToken | None
    leeway: int = field(on_setattr=setters.frozen)
    token_kwargs: dict[str, Any] = field(on_setattr=setters.frozen)

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        """Add the Access Token to the request.

        If Access Token is not specified or expired, obtain a new one first.

        Raises:
            NonRenewableTokenError: if the token is not renewable

        """
        if self.token is None or self.token.is_expired(self.leeway):
            self.renew_token()
        if self.token is None:
            raise NonRenewableTokenError  # pragma: no cover
        return self.token(request)

    def renew_token(self) -> None:
        """Obtain a new Bearer Token.

        Subclasses should implement this.

        """
        raise NotImplementedError

    def forget_token(self) -> None:
        """Forget the current token, forcing a renewal on the next HTTP request."""
        self.token = None


@define(init=False)
class BaseOAuth2RefreshTokenAuth(BaseOAuth2RenewableTokenAuth):
    """Base class for flows which can have a refresh-token.

    This implements a `renew_token()` method which uses the refresh token to obtain new tokens.

    """

    @override
    def renew_token(self) -> None:
        """Obtain a new token, using the Refresh Token, if available.

        Raises:
            NonRenewableTokenError: if the token is not renewable.

        """
        if self.token is None or self.token.refresh_token is None:
            raise NonRenewableTokenError

        self.token = self.client.refresh_token(refresh_token=self.token, **self.token_kwargs)


@define(init=False)
class OAuth2ClientCredentialsAuth(BaseOAuth2RenewableTokenAuth):
    """An Auth Handler for the [Client Credentials grant](https://www.rfc-editor.org/rfc/rfc6749#section-4.4).

    This [requests AuthBase][requests.auth.AuthBase] automatically gets Access Tokens from an OAuth
    2.0 Token Endpoint with the Client Credentials grant, and will get a new one once the current
    one is expired.

    Args:
        client: the [OAuth2Client][requests_oauth2client.client.OAuth2Client] to use to obtain Access Tokens.
        token: an initial Access Token, if you have one already. In most cases, leave `None`.
        leeway: expiration leeway, in number of seconds
        **token_kwargs: extra kw parameters to pass to the Token Endpoint. May include `scope`, `resource`, etc.

    Example:
        ```python
        from requests_oauth2client import OAuth2Client, OAuth2ClientCredentialsAuth, requests

        client = OAuth2Client(token_endpoint="https://my.as.local/token", auth=("client_id", "client_secret"))
        oauth2cc = OAuth2ClientCredentialsAuth(client, scope="my_scope")
        resp = requests.post("https://my.api.local/resource", auth=oauth2cc)
        ```

    """

    def __init__(
        self, client: OAuth2Client, *, leeway: int = 20, token: str | BearerToken | None = None, **token_kwargs: Any
    ) -> None:
        if isinstance(token, str):
            token = BearerToken(token)
        self.__attrs_init__(client=client, token=token, leeway=leeway, token_kwargs=token_kwargs)

    @override
    def renew_token(self) -> None:
        """Obtain a new token for use within this Auth Handler."""
        self.token = self.client.client_credentials(**self.token_kwargs)


@define(init=False)
class OAuth2AccessTokenAuth(BaseOAuth2RefreshTokenAuth):
    """Authentication Handler for OAuth 2.0 Access Tokens and (optional) Refresh Tokens.

    This [Requests Auth handler][requests.auth.AuthBase] implementation uses an access token as
    Bearer token, and can automatically refresh it when expired, if a refresh token is available.

    Token can be a simple `str` containing a raw access token value, or a
    [BearerToken][requests_oauth2client.tokens.BearerToken] that can contain a `refresh_token`.
    If a `refresh_token` and an expiration date are available (based on `expires_in` hint),
    this Auth Handler will automatically refresh the access token once it is expired.

    Args:
        client: the client to use to refresh tokens.
        token: an initial Access Token, if you have one already. In most cases, leave `None`.
        leeway: expiration leeway, in number of seconds.
        **token_kwargs: additional kwargs to pass to the token endpoint.

    Example:
        ```python
        from requests_oauth2client import BearerToken, OAuth2Client, OAuth2AccessTokenAuth, requests

        client = OAuth2Client(token_endpoint="https://my.as.local/token", auth=("client_id", "client_secret"))
        # obtain a BearerToken any way you see fit, optionally including a refresh token
        # for this example, the token value is hardcoded
        token = BearerToken(access_token="access_token", expires_in=600, refresh_token="refresh_token")
        auth = OAuth2AccessTokenAuth(client, token, scope="my_scope")
        resp = requests.post("https://my.api.local/resource", auth=auth)
        ```

    """

    def __init__(
        self, client: OAuth2Client, token: str | BearerToken, *, leeway: int = 20, **token_kwargs: Any
    ) -> None:
        if isinstance(token, str):
            token = BearerToken(token)
        self.__attrs_init__(client=client, token=token, leeway=leeway, token_kwargs=token_kwargs)


@define(init=False)
class OAuth2AuthorizationCodeAuth(BaseOAuth2RefreshTokenAuth):  # type: ignore[override]
    """Authentication handler for the [Authorization Code grant](https://www.rfc-editor.org/rfc/rfc6749#section-4.1).

    This [Requests Auth handler][requests.auth.AuthBase] implementation exchanges an Authorization
    Code for an access token, then automatically refreshes it once it is expired.

    Args:
        client: the client to use to obtain Access Tokens.
        code: an Authorization Code that has been obtained from the AS.
        token: an initial Access Token, if you have one already. In most cases, leave `None`.
        leeway: expiration leeway, in number of seconds.
        **token_kwargs: additional kwargs to pass to the token endpoint.

    Example:
        ```python
        from requests_oauth2client import ApiClient, OAuth2Client, OAuth2AuthorizationCodeAuth

        client = OAuth2Client(token_endpoint="https://myas.local/token", auth=("client_id", "client_secret"))
        code = "my_code"  # you must obtain this code yourself
        api = ApiClient("https://my.api.local/resource", auth=OAuth2AuthorizationCodeAuth(client, code))
        ```

    """

    code: str | AuthorizationResponse | None

    def __init__(
        self,
        client: OAuth2Client,
        code: str | AuthorizationResponse | None,
        *,
        leeway: int = 20,
        token: str | BearerToken | None = None,
        **token_kwargs: Any,
    ) -> None:
        if isinstance(token, str):
            token = BearerToken(token)
        self.__attrs_init__(
            client=client,
            token=token,
            code=code,
            leeway=leeway,
            token_kwargs=token_kwargs,
        )

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        """Implement the Authorization Code grant as an Authentication Handler.

        This exchanges an Authorization Code for an access token and adds it in the request.

        Args:
            request: the request

        Returns:
            the request, with an Access Token added in Authorization Header

        """
        if self.token is None or self.token.is_expired():
            self.exchange_code_for_token()
        return super().__call__(request)

    def exchange_code_for_token(self) -> None:
        """Exchange the authorization code for an access token."""
        if self.code:  # pragma: no branch
            self.token = self.client.authorization_code(code=self.code, **self.token_kwargs)
            self.code = None


@define(init=False)
class OAuth2ResourceOwnerPasswordAuth(BaseOAuth2RenewableTokenAuth):  # type: ignore[override]
    """Authentication Handler for the [Resource Owner Password Credentials Flow](https://www.rfc-editor.org/rfc/rfc6749#section-4.3).

    This [Requests Auth handler][requests.auth.AuthBase] implementation exchanges the user
    credentials for an Access Token, then automatically repeats the process to get a new one
    once the current one is expired.

    Note that this flow is considered *deprecated*, and the Authorization Code flow should be
    used whenever possible.
    Among other bad things, ROPC:

    - does not support SSO between multiple apps,
    - does not support MFA or risk-based adaptative authentication,
    - depends on the user typing its credentials directly inside the application, instead of on a
    dedicated, centralized login page managed by the AS, which makes it totally insecure for 3rd party apps.

    It needs the username and password and an
    [OAuth2Client][requests_oauth2client.client.OAuth2Client] to be able to get a token from
    the AS Token Endpoint just before the first request using this Auth Handler is being sent.

    Args:
        client: the client to use to obtain Access Tokens
        username: the username
        password: the user password
        leeway: an amount of time, in seconds
        token: an initial Access Token, if you have one already. In most cases, leave `None`.
        **token_kwargs: additional kwargs to pass to the token endpoint

    Example:
        ```python
        from requests_oauth2client import ApiClient, OAuth2Client, OAuth2ResourceOwnerPasswordAuth

        client = OAuth2Client(
            token_endpoint="https://myas.local/token",
            auth=("client_id", "client_secret"),
        )
        username = "my_username"
        password = "my_password"  # you must obtain those credentials from the user
        auth = OAuth2ResourceOwnerPasswordAuth(client, username=username, password=password)
        api = ApiClient("https://myapi.local", auth=auth)
        ```
    """

    username: str
    password: str

    def __init__(
        self,
        client: OAuth2Client,
        *,
        username: str,
        password: str,
        leeway: int = 20,
        token: str | BearerToken | None = None,
        **token_kwargs: Any,
    ) -> None:
        if isinstance(token, str):
            token = BearerToken(token)
        self.__attrs_init__(
            client=client,
            token=token,
            leeway=leeway,
            token_kwargs=token_kwargs,
            username=username,
            password=password,
        )

    @override
    def renew_token(self) -> None:
        """Exchange the user credentials for an Access Token."""
        self.token = self.client.resource_owner_password(
            username=self.username,
            password=self.password,
            **self.token_kwargs,
        )


@define(init=False)
class OAuth2DeviceCodeAuth(BaseOAuth2RefreshTokenAuth):  # type: ignore[override]
    """Authentication Handler for the [Device Code Flow](https://www.rfc-editor.org/rfc/rfc8628).

    This [Requests Auth handler][requests.auth.AuthBase] implementation exchanges a Device Code for
    an Access Token, then automatically refreshes it once it is expired.

    It needs a Device Code and an [OAuth2Client][requests_oauth2client.client.OAuth2Client] to be
    able to get a token from the AS Token Endpoint just before the first request using this Auth
    Handler is being sent.

    Args:
        client: the [OAuth2Client][requests_oauth2client.client.OAuth2Client] to use to obtain Access Tokens.
        device_code: a Device Code obtained from the AS.
        interval: the interval to use to pool the Token Endpoint, in seconds.
        expires_in: the lifetime of the token, in seconds.
        token: an initial Access Token, if you have one already. In most cases, leave `None`.
        leeway: expiration leeway, in number of seconds.
        **token_kwargs: additional kwargs to pass to the token endpoint.

    Example:
        ```python
        from requests_oauth2client import OAuth2Client, OAuth2DeviceCodeAuth, requests

        client = OAuth2Client(token_endpoint="https://my.as.local/token", auth=("client_id", "client_secret"))
        device_code = client.device_authorization()
        auth = OAuth2DeviceCodeAuth(client, device_code)
        resp = requests.post("https://my.api.local/resource", auth=auth)
        ```

    """

    device_code: str | DeviceAuthorizationResponse
    interval: int
    expires_in: int

    def __init__(
        self,
        client: OAuth2Client,
        *,
        device_code: str | DeviceAuthorizationResponse,
        leeway: int = 20,
        interval: int = 5,
        expires_in: int = 360,
        token: str | BearerToken | None = None,
        **token_kwargs: Any,
    ) -> None:
        if isinstance(token, str):
            token = BearerToken(token)
        self.__attrs_init__(
            client=client,
            token=token,
            leeway=leeway,
            token_kwargs=token_kwargs,
            device_code=device_code,
            interval=interval,
            expires_in=expires_in,
        )

    @override
    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        """Implement the Device Code grant as a request Authentication Handler.

        This exchanges a Device Code for an access token and adds it in HTTP requests.

        Args:
            request: a [requests.PreparedRequest][]

        Returns:
            a [requests.PreparedRequest][] with an Access Token added in Authorization Header

        """
        if self.token is None:
            self.exchange_device_code_for_token()
        return super().__call__(request)

    def exchange_device_code_for_token(self) -> None:
        """Exchange the Device Code for an access token.

        This will poll the Token Endpoint until the user finishes the authorization process.

        """
        from .device_authorization import DeviceAuthorizationPoolingJob

        if self.device_code:  # pragma: no branch
            pooling_job = DeviceAuthorizationPoolingJob(
                client=self.client,
                device_code=self.device_code,
                interval=self.interval,
            )
            token = None
            while token is None:
                token = pooling_job()
            self.token = token
            self.device_code = None
