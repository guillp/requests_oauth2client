"""This module contains `requests`-compatible Auth Handlers that implement OAuth 2.0."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import requests
from attr import field
from attrs import define, frozen, setters
from typing_extensions import override

from .exceptions import ExpiredAccessToken
from .tokens import BearerToken

if TYPE_CHECKING:
    from .authorization_request import AuthorizationResponse
    from .client import OAuth2Client
    from .device_authorization import DeviceAuthorizationResponse


@frozen(init=False)
class BearerAuth(requests.auth.AuthBase):
    """An Auth Handler that includes a Bearer Token in API calls, as defined in [RFC6750$2.1].

    As a prerequisite to using this `AuthBase`, you have to obtain an access token manually.
    You most likely don't want to do that by yourself, but instead use an instance of
    [OAuth2Client][requests_oauth2client.client.OAuth2Client] to do that for you.
    See the others Auth Handlers in this module, which will automatically obtain
    access tokens from an OAuth 2.x server.

    [RFC6750$2.1]: https://datatracker.ietf.org/doc/html/rfc6750#section-2.1

    Usage:
        ```python
        auth = BearerAuth("my_access_token")
        resp = requests.get("https://my.api.local/resource", auth=auth)
        ```

        The HTTP request will look like:
        ```
        GET /resource HTTP/1.1
        Host: my.api.local
        Authorization: Bearer my_access_token
        ```

    Args:
        token: a [BearerToken][requests_oauth2client.tokens.BearerToken] or a string
            to use as token for this Auth Handler. If `None`, this Auth Handler is a no-op.

    """

    token: BearerToken | None

    def __init__(self, token: str | BearerToken | None = None) -> None:
        if token is not None and not isinstance(token, BearerToken):
            token = BearerToken(token)
        self.__attrs_init__(token=token)

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        """Implement the usage of Bearer Tokens in requests.

        This will add a properly formatted `Authorization: Bearer <token>` header in the request.

        If the configured token is an instance of BearerToken with an expires_at attribute, raises
        [ExpiredAccessToken][requests_oauth2client.exceptions.ExpiredAccessToken] once the access
        token is expired.

        Args:
            request: a [PreparedRequest][requests.PreparedRequest]

        Returns:
            a [PreparedRequest][requests.PreparedRequest] with an Access Token added in
            Authorization Header

        """
        if self.token is None:
            return request
        if self.token.is_expired():
            raise ExpiredAccessToken(self.token)
        request.headers["Authorization"] = self.token.authorization_header()
        return request


@define
class BaseOAuth2RenewableTokenAuth(requests.auth.AuthBase):
    """Base class for BearerToken-based Auth Handlers, with an obtainable or renewable token.

    In addition to adding a properly formatted `Authorization` header, this will obtain a new token
    once the current token is expired. Expiration is detected based on the `expires_in` hint
    returned by the AS. A configurable `leeway`, in number of seconds, will make sure that a new
    token is obtained some seconds before the actual expiration is reached. This may help in
    situations where the client, AS and RS have slightly offset clocks.

    Args:
        client: an OAuth2Client
        token: an initial Access Token, if you have one already. In most cases, leave `None`.
        leeway: expiration leeway, in number of seconds
        token_kwargs: additional kwargs to include in token requests

    """

    client: OAuth2Client = field(on_setattr=setters.frozen)
    bearer_auth: BearerAuth | None
    leeway: int = field(on_setattr=setters.frozen)
    token_kwargs: dict[str, Any] = field(on_setattr=setters.frozen)

    @property
    def token(self) -> BearerToken | None:
        """The BearerToken associated with this Authentication Method."""
        if self.bearer_auth is not None:
            return self.bearer_auth.token
        return None

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        """Add the Access Token to the request.

        If Access Token is not specified or expired, obtain a new one first.

        """
        if self.bearer_auth is None or self.bearer_auth.token is None or self.bearer_auth.token.is_expired(self.leeway):
            self.renew_token()
        if self.bearer_auth:
            return self.bearer_auth.__call__(request)
        return request

    def renew_token(self) -> None:
        """Obtain a new Bearer Token.

        Subclasses should implement this.

        """
        raise NotImplementedError

    def forget_token(self) -> None:
        """Forget the current token, forcing a renewal on the next HTTP request."""
        self.bearer_auth = None


@define
class BaseOAuth2RefreshTokenAuth(BaseOAuth2RenewableTokenAuth):
    """Base class for flows which can have a refresh-token.

    This implements a `renew_token()` method which uses the refresh token to obtain new tokens.

    """

    @override
    def renew_token(self) -> None:
        """Obtain a new token, using the Refresh Token, if available."""
        if self.token is not None and self.token.refresh_token and self.client is not None:
            self.bearer_auth = BearerAuth(
                self.client.refresh_token(refresh_token=self.token.refresh_token, **self.token_kwargs)
            )


@define(init=False)
class OAuth2ClientCredentialsAuth(BaseOAuth2RenewableTokenAuth):
    """An Auth Handler for the Client Credentials grant.

    This [requests AuthBase][requests.auth.AuthBase] automatically gets Access Tokens from an OAuth
    2.0 Token Endpoint with the Client Credentials grant, and will get a new one once the current
    one is expired.

    Args:
        client: the [OAuth2Client][requests_oauth2client.client.OAuth2Client] to use to obtain Access Tokens.
        **token_kwargs: extra kw parameters to pass to the Token Endpoint. May include `scope`, `resource`, etc.

    Usage:
        ```python
        client = OAuth2Client(token_endpoint="https://my.as.local/token", auth=("client_id", "client_secret"))
        oauth2cc = OAuth2ClientCredentialsAuth(client, scope="my_scope")
        resp = requests.post("https://my.api.local/resource", auth=oauth2cc)
        ```

    """

    def __init__(
        self, client: OAuth2Client, *, leeway: int = 20, token: str | BearerToken | None = None, **token_kwargs: Any
    ) -> None:
        self.__attrs_init__(client=client, bearer_auth=BearerAuth(token), leeway=leeway, token_kwargs=token_kwargs)

    @override
    def renew_token(self) -> None:
        """Obtain a new token for use within this Auth Handler."""
        self.bearer_auth = BearerAuth(self.client.client_credentials(**self.token_kwargs))


@define(init=False)
class OAuth2AccessTokenAuth(BaseOAuth2RefreshTokenAuth):
    """Authentication Handler for OAuth 2.0 Access Tokens and (optional) Refresh Tokens.

    This [Requests Auth handler][requests.auth.AuthBase] implementation uses an access token as
    Bearer token, and can automatically refresh it when expired, if a refresh token is available.

    Token can be a simple `str` containing a raw access token value, or a
    [BearerToken][requests_oauth2client.tokens.BearerToken] that can contain a refresh_token. If a
    refresh_token and an expiration date are available, this Auth Handler will automatically refresh
    the access token once it is expired.

    Args:
        client: the [OAuth2Client][requests_oauth2client.client.OAuth2Client] to use to refresh tokens.
        token: a access token that has been previously obtained
        **token_kwargs: additional kwargs to pass to the token endpoint

    Usage:
        ```python
        client = OAuth2Client(token_endpoint="https://my.as.local/token", auth=("client_id", "client_secret"))
        token = BearerToken(
            access_token="access_token", expires_in=600, refresh_token="refresh_token"
        )  # obtain a BearerToken any way you see fit, including a refresh token
        oauth2at_auth = OAuth2ClientCredentialsAuth(client, token, scope="my_scope")
        resp = requests.post("https://my.api.local/resource", auth=oauth2at_auth)
        ````

    """

    def __init__(
        self, client: OAuth2Client, token: str | BearerToken | None, *, leeway: int = 20, **token_kwargs: Any
    ) -> None:
        self.__attrs_init__(client=client, bearer_auth=BearerAuth(token), leeway=leeway, token_kwargs=token_kwargs)


@define(init=False)
class OAuth2AuthorizationCodeAuth(BaseOAuth2RefreshTokenAuth):
    """Authentication handler for the Authorization Code grant.

    This [Requests Auth handler][requests.auth.AuthBase] implementation exchanges an Authorization
    Code for an access token, then automatically refreshes it once it is expired.

    Args:
        client: the [OAuth2Client][requests_oauth2client.client.OAuth2Client] to use to obtain Access Tokens.
        code: an Authorization Code that has been obtained from the AS.
        **token_kwargs: additional kwargs to pass to the token endpoint

    Usage:
        ```python
        client = OAuth2Client(token_endpoint="https://my.as.local/token", auth=("client_id", "client_secret"))
        code = "my_code"  # you must obtain this code yourself
        resp = requests.post("https://my.api.local/resource", auth=OAuth2AuthorizationCodeAuth(client, code))
        ````

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
        self.__attrs_init__(
            client=client,
            bearer_auth=BearerAuth(token),
            code=code,
            leeway=leeway,
            token_kwargs=token_kwargs,
        )

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        """Implement the Authorization Code grant as an Authentication Handler.

        This exchanges an Authorization Code for an access token and adds it in the request.

        Args:
            request: a [PreparedRequest][requests.PreparedRequest]

        Returns:
            a [PreparedRequest][requests.PreparedRequest] with an Access Token added in
            Authorization Header

        """
        if self.token is None or self.token.is_expired():
            self.exchange_code_for_token()
        return super().__call__(request)

    def exchange_code_for_token(self) -> None:
        """Obtain the initial access token with the authorization_code grant."""
        if self.code:  # pragma: no branch
            self.bearer_auth = BearerAuth(self.client.authorization_code(code=self.code, **self.token_kwargs))
            self.code = None


@define(init=False)
class OAuth2ResourceOwnerPasswordAuth(BaseOAuth2RenewableTokenAuth):
    """Authentication Handler for the [Resource Owner Password Flow](https://www.rfc-editor.org/rfc/rfc6749#section-4.3).

    This [Requests Auth handler][requests.auth.AuthBase] implementation exchanges the user
    credentials for an Access Token, then automatically obtains a new one once it is expired.

    Note that this flow is considered *deprecated*, and the Authorization Code flow should be
    used whenever possible. Among other bad things, ROPC does not support SSO nor MFA and
    depends on the user typing its credentials directly inside the application instead of on a
    dedicated login page, which makes it totally insecure for 3rd party apps.

    It needs the username and password and an
    [OAuth2Client][requests_oauth2client.client.OAuth2Client] to be able to get a token from
    the AS Token Endpoint just before the first request using this Auth Handler is being sent.

    Args:
        client: the [OAuth2Client][requests_oauth2client.client.OAuth2Client] to use to obtain
            Access Tokens
        username: the username
        password: the user password
        leeway: an amount of time, in seconds
        **token_kwargs: additional kwargs to pass to the token endpoint

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
        self.__attrs_init__(
            client=client,
            bearer_auth=BearerAuth(token),
            leeway=leeway,
            token_kwargs=token_kwargs,
            username=username,
            password=password,
        )

    @override
    def renew_token(self) -> None:
        """Exchange the user credentials for an Access Token."""
        self.bearer_auth = BearerAuth(
            self.client.resource_owner_password(
                username=self.username,
                password=self.password,
                **self.token_kwargs,
            )
        )


@define(init=False)
class OAuth2DeviceCodeAuth(BaseOAuth2RefreshTokenAuth):
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
        **token_kwargs: additional kwargs to pass to the token endpoint.

    Usage:
        ```python
        client = OAuth2Client(token_endpoint="https://my.as.local/token", auth=("client_id", "client_secret"))
        device_code = client.device_authorization()
        auth = OAuth2DeviceCodeAuth(client, device_code)
        resp = requests.post("https://my.api.local/resource", auth=auth)
        ````
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
        self.__attrs_init__(
            client=client,
            bearer_auth=BearerAuth(token),
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
        if self.token is not None and self.token.is_expired():
            self.renew_token()
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
            self.bearer_auth = BearerAuth(token)
            self.device_code = None
