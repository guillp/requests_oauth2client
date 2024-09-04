"""Implementation of CIBA.

CIBA stands for Client Initiated BackChannel Authentication and is standardised by the OpenID
Fundation.
https://openid.net/specs/openid-client-initiated-backchannel-
authentication-core-1_0.html.

"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from math import ceil
from typing import TYPE_CHECKING, Any

from attrs import define

from .pooling import BaseTokenEndpointPoolingJob
from .utils import accepts_expires_in

if TYPE_CHECKING:
    from .client import OAuth2Client
    from .tokens import BearerToken


class BackChannelAuthenticationResponse:
    """Represent a BackChannel Authentication Response.

    This contains all the parameters that are returned by the AS as a result of a BackChannel
    Authentication Request, such as `auth_req_id` (required), and the optional `expires_at`,
    `interval`, and/or any custom parameters.

    Args:
        auth_req_id: the `auth_req_id` as returned by the AS.
        expires_at: the date when the `auth_req_id` expires.
            Note that this request also accepts an `expires_in` parameter, in seconds.
        interval: the Token Endpoint pooling interval, in seconds, as returned by the AS.
        **kwargs: any additional custom parameters as returned by the AS.

    """

    @accepts_expires_in
    def __init__(
        self,
        auth_req_id: str,
        expires_at: datetime | None = None,
        interval: int | None = 20,
        **kwargs: Any,
    ) -> None:
        self.auth_req_id = auth_req_id
        self.expires_at = expires_at
        self.interval = interval
        self.other = kwargs

    def is_expired(self, leeway: int = 0) -> bool | None:
        """Return `True` if the `auth_req_id` within this response is expired.

        Expiration is evaluated at the time of the call. If there is no "expires_at" hint (which is
        derived from the `expires_in` hint returned by the AS BackChannel Authentication endpoint),
        this will return `None`.

        Returns:
            `True` if the auth_req_id is expired, `False` if it is still valid, `None` if there is
            no `expires_in` hint.

        """
        if self.expires_at:
            return datetime.now(tz=timezone.utc) - timedelta(seconds=leeway) > self.expires_at
        return None

    @property
    def expires_in(self) -> int | None:
        """Number of seconds until expiration."""
        if self.expires_at:
            return ceil((self.expires_at - datetime.now(tz=timezone.utc)).total_seconds())
        return None

    def __getattr__(self, key: str) -> Any:
        """Return attributes from this `BackChannelAuthenticationResponse`.

        Allows accessing response parameters with `token_response.expires_in` or
        `token_response.any_custom_attribute`.

        Args:
            key: a key

        Returns:
            the associated value in this token response

        Raises:
            AttributeError: if the attribute is not present in the response

        """
        return self.other.get(key) or super().__getattribute__(key)


@define(init=False)
class BackChannelAuthenticationPoolingJob(BaseTokenEndpointPoolingJob):
    """A pooling job for the BackChannel Authentication flow.

    This will poll the Token Endpoint until the user finishes with its authentication.

    Args:
        client: an OAuth2Client that will be used to pool the token endpoint.
        auth_req_id: an `auth_req_id` as `str` or a `BackChannelAuthenticationResponse`.
        interval: The pooling interval, in seconds, to use. This overrides
            the one in `auth_req_id` if it is a `BackChannelAuthenticationResponse`.
            Defaults to 5 seconds.
        slow_down_interval: Number of seconds to add to the pooling interval when the AS returns
            a slow down request.
        requests_kwargs: Additional parameters for the underlying calls to [requests.request][].
        **token_kwargs: Additional parameters for the token request.

    Example:
        ```python
        client = OAuth2Client(token_endpoint="https://my.as.local/token", auth=("client_id", "client_secret"))
        pool_job = BackChannelAuthenticationPoolingJob(
            client=client,
            auth_req_id="my_auth_req_id",
        )

        token = None
        while token is None:
            token = pool_job()
        ```

    """

    auth_req_id: str

    def __init__(
        self,
        client: OAuth2Client,
        auth_req_id: str | BackChannelAuthenticationResponse,
        *,
        interval: int | None = None,
        slow_down_interval: int = 5,
        requests_kwargs: dict[str, Any] | None = None,
        **token_kwargs: Any,
    ) -> None:
        if isinstance(auth_req_id, BackChannelAuthenticationResponse):
            interval = interval or auth_req_id.interval
            auth_req_id = auth_req_id.auth_req_id

        self.__attrs_init__(
            client=client,
            auth_req_id=auth_req_id,
            interval=interval or 5,
            slow_down_interval=slow_down_interval,
            requests_kwargs=requests_kwargs or {},
            token_kwargs=token_kwargs,
        )

    def token_request(self) -> BearerToken:
        """Implement the CIBA token request.

        This actually calls [OAuth2Client.ciba(auth_req_id)] on `client`.

        Returns:
            a [BearerToken][requests_oauth2client.tokens.BearerToken]

        """
        return self.client.ciba(self.auth_req_id, requests_kwargs=self.requests_kwargs, **self.token_kwargs)
