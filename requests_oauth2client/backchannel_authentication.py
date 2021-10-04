from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Dict, Optional

from .pooling import TokenEndpointPoolingJob
from .tokens import BearerToken
from .utils import accepts_expires_in

if TYPE_CHECKING:  # pragma: no cover
    from .client import OAuth2Client


class BackChannelAuthenticationResponse:
    """
    Represents a BackChannel Authentication Response.
    This contains all the parameters taht are returned by the AS as a result of a BackChannel Authentication Request,
    such as `auth_req_id`, `expires_at`, `interval`, and/or any custom parameters.
    """

    @accepts_expires_in
    def __init__(
        self,
        auth_req_id: str,
        expires_at: Optional[datetime] = None,
        interval: Optional[int] = 20,
        **kwargs: Any,
    ):
        """
        Initializes a `BackChannelAuthenticationResponse`. Such a response MUST include an `auth_req_id`.
        :param auth_req_id: the `auth_req_id` as returned by the AS.
        :param expires_at: the date when the `auth_req_id` expires.
        Note that this request also accepts an `expires_in` parameter, in seconds.
        :param interval: the Token Endpoint pooling interval, in seconds, as returned by the AS.
        :param kwargs: any additional custom parameters as returned by the AS.
        """
        self.auth_req_id = auth_req_id
        self.expires_at = expires_at
        self.interval = interval
        self.other = kwargs

    def is_expired(self, leeway: int = 0) -> Optional[bool]:
        """
        Returns `True` if the auth_req_id within this response is expired at the time of the call.
        :return: `True` if the auth_req_id is expired, `False` if it is still valid,
        `None` if there is no `expires_in` hint.
        """
        if self.expires_at:
            return datetime.now() - timedelta(seconds=leeway) > self.expires_at
        return None

    def __getattr__(self, key: str) -> Any:
        """
        Returns items from this Token Response.
        Allows accessing response parameters with `token_response.expires_in` or `token_response.any_custom_attribute`
        :param key: a key
        :return: the associated value in this token response
        :raises AttributeError: if the attribute is not present in the response
        """
        if key == "expires_in":
            if self.expires_at is None:
                return None
            return int(self.expires_at.timestamp() - datetime.now().timestamp())
        return self.other.get(key) or super().__getattribute__(key)


class BackChannelAuthenticationPoolingJob(TokenEndpointPoolingJob):
    """A pooling job for checking if the user has finished with his authorization in a Device Authorization flow.

    Usage:
    ```python
    client = OAuth2Client(
        token_endpoint="https://my.as.local/token", auth=("client_id", "client_secret")
    )
    pool_job = BackChannelAuthenticationPoolingJob(
        client=client, auth_req_id="my_auth_req_id"
    )

    token = None
    while token is None:
        token = pool_job()
    ```
    """

    def __init__(
        self,
        client: "OAuth2Client",
        auth_req_id: str,
        interval: Optional[int] = None,
        slow_down_interval: int = 5,
        requests_kwargs: Optional[Dict[str, Any]] = None,
        **token_kwargs: Any,
    ):
        super().__init__(
            client=client,
            interval=interval,
            slow_down_interval=slow_down_interval,
            requests_kwargs=requests_kwargs,
            **token_kwargs,
        )
        self.auth_req_id = auth_req_id

    def pool(self) -> BearerToken:
        return self.client.ciba(
            self.auth_req_id, requests_kwargs=self.requests_kwargs, **self.token_kwargs
        )
