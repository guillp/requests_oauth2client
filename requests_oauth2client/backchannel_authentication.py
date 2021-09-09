from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, Optional

from .pooling import TokenEndpointPoolingJob
from .tokens import BearerToken
from .utils import accepts_expires_in

if TYPE_CHECKING:  # pragma: no cover
    from .client import OAuth2Client


class BackChannelAuthenticationResponse:
    @accepts_expires_in
    def __init__(
        self,
        auth_req_id: str,
        expires_at: Optional[datetime] = None,
        interval: Optional[int] = 20,
        **kwargs: Any,
    ):
        self.auth_req_id = auth_req_id
        self.expires_at = expires_at
        self.interval = interval
        self.other = kwargs

    def is_expired(self) -> Optional[bool]:
        """
        Returns True if the auth_req_id within this response is expired at the time of the call.
        :return: True if the auth_req_id is expired, False if it is still valid, None if there is no expires_in hint.
        """
        if self.expires_at:
            return datetime.now() > self.expires_at
        return None

    def __getattr__(self, key: str) -> Any:
        """
        Returns items from this Token Response.
        Allows `token_response.expires_in` or `token_response.any_custom_attribute`
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
    """A pooling job for checking if the user has finished with his authorization in a Device Authorization flow."""

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
