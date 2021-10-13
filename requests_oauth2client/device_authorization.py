from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Dict, Optional

from .pooling import TokenEndpointPoolingJob
from .tokens import BearerToken
from .utils import accepts_expires_in

if TYPE_CHECKING:  # pragma: no cover
    from .client import OAuth2Client


class DeviceAuthorizationResponse:
    """
    A response returned by the device Authorization Endpoint (as defined in RFC8628)
    """

    @accepts_expires_in
    def __init__(
        self,
        device_code: str,
        user_code: str,
        verification_uri: str,
        verification_uri_complete: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        interval: Optional[int] = None,
        **kwargs: Any,
    ):
        self.device_code = device_code
        self.user_code = user_code
        self.verification_uri = verification_uri
        self.verification_uri_complete = verification_uri_complete
        self.expires_at = expires_at
        self.interval = interval
        self.other = kwargs

    def is_expired(self, leeway: int = 0) -> Optional[bool]:
        """
        Returns True if the device_code within this response is expired at the time of the call.
        :return: True if the device_code is expired, False if it is still valid, None if there is no expires_in hint.
        """
        if self.expires_at:
            return datetime.now() - timedelta(seconds=leeway) > self.expires_at
        return None


class DeviceAuthorizationPoolingJob(TokenEndpointPoolingJob):
    """
    A pooling job for checking if the user has finished with his authorization in a Device Authorization flow.

    Usage:
    ```python
    client = OAuth2Client(
        token_endpoint="https://my.as.local/token", auth=("client_id", "client_secret")
    )
    pool_job = DeviceAuthorizationPoolingJob(client=client, device_code="my_device_code")

    token = None
    while token is None:
        token = pool_job()
    ```
    """

    def __init__(
        self,
        client: "OAuth2Client",
        device_code: str,
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
        self.device_code = device_code

    def token_request(self) -> BearerToken:
        """
        Implement the Device Code token request.

        This actually calls [OAuth2Client.device_code(device_code)] on `client`.
        :return: a [BearerToken][requests_oauth2client.tokens.BearerToken]
        """
        return self.client.device_code(
            self.device_code, requests_kwargs=self.requests_kwargs, **self.token_kwargs
        )
