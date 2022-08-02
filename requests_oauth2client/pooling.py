"""Contains base classes for pooling jobs."""

import time
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Dict, Optional

from .exceptions import AuthorizationPending, SlowDown
from .tokens import BearerToken

if TYPE_CHECKING:  # pragma: no cover
    from .client import OAuth2Client


class TokenEndpointPoolingJob(ABC):
    """Base class for Token Endpoint pooling jobs.

    This is used for decoupled flows like CIBA or Device Authorization.

    This class must be subclassed to implement actual BackChannel flows.
    This needs an [OAuth2Client][requests_oauth2client.client.OAuth2Client] that will be used to pool the token
    endpoint. The initial pooling `interval` is configurable.

    Args:
        client: the [OAuth2Client][requests_oauth2client.client.OAuth2Client] that will be used to pool the token endpoint.
        interval: initial pooling interval, in seconds. If `None`, default to `5`.
        slow_down_interval: when a [SlowDown][requests_oauth2client.exceptions.SlowDown] is received, this number of seconds will be added to the pooling interval.
        requests_kwargs: additional parameters for the underlying calls to [requests.request][]
        **token_kwargs: additional parameters for the token request
    """

    def __init__(
        self,
        client: "OAuth2Client",
        interval: Optional[int] = None,
        slow_down_interval: int = 5,
        requests_kwargs: Optional[Dict[str, Any]] = None,
        **token_kwargs: Any,
    ):
        self.client = client
        self.interval = interval or 5
        self.slow_down_interval = slow_down_interval
        self.requests_kwargs = requests_kwargs
        self.token_kwargs = token_kwargs

    def __call__(self) -> Optional[BearerToken]:
        """Wrap the actual Token Endpoint call with a pooling interval.

        Everytime this method is called, it will wait for the entire duration of the pooling interval before calling
        [token_request()][requests_oauth2client.pooling.TokenEndpointPoolingJob.token_request]. So you can call it
        immediately after initiating the BackChannel flow, and it will wait before initiating the first call.

        This implements the logic to handle [AuthorizationPending][requests_oauth2client.exceptions.AuthorizationPending]
        or [SlowDown][requests_oauth2client.exceptions.SlowDown] requests by the AS.

        Returns:
            a [BearerToken][requests_oauth2client.tokens.BearerToken] if the AS returns one, or `None` if the Authorization is still pending.
        """
        time.sleep(self.interval)
        try:
            return self.token_request()
        except SlowDown:
            self.interval += self.slow_down_interval
        except AuthorizationPending:
            pass
        return None

    @abstractmethod
    def token_request(self) -> BearerToken:
        """Abstract method for the token endpoint call.

        This must be implemented by subclasses. This method must
        Must raise [AuthorizationPending][requests_oauth2client.exceptions.AuthorizationPending] to retry after the pooling interval,
        or [SlowDown][requests_oauth2client.exceptions.SlowDown] to increase the pooling interval by `slow_down_interval` seconds.

        Returns:
            a [BearerToken][requests_oauth2client.tokens.BearerToken]
        """
        raise NotImplementedError  # pragma: no cover
