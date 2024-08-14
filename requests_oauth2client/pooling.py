"""Contains base classes for pooling jobs."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from attrs import define

from .exceptions import AuthorizationPending, SlowDown

if TYPE_CHECKING:
    from .client import OAuth2Client
    from .tokens import BearerToken


@define
class BaseTokenEndpointPoolingJob:
    """Base class for Token Endpoint pooling jobs.

    This is used for decoupled flows like CIBA or Device Authorization.

    This class must be subclassed to implement actual BackChannel flows. This needs an
    [OAuth2Client][requests_oauth2client.client.OAuth2Client] that will be used to pool the token
    endpoint. The initial pooling `interval` is configurable.

    """

    client: OAuth2Client
    requests_kwargs: dict[str, Any]
    token_kwargs: dict[str, Any]
    interval: int
    slow_down_interval: int

    def __call__(self) -> BearerToken | None:
        """Wrap the actual Token Endpoint call with a pooling interval.

        Everytime this method is called, it will wait for the entire duration of the pooling
        interval before calling
        [token_request()][requests_oauth2client.pooling.TokenEndpointPoolingJob.token_request]. So
        you can call it immediately after initiating the BackChannel flow, and it will wait before
        initiating the first call.

        This implements the logic to handle
        [AuthorizationPending][requests_oauth2client.exceptions.AuthorizationPending] or
        [SlowDown][requests_oauth2client.exceptions.SlowDown] requests by the AS.

        Returns:
            a `BearerToken` if the AS returns one, or `None` if the Authorization is still pending.

        """
        self.sleep()
        try:
            return self.token_request()
        except SlowDown:
            self.slow_down()
        except AuthorizationPending:
            self.authorization_pending()
        return None

    def sleep(self) -> None:
        """Implement the wait between two requests of the token endpoint.

        By default, relies on time.sleep().

        """
        time.sleep(self.interval)

    def slow_down(self) -> None:
        """Implement the behavior when receiving a 'slow_down' response from the AS.

        By default, it increases the pooling interval by the slow down interval.

        """
        self.interval += self.slow_down_interval

    def authorization_pending(self) -> None:
        """Implement the behavior when receiving an 'authorization_pending' response from the AS.

        By default, it does nothing.

        """

    def token_request(self) -> BearerToken:
        """Abstract method for the token endpoint call.

        Subclasses must implement this. This method must raise
        [AuthorizationPending][requests_oauth2client.exceptions.AuthorizationPending] to retry after
        the pooling interval, or [SlowDown][requests_oauth2client.exceptions.SlowDown] to increase
        the pooling interval by `slow_down_interval` seconds.

        Returns:
            a [BearerToken][requests_oauth2client.tokens.BearerToken]

        """
        raise NotImplementedError
