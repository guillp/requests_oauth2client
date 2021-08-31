import time
from typing import TYPE_CHECKING, Any, Dict, Optional

from .exceptions import AuthorizationPending, SlowDown
from .tokens import BearerToken

if TYPE_CHECKING:  # pragma: no cover
    from .client import OAuth2Client


class TokenEndpointPoolingJob:
    """Base class for Token Endpoint pooling jobs on decoupled flows like CIBA or Device Authorization."""

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
        time.sleep(self.interval)
        try:
            return self.pool()
        except SlowDown:
            self.interval += 5
        except AuthorizationPending:
            pass
        return None

    def pool(self) -> BearerToken:
        raise NotImplementedError
