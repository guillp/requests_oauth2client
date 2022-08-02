"""Various utilities used in multiple places.

This module contains helper methods that are used in multiple places within
`requests_oauth2client`.
"""

from datetime import datetime, timedelta
from functools import wraps
from typing import Any, Callable, Optional

from furl import furl  # type: ignore[import]


def validate_endpoint_uri(
    uri: str, https: bool = True, no_fragment: bool = True, path: bool = True
) -> None:
    """Validate that an URI is suitable as an endpoint URI.

    It checks:

    - that the scheme is `https`
    - that no fragment is included
    - that a path is present

    Those check can be individually disabled using the parameters `https`, `no_fragment` and `path`.

    Args:
        uri: the uri
        https: if `True`, check that the uri is https
        no_fragment: if `True`, check that the uri contains no fragment
        path: if `True`, check that the uri contains a path component

    Raises:
        ValueError: if the supplied url is not suitable
    """
    url = furl(uri)
    if https and url.scheme != "https":
        raise ValueError("url must use https")
    if no_fragment and url.fragment:
        raise ValueError("url must not contain a fragment")
    if path and (not url.path or url.path == "/"):
        raise ValueError("url has no path")


def accepts_expires_in(f: Callable[..., Any]) -> Callable[..., Any]:
    """Decorate methods to handle both `expires_at` and `expires_in`.

    This decorates methods that accept an `expires_at` datetime parameter, to also allow an
    `expires_in` parameter in seconds.

    If supplied, `expires_in` will be converted to a datetime `expires_in` seconds in the future, and passed as `expires_at`
    in the decorated method.

    Args:
        f: the method to decorate, with an `expires_at` parameter

    Returns:
        a decorated method that accepts either `expires_in` or `expires_at`.
    """

    @wraps(f)
    def decorator(
        *args: Any,
        expires_in: Optional[int] = None,
        expires_at: Optional[datetime] = None,
        **kwargs: Any,
    ) -> Any:
        if expires_in is None and expires_at is None:
            return f(*args, **kwargs)
        if expires_in and isinstance(expires_in, int) and expires_in >= 1:
            expires_at = datetime.now() + timedelta(seconds=expires_in)
        return f(*args, expires_at=expires_at, **kwargs)

    return decorator
