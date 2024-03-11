"""Various utilities used in multiple places.

This module contains helper methods that are used in multiple places.

"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Callable

from furl import furl  # type: ignore[import-untyped]


def validate_endpoint_uri(
    uri: str,
    *,
    https: bool = True,
    no_credentials: bool = True,
    no_port: bool = True,
    no_fragment: bool = True,
    path: bool = True,
) -> str:
    """Validate that a URI is suitable as an endpoint URI.

    It checks:

    - that the scheme is `https`
    - that no custom port number is being used
    - that no username or password are included
    - that no fragment is included
    - that a path is present

    Those checks can be individually disabled using the parameters

    - `https`
    - `no_fragment`
    - `path`

    Args:
        uri: the uri
        https: if `True`, check that the uri is https
        no_port: if `True`, check that no custom port number is included
        no_credentials: if ` True`, check that no username/password are included
        no_fragment: if `True`, check that the uri contains no fragment
        path: if `True`, check that the uri contains a path component

    Raises:
        ValueError: if the supplied url is not suitable

    Returns:
        the endpoint URI, if all checks passed

    """
    url = furl(uri)
    msg: list[str] = []
    if https and url.scheme != "https":
        msg.append("url must use https")
    if no_port and url.port != 443:  # noqa: PLR2004
        msg.append("no custom port number allowed")
    if no_credentials and url.username or url.password:
        msg.append("no username or password are allowed")
    if no_fragment and url.fragment:
        msg.append("url must not contain a fragment")
    if path and (not url.path or url.path == "/"):
        msg.append("url must include a path")

    if msg:
        raise ValueError(", ".join(msg))

    return uri


def validate_issuer_uri(uri: str) -> str:
    """Validate that an Issuer Identifier URI is valid.

    This is almost the same as a valid endpoint URI, but a path is not mandatory.

    """
    return validate_endpoint_uri(uri, path=False)


def accepts_expires_in(f: Callable[..., Any]) -> Callable[..., Any]:
    """Decorate methods to handle both `expires_at` and `expires_in`.

    This decorates methods that accept an `expires_at` datetime parameter, to also allow an
    `expires_in` parameter in seconds.

    If supplied, `expires_in` will be converted to a datetime `expires_in` seconds in the future,
    and passed as `expires_at` in the decorated method.

    Args:
        f: the method to decorate, with an `expires_at` parameter

    Returns:
        a decorated method that accepts either `expires_in` or `expires_at`.

    """

    @wraps(f)
    def decorator(
        *args: Any,
        expires_in: int | str | None = None,
        expires_at: datetime | None = None,
        **kwargs: Any,
    ) -> Any:
        if expires_in is None and expires_at is None:
            return f(*args, **kwargs)
        if expires_in and isinstance(expires_in, str) and expires_in.isdigit() and int(expires_in) >= 1:
            expires_at = datetime.now(tz=timezone.utc) + timedelta(seconds=int(expires_in))
        elif expires_in and isinstance(expires_in, int) and expires_in >= 1:
            expires_at = datetime.now(tz=timezone.utc) + timedelta(seconds=expires_in)
        return f(*args, expires_at=expires_at, **kwargs)

    return decorator
