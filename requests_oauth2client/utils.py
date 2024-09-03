"""Various utilities used in multiple places.

This module contains helper methods that are used in multiple places.

"""

from __future__ import annotations

from contextlib import suppress
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Callable, Iterator

from furl import furl  # type: ignore[import-untyped]


class InvalidUri(ValueError):
    """Raised when a URI does not pass validation by `validate_endpoint_uri()`."""

    def __init__(
        self, url: str, *, https: bool, no_credentials: bool, no_port: bool, no_fragment: bool, path: bool
    ) -> None:
        super().__init__("Invalid endpoint uri.")
        self.url = url
        self.https = https
        self.no_credentials = no_credentials
        self.no_port = no_port
        self.no_fragment = no_fragment
        self.path = path

    def errors(self) -> Iterator[str]:
        """Iterate over all error descriptions, as str."""
        if self.https:
            yield "must use https"
        if self.no_credentials:
            yield "must not contain basic credentials"
        if self.no_port:
            yield "no custom port number allowed"
        if self.no_fragment:
            yield "must not contain a uri fragment"
        if self.path:
            yield "must include a path other than /"

    def __str__(self) -> str:
        all_errors = ", ".join(self.errors())
        return f"Invalid URI: {all_errors}"


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

    Those checks can be individually disabled by using the parameters.

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
    if https and url.scheme == "https":
        https = False
    if no_port and url.port == 443:  # noqa: PLR2004
        no_port = False
    if no_credentials and not url.username and not url.password:
        no_credentials = False
    if no_fragment and not url.fragment:
        no_fragment = False
    if path and url.path and url.path != "/":
        path = False

    if https or no_port or no_credentials or no_fragment or path:
        raise InvalidUri(
            uri, https=https, no_port=no_port, no_credentials=no_credentials, no_fragment=no_fragment, path=path
        )

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
        if expires_in and isinstance(expires_in, str):
            with suppress(ValueError):
                expires_at = datetime.now(tz=timezone.utc).replace(microsecond=0) + timedelta(seconds=int(expires_in))
        elif expires_in and isinstance(expires_in, int):
            expires_at = datetime.now(tz=timezone.utc).replace(microsecond=0) + timedelta(seconds=expires_in)
        return f(*args, expires_at=expires_at, **kwargs)

    return decorator
