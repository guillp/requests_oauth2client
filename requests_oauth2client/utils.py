import base64
import json
from datetime import datetime, timedelta
from functools import wraps
from typing import Any, Callable, Dict, Optional, Union

from furl import furl  # type: ignore


def b64_encode(
    data: Union[bytes, str], encoding: str = "utf-8", padded: bool = True
) -> str:
    """
    Encodes the string or bytes `data` using Base64.
    If `data` is a string, encode it to bytes using `encoding` before converting it to Base64.
    If `padded` is `True` (default), outputs includes a padding with `=` to make its length a multiple of 4. If `False`,
    no padding is included.
    :param data: value to base64-encode.
    :param encoding: if `data` is a `str`, use this encoding to convert it to `bytes` first.
    :param padded: whether to include padding in the output
    :return: a `str` with the base64-encoded data.
    """
    if not isinstance(data, bytes):
        if not isinstance(data, str):
            data = str(data)
        data = data.encode(encoding)

    encoded = base64.b64encode(data)
    if not padded:
        encoded = encoded.rstrip(b"=")
    return encoded.decode("ascii")


def b64_decode(data: Union[str, bytes]) -> bytes:
    """
    Decodes a base64-encoded string or bytes.
    :param data: the data to base64-decode
    :return: the decoded data, as bytes
    """
    if not isinstance(data, bytes):
        if not isinstance(data, str):
            data = str(data)
        data = data.encode("ascii")

    padding_len = len(data) % 4
    if padding_len:
        data = data + b"=" * padding_len

    decoded = base64.urlsafe_b64decode(data)
    return decoded


def b64u_encode(
    data: Union[bytes, str], encoding: str = "utf-8", padded: bool = False
) -> str:
    """
    Encodes some data using Base64url.
    If `data` is a string, encode it to bytes using `encoding` before converting it to Base64.
    If `padded` is `False` (default), no padding is added. If `True`, outputs includes a padding with `=` to make
    its length a multiple of 4.
    :param data: the data to encode.
    :param encoding: if `data` is a string, the encoding to use to convert it to `bytes`
    :param padded: if `True`, pad the output with `=` to make its length a multiple of 4
    :return: the base64url encoded data, as a string
    """
    if not isinstance(data, bytes):
        if not isinstance(data, str):
            data = str(data)
        data = data.encode(encoding)

    encoded = base64.urlsafe_b64encode(data)
    if not padded:
        encoded = encoded.rstrip(b"=")
    return encoded.decode("ascii")


def b64u_decode(
    data: Union[str, bytes],
) -> bytes:
    """
    Decodes a base64url-encoded data.
    :param data: the data to decode.
    :return: the decoded data as bytes.
    """
    if not isinstance(data, bytes):
        if not isinstance(data, str):
            data = str(data)
        data = data.encode("ascii")

    padding_len = len(data) % 4
    if padding_len:
        data = data + b"=" * padding_len

    decoded = base64.urlsafe_b64decode(data)
    return decoded


def _default_json_encode(data: Any) -> Any:
    if isinstance(data, datetime):
        return int(data.timestamp())
    return str(data)


def json_encode(
    obj: Dict[str, Any],
    compact: bool = True,
    default_encoder: Callable[[Any], Any] = _default_json_encode,
) -> str:
    """
    Encodes an object to JSON. By default, this produces a compact output (no extra whitespaces), and datetimes are
    converted to epoch-style integers. Any unhandled value is stringified using `str()`. You can override this with the
    parameters `compact` and `default_encoder`.
    :param obj: the data to JSON-encode.
    :param compact: if `True` (default), produces a compact output.
    :param default_encoder: the default encoder to use for types that the default `json` module doesn't handle.
    :return: the JSON-encoded data.
    """
    separators = (",", ":") if compact else (", ", ": ")

    return json.dumps(obj, separators=separators, default=default_encoder)


def validate_endpoint_uri(
    value: str, https: bool = True, no_fragment: bool = True, path: bool = True
) -> None:
    """
    Validates that an URI is suitable as an endpoint URI.
    It checks:

    - that the scheme is `https`
    - that no fragment is included
    - that a path is present

    Those check can be individually disabled using the parameters `https`, `no_fragment` and `path`.
    :param value:
    :param https:
    :param no_fragment:
    :param path:
    :return:
    """
    url = furl(value)
    if https and url.scheme != "https":
        raise ValueError("url must use https")
    if no_fragment and url.fragment:
        raise ValueError("url must not contain a fragment")
    if path and (not url.path or url.path == "/"):
        raise ValueError("url has no path")


def accepts_expires_in(f: Callable[..., Any]) -> Callable[..., Any]:
    """
    A decorator that allows any method that takes an `expires_at` datetime parameter
    to also accept an `expires_in` integer parameter. This will be converted
    to a datetime with `expires_in` seconds in the future.
    :param f: the method to decorate, with an `expires_at` parameter
    :return: a decorated method that accepts either `expires_in` or `expires_at`.
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
