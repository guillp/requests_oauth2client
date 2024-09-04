"""`ApiClient` main module."""

from __future__ import annotations

from typing import IO, TYPE_CHECKING, Any, Callable, Iterable, Mapping, MutableMapping
from urllib.parse import quote as urlencode
from urllib.parse import urljoin

import requests
from attrs import field, frozen
from typing_extensions import Literal, Self

if TYPE_CHECKING:
    from types import TracebackType

    from requests.cookies import RequestsCookieJar


class InvalidBoolFieldsParam(ValueError):
    """Raised when an invalid value is passed as 'bool_fields' parameter."""

    def __init__(self, bool_fields: object) -> None:
        super().__init__("""\
Invalid value for 'bool_fields' parameter. It must be an iterable of 2 str values:
- first one for the True value
- second one for the False value
boolean fields in `data` or `params` with a boolean value (`True` or `False`)
will be serialized to the corresponding value.
Default is `('true', 'false')`
Use this parameter when the target API expects some other values, e.g.:
- ('on', 'off')
- ('1', '0')
- ('yes', 'no')
""")
        self.value = bool_fields


def validate_bool_fields(bool_fields: tuple[str, str]) -> tuple[str, str]:
    """Validate the `bool_fields` paremeter.

    It must be a sequence of 2 values. First one is the `True` value, second one is the `False` value.
    Both must be `str` or string-able values.

    """
    try:
        true_value, false_value = bool_fields
    except ValueError:
        raise InvalidBoolFieldsParam(bool_fields) from None
    else:
        return str(true_value), str(false_value)


class InvalidPathParam(TypeError, ValueError):
    """Raised when an unexpected path is passed as 'url' parameter."""

    def __init__(self, path: None | str | bytes | Iterable[str | bytes | int]) -> None:
        super().__init__("""\
Unexpected path. Please provide a path that is relative to the configured `base_url`:
- `None` (default) to call the base_url
- a `str` or `bytes`, that will be joined to the base_url (with a / separator, if required)
- or an iterable of string-able objects, which will be joined to the base_url with / separators
""")
        self.url = path


@frozen(init=False)
class ApiClient:
    """A Wrapper around [requests.Session][] with extra features for REST API calls.

    Additional features compared to using a [requests.Session][] directly:

    - You must set a root url at creation time, which then allows passing relative urls at request time.
    - It may also raise exceptions instead of returning error responses.
    - You can also pass additional kwargs at init time, which will be used to configure the
    [Session][requests.Session], instead of setting them later.
    - for parameters passed as `json`, `params` or `data`, values that are `None` can be
    automatically discarded from the request
    - boolean values in `data` or `params` fields can be serialized to values that are suitable
    for the target API, like `"true"`  or `"false"`, or `"1"` / `"0"`, instead of the default
    values `"True"` or `"False"`.

    `base_url` will serve as root for relative urls passed to
    [ApiClient.request()][requests_oauth2client.api_client.ApiClient.request],
    [ApiClient.get()][requests_oauth2client.api_client.ApiClient.get], etc.

    A [requests.HTTPError][] will be raised everytime an API call returns an error code (>= 400), unless
    you set `raise_for_status` to `False`. Additional parameters passed at init time, including
    `auth` will be used to configure the [Session][requests.Session].

    Example:
        ```python
        from requests_oauth2client import ApiClient

        api = ApiClient("https://myapi.local/resource", timeout=10)
        resp = api.get("/myid")  # this will send a GET request
        # to https://myapi.local/resource/myid

        # you can pass an underlying requests.Session at init time
        session = requests.Session()
        session.proxies = {"https": "https://localhost:3128"}
        api = ApiClient("https://myapi.local/resource", session=session)

        # or you can let ApiClient init its own session and provide additional configuration
        # parameters:
        api = ApiClient(
            "https://myapi.local/resource",
            proxies={"https": "https://localhost:3128"},
        )
        ```

    Args:
        base_url: the base api url, that is the root for all the target API endpoints.
        auth: the [requests.auth.AuthBase][] to use as authentication handler.
        timeout: the default timeout, in seconds, to use for each request from this `ApiClient`.
            Can be set to `None` to disable timeout.
        raise_for_status: if `True`, exceptions will be raised everytime a request returns an
            error code (>= 400).
        none_fields: defines what to do with parameters with value `None` in `data` or `json` fields.

            - if `"exclude"` (default), fields whose values are `None` are not included in the request.
            - if `"include"`, they are included with string value `None`. This is
            the default behavior of `requests`. Note that they will be serialized to `null` in JSON.
            - if `"empty"`, they are included with an empty value (as an empty string).
        bool_fields: a tuple of `(true_value, false_value)`. Fields from `data` or `params` with
            a boolean value (`True` or `False`) will be serialized to the corresponding value.
            This can be useful since some APIs expect a `'true'` or `'false'` value as boolean,
            and `requests` serializes `True` to `'True'` and `False` to `'False'`.
            Set it to `None` to restore default requests behaviour.
        session: a preconfigured `requests.Session` to use with this `ApiClient`.
        **session_kwargs: additional kwargs to configure the underlying `requests.Session`.

    Raises:
        InvalidBoolFieldsParam: if the provided `bool_fields` parameter is invalid.

    """

    base_url: str
    auth: requests.auth.AuthBase | None = None
    timeout: int | None = 60
    raise_for_status: bool = True
    none_fields: Literal["include", "exclude", "empty"] = "exclude"
    bool_fields: tuple[Any, Any] | None = "true", "false"
    session: requests.Session = field(factory=requests.Session)

    def __init__(
        self,
        base_url: str,
        *,
        auth: requests.auth.AuthBase | None = None,
        timeout: int | None = 60,
        raise_for_status: bool = True,
        none_fields: Literal["include", "exclude", "empty"] = "exclude",
        bool_fields: tuple[Any, Any] | None = ("true", "false"),
        session: requests.Session | None = None,
        **session_kwargs: Any,
    ) -> None:
        session = session or requests.Session()
        for key, val in session_kwargs.items():
            setattr(session, key, val)

        if bool_fields is None:
            bool_fields = ("True", "False")
        else:
            validate_bool_fields(bool_fields)

        self.__attrs_init__(
            base_url=base_url,
            auth=auth,
            raise_for_status=raise_for_status,
            none_fields=none_fields,
            bool_fields=bool_fields,
            timeout=timeout,
            session=session,
        )

    def request(  # noqa: C901, PLR0913, D417
        self,
        method: str,
        path: None | str | bytes | Iterable[str | bytes | int] = None,
        *,
        params: None | bytes | MutableMapping[str, str] = None,
        data: (
            Iterable[bytes]
            | str
            | bytes
            | list[tuple[Any, Any]]
            | tuple[tuple[Any, Any], ...]
            | Mapping[Any, Any]
            | None
        ) = None,
        headers: MutableMapping[str, str] | None = None,
        cookies: None | RequestsCookieJar | MutableMapping[str, str] = None,
        files: MutableMapping[str, IO[Any]] | None = None,
        auth: (
            None
            | tuple[str, str]
            | requests.auth.AuthBase
            | Callable[[requests.PreparedRequest], requests.PreparedRequest]
        ) = None,
        timeout: None | float | tuple[float, float] | tuple[float, None] = None,
        allow_redirects: bool = False,
        proxies: MutableMapping[str, str] | None = None,
        hooks: None
        | (
            MutableMapping[
                str,
                (Iterable[Callable[[requests.Response], Any]] | Callable[[requests.Response], Any]),
            ]
        ) = None,
        stream: bool | None = None,
        verify: str | bool | None = None,
        cert: str | tuple[str, str] | None = None,
        json: Mapping[str, Any] | None = None,
        raise_for_status: bool | None = None,
        none_fields: Literal["include", "exclude", "empty"] | None = None,
        bool_fields: tuple[Any, Any] | None = None,
    ) -> requests.Response:
        """A wrapper around [requests.Session.request][] method with extra features.

        Additional features are described in
        [ApiClient][requests_oauth2client.api_client.ApiClient] documentation.

        All parameters will be passed as-is to [requests.Session.request][], expected those
        described below which have a special behavior.

        Args:
          path: the url where the request will be sent to. Can be:

            - a path, as `str`: that path will be joined to the configured API url,
            - an iterable of path segments: that will be joined to the root url.
          raise_for_status: like the parameter of the same name from
            [ApiClient][requests_oauth2client.api_client.ApiClient],
            but this will be applied for this request only.
          none_fields: like the parameter of the same name from
            [ApiClient][requests_oauth2client.api_client.ApiClient],
            but this will be applied for this request only.
          bool_fields: like the parameter of the same name from
            [ApiClient][requests_oauth2client.api_client.ApiClient],
            but this will be applied for this request only.

        Returns:
          a Response as returned by requests

        Raises:
            InvalidBoolFieldsParam: if the provided `bool_fields` parameter is invalid.

        """
        path = self.to_absolute_url(path)

        if none_fields is None:
            none_fields = self.none_fields

        if none_fields == "exclude":
            if isinstance(data, Mapping):
                data = {key: val for key, val in data.items() if val is not None}
            if isinstance(json, Mapping):
                json = {key: val for key, val in json.items() if val is not None}
        elif none_fields == "empty":
            if isinstance(data, Mapping):
                data = {key: val if val is not None else "" for key, val in data.items()}
            if isinstance(json, Mapping):
                json = {key: val if val is not None else "" for key, val in json.items()}

        if bool_fields is None:
            bool_fields = self.bool_fields

        if bool_fields:
            true_value, false_value = validate_bool_fields(bool_fields)
            if isinstance(data, MutableMapping):
                for key, val in data.items():
                    if val is True:
                        data[key] = true_value
                    elif val is False:
                        data[key] = false_value
            if isinstance(params, MutableMapping):
                for key, val in params.items():
                    if val is True:
                        params[key] = true_value
                    elif val is False:
                        params[key] = false_value

        timeout = timeout or self.timeout

        response = self.session.request(
            method,
            path,
            params=params,
            data=data,
            headers=headers,
            cookies=cookies,
            files=files,
            auth=auth or self.auth,
            timeout=timeout,
            allow_redirects=allow_redirects,
            proxies=proxies,
            hooks=hooks,
            stream=stream,
            verify=verify,
            cert=cert,
            json=json,
        )

        if raise_for_status is None:
            raise_for_status = self.raise_for_status
        if raise_for_status:
            response.raise_for_status()
        return response

    def to_absolute_url(self, path: None | str | bytes | Iterable[str | bytes | int] = None) -> str:
        """Convert a relative url to an absolute url.

        Given a `path`, return the matching absolute url, based on the `base_url` that is
        configured for this API.

        The result of this method is different from a standard `urljoin()`, because a relative_url
        that starts with a "/" will not override the path from the base url. You can also pass an
        iterable of path parts as relative url, which will be properly joined with "/". Those parts
        may be `str` (which will be urlencoded) or `bytes` (which will be decoded as UTF-8 first) or
        any other type (which will be converted to `str` first, using the `str() function`). See the
        table below for example results which would exhibit most cases:

        | base_url | relative_url | result_url |
        |---------------------------|-----------------------------|-------------------------------------------|
        | `"https://myhost.com/root"` | `"/path"` | `"https://myhost.com/root/path"` |
        | `"https://myhost.com/root"` | `"/path"` | `"https://myhost.com/root/path"` |
        | `"https://myhost.com/root"` | `b"/path"` | `"https://myhost.com/root/path"` |
        | `"https://myhost.com/root"` | `"path"` | `"https://myhost.com/root/path"` |
        | `"https://myhost.com/root"` | `None` | `"https://myhost.com/root"` |
        | `"https://myhost.com/root"` |  `("user", 1, "resource")` | `"https://myhost.com/root/user/1/resource"` |
        | `"https://myhost.com/root"` | `"https://otherhost.org/foo"` | `ValueError` |

        Args:
          path: a relative url

        Returns:
          the resulting absolute url

        Raises:
            InvalidPathParam: if the provided path does not allow constructing a valid url

        """
        url = path

        if url is None:
            url = self.base_url
        else:
            if not isinstance(url, (str, bytes)):
                try:
                    url = "/".join(
                        [urlencode(part.decode() if isinstance(part, bytes) else str(part)) for part in url if part],
                    )
                except Exception as exc:
                    raise InvalidPathParam(url) from exc

            if isinstance(url, bytes):
                url = url.decode()

            if "://" in url:
                raise InvalidPathParam(url)

            url = urljoin(self.base_url + "/", url.lstrip("/"))

        if url is None or not isinstance(url, str):
            raise InvalidPathParam(url)  # pragma: no cover

        return url

    def get(
        self,
        path: None | str | bytes | Iterable[str | bytes | int] = None,
        raise_for_status: bool | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Send a GET request and return a [Response][requests.Response] object.

        The passed `url` is relative to the `base_url` passed at initialization time.
        It takes the same parameters as [ApiClient.request()][requests_oauth2client.api_client.ApiClient.request].

        Args:
            path: the path where the request will be sent.
            raise_for_status: overrides the `raises_for_status` parameter passed at initialization time.
            **kwargs: additional kwargs for `requests.request()`

        Returns:
            a response object.

        Raises:
            requests.HTTPError: if `raises_for_status` is `True` and an error response is returned.

        """
        return self.request("GET", path, raise_for_status=raise_for_status, **kwargs)

    def post(
        self,
        path: str | bytes | Iterable[str | bytes] | None = None,
        raise_for_status: bool | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Send a POST request and return a [Response][requests.Response] object.

        The passed `url` is relative to the `base_url` passed at initialization time.
        It takes the same parameters as [ApiClient.request()][requests_oauth2client.api_client.ApiClient.request].

        Args:
          path: the path where the request will be sent.
          raise_for_status: overrides the `raises_for_status` parameter passed at initialization time.
          **kwargs: additional kwargs for `requests.request()`

        Returns:
          a response object.

        Raises:
          requests.HTTPError: if `raises_for_status` is `True` and an error response is returned.

        """
        return self.request("POST", path, raise_for_status=raise_for_status, **kwargs)

    def patch(
        self,
        path: str | bytes | Iterable[str | bytes] | None = None,
        raise_for_status: bool | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Send a PATCH request. Return a [Response][requests.Response] object.

        The passed `url` is relative to the `base_url` passed at initialization time.
        It takes the same parameters as [ApiClient.request()][requests_oauth2client.api_client.ApiClient.request].

        Args:
          path: the path where the request will be sent.
          raise_for_status: overrides the `raises_for_status` parameter passed at initialization time.
          **kwargs: additional kwargs for `requests.request()`

        Returns:
          a [Response][requests.Response] object.

        Raises:
          requests.HTTPError: if `raises_for_status` is `True` and an error response is returned.

        """
        return self.request("PATCH", path, raise_for_status=raise_for_status, **kwargs)

    def put(
        self,
        path: str | bytes | Iterable[str | bytes] | None = None,
        raise_for_status: bool | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Send a PUT request. Return a [Response][requests.Response] object.

        The passed `url` is relative to the `base_url` passed at initialization time.
        It takes the same parameters as [ApiClient.request()][requests_oauth2client.api_client.ApiClient.request].

        Args:
          path: the path where the request will be sent.
          raise_for_status: overrides the `raises_for_status` parameter passed at initialization time.
          **kwargs: additional kwargs for `requests.request()`

        Returns:
          a [Response][requests.Response] object.

        Raises:
          requests.HTTPError: if `raises_for_status` is `True` and an error response is returned.

        """
        return self.request("PUT", path, raise_for_status=raise_for_status, **kwargs)

    def delete(
        self,
        path: str | bytes | Iterable[str | bytes] | None = None,
        raise_for_status: bool | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Send a DELETE request. Return a [Response][requests.Response] object.

        The passed `url` may be relative to the url passed at initialization time. It takes the same
        parameters as [ApiClient.request()][requests_oauth2client.api_client.ApiClient.request].

        Args:
          path: the path where the request will be sent.
          raise_for_status: overrides the `raises_for_status` parameter passed at initialization time.
          **kwargs: additional kwargs for `requests.request()`.

        Returns:
          a response object.

        Raises:
          requests.HTTPError: if `raises_for_status` is `True` and an error response is returned.

        """
        return self.request("DELETE", path, raise_for_status=raise_for_status, **kwargs)

    def __getattr__(self, item: str) -> ApiClient:
        """Allow access sub resources with an attribute-based syntax.

        Args:
            item: a subpath

        Returns:
            a new `ApiClient` initialized on the new base url

        Example:
            ```python
            from requests_oauth2client import ApiClient

            api = ApiClient("https://myapi.local")
            resource1 = api.resource1.get()  # GET https://myapi.local/resource1
            resource2 = api.resource2.get()  # GET https://myapi.local/resource2
            ```

        """
        return self[item]

    def __getitem__(self, item: str) -> ApiClient:
        """Allow access to sub resources with a subscription-based syntax.

        Args:
            item: a subpath

        Returns:
            a new `ApiClient` initialized on the new base url

        Example:
            ```python
            from requests_oauth2client import ApiClient

            api = ApiClient("https://myapi.local")
            resource1 = api["resource1"].get()  # GET https://myapi.local/resource1
            resource2 = api["resource2"].get()  # GET https://myapi.local/resource2
            ```

        """
        new_base_uri = self.to_absolute_url(item)
        return ApiClient(
            new_base_uri,
            session=self.session,
            none_fields=self.none_fields,
            bool_fields=self.bool_fields,
            timeout=self.timeout,
            raise_for_status=self.raise_for_status,
        )

    def __enter__(self) -> Self:
        """Allow `ApiClient` to act as a context manager.

        You can then use an `ApiClient` instance in a `with` clause, the same way as
        `requests.Session`. The underlying request.Session will be closed on exit.

        Example:
            ```python
            with ApiClient("https://myapi.com/path") as client:
                resp = client.get("resource")
            ```

        """
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Close the underlying requests.Session on exit."""
        self.session.close()
