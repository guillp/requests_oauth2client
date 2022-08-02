"""ApiClient main module."""

from __future__ import annotations

from typing import (
    IO,
    Any,
    Callable,
    Iterable,
    Mapping,
    MutableMapping,
    Optional,
    Tuple,
    Union,
)
from urllib.parse import quote as urlencode
from urllib.parse import urljoin

import requests
from requests.cookies import RequestsCookieJar
from typing_extensions import Literal


class ApiClient:
    """A Wrapper around [requests.Session][] with extra features for Rest API calls.

    Additional features compared to [requests.Session][]:

    - Allows setting a root url at creation time, then passing relative urls at request time.
    - It may also raise exceptions instead of returning error responses.
    - You can also pass additional kwargs at init time, which will be used to configure the [Session][requests.Session],
    instead of setting them later.
    - for parameters passed as `json`, `params` or `data`, values that are `None` can be automatically discarded from the request
    - boolean values in `data` or `params` fields can be serialized to values that are suitable for the target API, like `"true"` or `"false"`, or `"1"` / `"0"`, instead of the default values `"True"` or `"False"`.

    `base_url` will serve as root for relative urls passed to [ApiClient.request()][requests_oauth2client.api_client.ApiClient.request], [ApiClient.get()][requests_oauth2client.api_client.ApiClient.get], etc.
    An `HTTPError` will be raised everytime an API call returns an error code (>= 400), unless you set `raise_for_status` to `False`.
    Additional parameters passed at init time, including `auth` will be used to configure the [Session][requests.Session].

    Usage:
        ```python
        from requests_oauth2client import ApiClient

        api = ApiClient("https://myapi.local/resource", timeout=10)
        resp = api.get("/myid")  # this will send a GET request
        # to https://myapi.local/resource/myid

        # you can pass an underlying requests.Session at init time
        session = requests.Session()
        session.proxies = {"https": "https://localhost:3128"}
        api = ApiClient("https://myapi.local/resource", session=session)

        # or you can let ApiClient init it's own session and provide additional configuration parameters:
        api = ApiClient(
            "https://myapi.local/resource", proxies={"https": "https://localhost:3128"}
        )
        ```

    Args:
        base_url: the base api url, that should be root for all the target API endpoints.
        auth: the [requests.auth.AuthBase][] to use as authentication handler.
        timeout: the default timeout, in seconds, to use for each request from this ApiClient. Can be set to `None` to disable timeout.
        raise_for_status: if `True`, exceptions will be raised everytime a request returns an error code (>= 400).
        none_fields: if `"exclude"` (default), `data` or `json` fields whose values are `None` are not included in the request. If `"include"`, they are included with string value `None` (this is the default behavior of `requests`). If "empty", they are included with an empty value (as an empty string).
        bool_fields: a tuple of (true_value, false_value). Fields from `data` or `params` with a boolean value (`True` or `False`) will be serialized to the corresponding value. This can be useful since some APIs expect a `'true'` or `'false'` value as boolean, and requests serialises `True` to `'True'` and `False` to `'False'`. Set it to `None` to restore default requests behaviour.
        **kwargs: additional kwargs to configure this session. This parameter may be overridden at request time.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        auth: Optional[requests.auth.AuthBase] = None,
        timeout: Optional[int] = 60,
        raise_for_status: bool = True,
        none_fields: Literal["include", "exclude", "empty"] = "exclude",
        bool_fields: Optional[Tuple[Any, Any]] = ("true", "false"),
        session: Optional[requests.Session] = None,
        **kwargs: Any,
    ):
        super(ApiClient, self).__init__()

        self.base_url = base_url
        self.raise_for_status = raise_for_status
        self.none_fields = none_fields
        self.bool_fields = bool_fields if bool_fields is not None else (True, False)
        self.timeout = timeout

        self.session = session or requests.Session()
        self.session.auth = auth

        for key, val in kwargs.items():
            setattr(self.session, key, val)

    def request(  # noqa: C901
        self,
        method: str,
        url: Union[None, str, bytes, Iterable[Union[str, bytes, int]]] = None,
        params: Union[None, bytes, MutableMapping[str, str]] = None,
        data: Union[
            None,
            str,
            bytes,
            Mapping[str, Any],
            Iterable[Tuple[str, Optional[str]]],
            IO[Any],
        ] = None,
        headers: Optional[MutableMapping[str, str]] = None,
        cookies: Union[None, RequestsCookieJar, MutableMapping[str, str]] = None,
        files: Optional[MutableMapping[str, IO[Any]]] = None,
        auth: Union[
            None,
            Tuple[str, str],
            requests.auth.AuthBase,
            Callable[[requests.PreparedRequest], requests.PreparedRequest],
        ] = None,
        timeout: Union[None, float, Tuple[float, float], Tuple[float, None]] = None,
        allow_redirects: bool = False,
        proxies: Optional[MutableMapping[str, str]] = None,
        hooks: Optional[
            MutableMapping[
                str,
                Union[
                    Iterable[Callable[[requests.Response], Any]],
                    Callable[[requests.Response], Any],
                ],
            ]
        ] = None,
        stream: Optional[bool] = None,
        verify: Optional[Union[str, bool]] = None,
        cert: Optional[Union[str, Tuple[str, str]]] = None,
        json: Optional[Mapping[str, Any]] = None,
        raise_for_status: Optional[bool] = None,
        none_fields: Optional[Literal["include", "exclude", "empty"]] = None,
        bool_fields: Optional[Tuple[Any, Any]] = None,
    ) -> requests.Response:
        """Overridden `request` method with extra features.

        Features added compared to plain request():
        - it can handle a relative path instead of a full url, which will be appended to the base_url
        - it can raise an exception when the API returns a non-success status code
        - allow_redirects is False by default (API usually don't use redirects)
        - `data` or `json` fields with value `None` can either be included or excluded from the request
        - boolean fields can be serialized to `'true'` or `'false'` instead of `'True'` and `'False'`

        Args:
          method: the HTTP method to use
          url: the url where the request will be sent to. Can be a path instead of a full url; that path will be
        joined to the configured API url. Can also be an iterable of path segments, that will be joined to the root url.
          raise_for_status: like the parameter of the same name from `ApiClient.__init__`, but this will be applied for this request only.
          none_fields: like the parameter of the same name from `ApiClient.__init__`, but this will be applied for this request only.
          bool_fields: like the parameter of the same name from `ApiClient.__init__`, but this will be applied for this request only.

        Returns:
          a [requests.Response][] as returned by requests
        """
        url = self.to_absolute_url(url)

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
            try:
                true_value, false_value = bool_fields
            except ValueError:
                raise ValueError(
                    "Invalid value for 'bool_fields'. Must be a 2 value tuple, with (true_value, false_value)."
                )
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
            url,
            params=params,
            data=data,
            headers=headers,
            cookies=cookies,
            files=files,
            auth=auth,
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

    def to_absolute_url(
        self, relative_url: Union[None, str, bytes, Iterable[Union[str, bytes, int]]] = None
    ) -> str:
        """Convert a relative url to an absolute url.

        Given a `relative_url`, return the matching absolute url, based on the `base_url` that is configured for this API.

        The result of this methods is different from a standard `urljoin()`, because a relative_url that starts with a "/"
        will not override the path from the base url.
        You can also pass an iterable of path parts as relative url, which will be properly joined with "/". Those parts may be
        `str` (which will be urlencoded) or `bytes` (which will be decoded as UTF-8 first) or any other type (which will be converted to `str` first, using the `str() function`).
        See the table below for examples results which would exhibit most cases:

        | base_url                  | relative_url                | result_url                                |
        |---------------------------|-----------------------------|-------------------------------------------|
        | "https://myhost.com/root" | "/path"                     | "https://myhost.com/root/path"            |
        | "https://myhost.com/root" | "/path"                     | "https://myhost.com/root/path"            |
        | "https://myhost.com/root" | b"/path"                    | "https://myhost.com/root/path"            |
        | "https://myhost.com/root" | "path"                      | "https://myhost.com/root/path"            |
        | "https://myhost.com/root" | None                        | "https://myhost.com/root"                 |
        | "https://myhost.com/root" | ("user", 1, "resource")     | "https://myhost.com/root/user/1/resource" |
        | "https://myhost.com/root" | "https://otherhost.org/foo" | "https://otherhost.org/foo"               |

        Args:
          relative_url: a relative url

        Returns:
          the resulting absolute url
        """
        url = relative_url

        if self.base_url:
            if url is not None:
                if not isinstance(url, (str, bytes)):
                    try:
                        url = "/".join(
                            [
                                urlencode(
                                    part.decode() if isinstance(part, bytes) else str(part)
                                )
                                for part in url
                                if part
                            ]
                        )
                    except TypeError:
                        raise TypeError(
                            "Unexpected url type, please pass a relative path as string or bytes, "
                            "or an iterable of string-able objects",
                            type(url),
                        )

                if isinstance(url, bytes):
                    url = url.decode()

                url = urljoin(self.base_url + "/", url.lstrip("/"))
            else:
                url = self.base_url

        if url is None or not isinstance(url, str):
            raise ValueError("Unable to determine an absolute url.")

        return url

    def get(
        self,
        url: Union[None, str, bytes, Iterable[Union[str, bytes, int]]] = None,
        raise_for_status: Optional[bool] = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Send a GET request. Return a [Response][requests.Response] object.

        The passed `url` may be relative to the url passed at initialization time.
        It takes the same parameters as [ApiClient.request()][requests_oauth2client.api_client.ApiClient.request].

        Args:
            url: a url where the request will be sent.
            raise_for_status: overrides the `raises_for_status` parameter passed at initialization time.
            **kwargs: Optional arguments that [request()][requests.request] takes.

        Returns:
            a [Response][requests.Response] object.

        Raises:
            requests.HTTPError: if `raises_for_status` is True (in this request or at initialization time) and an error response is returned.
                and an error response is returned.
        """
        return self.request("GET", url, raise_for_status=raise_for_status, **kwargs)

    def post(
        self,
        url: Optional[Union[str, bytes, Iterable[Union[str, bytes]]]] = None,
        raise_for_status: Optional[bool] = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Send a POST request. Return a [Response][requests.Response] object.

        The passed `url` may be relative to the url passed at initialization time.
        It takes the same parameters as [ApiClient.request()][requests_oauth2client.api_client.ApiClient.request].

        Args:
          url: a url where the request will be sent.
          raise_for_status: overrides the `raises_for_status` parameter passed at initialization time.
          **kwargs: Optional arguments that ``request`` takes.

        Returns:
          a [Response][requests.Response] object.

        Raises:
          requests.HTTPError: if `raises_for_status` is True (in this request or at initialization time) and an error response is returned.
        """
        return self.request("POST", url, raise_for_status=raise_for_status, **kwargs)

    def patch(
        self,
        url: Optional[Union[str, bytes, Iterable[Union[str, bytes]]]] = None,
        raise_for_status: Optional[bool] = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Send a PATCH request. Return a [Response][requests.Response] object.

        The passed `url` may be relative to the url passed at initialization time.
        It takes the same parameters as [ApiClient.request()][requests_oauth2client.api_client.ApiClient.request].

        Args:
          url: a url where the request will be sent.
          raise_for_status: overrides the `raises_for_status` parameter passed at initialization time.
          **kwargs: Optional arguments that ``request`` takes.

        Returns:
          a [Response][requests.Response] object.

        Raises:
          requests.HTTPError: if `raises_for_status` is True (in this request or at initialization time) and an error response is returned.
        """
        return self.request("PATCH", url, raise_for_status=raise_for_status, **kwargs)

    def put(
        self,
        url: Optional[Union[str, bytes, Iterable[Union[str, bytes]]]] = None,
        raise_for_status: Optional[bool] = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Send a PUT request. Return a [Response][requests.Response] object.

        The passed `url` may be relative to the url passed at initialization time.
        It takes the same parameters as [ApiClient.request()][requests_oauth2client.api_client.ApiClient.request].

        Args:
          url: a url where the request will be sent.
          raise_for_status: overrides the `raises_for_status` parameter passed at initialization time.
          **kwargs: additional kwargs for `requests.request()`

        Returns:
          a [Response][requests.Response] object.

        Raises:
          requests.HTTPError: if `raises_for_status` is True (in this request or at initialization time) and an error response is returned.
        """
        return self.request("PUT", url, raise_for_status=raise_for_status, **kwargs)

    def delete(
        self,
        url: Optional[Union[str, bytes, Iterable[Union[str, bytes]]]] = None,
        raise_for_status: Optional[bool] = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Send a DELETE request. Return a [Response][requests.Response] object.

        The passed `url` may be relative to the url passed at initialization time.
        It takes the same parameters as [ApiClient.request()][requests_oauth2client.api_client.ApiClient.request].

        Args:
          url: a url where the request will be sent.
          raise_for_status: overrides the `raises_for_status` parameter passed at initialization time.
          **kwargs: additional kwargs for `requests.request()`.

        Returns:
          a [Response][requests.Response] object.

        Raises:
          requests.HTTPError: if `raises_for_status` is True (in this request or at initialization time) and an error response is returned.
        """
        return self.request("DELETE", url, raise_for_status=raise_for_status, **kwargs)

    def __getattr__(self, item: str) -> ApiClient:
        """Allow access sub resources with an attribute-based syntax.

        Args:
            item: a subpath

        Returns:
            a new ApiClient initialised on the new base url

        Usage:
            ```python
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
            a new ApiClient initialised on the new base url

        Usage:
            ```python
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

    def __enter__(self) -> ApiClient:
        """Allow `ApiClient` to act as a context manager.

        You can then use an `ApiClient` instance in a `with` clause, the same way as `requests.Session`.
        The underlying request.Session will be closed on exit.

        Usage:
            ```python
            with ApiClient("https://myapi.com/path") as client:
                resp = client.get("resource")
            ```
        """
        return self

    def __exit__(self, *args: Any) -> None:
        """Close the underlying requests.Session on exit."""
        self.session.close()
