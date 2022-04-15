"""ApiClient main module."""

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

try:
    from typing import Literal
except ImportError:
    from typing_extensions import Literal  # type: ignore

from urllib.parse import urljoin

import requests
from requests.cookies import RequestsCookieJar


class ApiClient(requests.Session):
    """
    A Wrapper around [requests.Session][] to simplify Rest API calls.

    This allows setting a root url at creation time, then passing relative urls at request time.
    It may also raise exceptions instead of returning error responses.
    You can also pass additional kwargs at init time, which will be used to configure the [Session][requests.Session],
    instead of setting them later.

    Basic usage:

        from requests_oauth2client import ApiClient
        api = ApiClient("https://myapi.local/resource", timeout=10)
        resp = api.get("/myid") # this will send a GET request
                                # to https://myapi.local/resource/myid

    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        auth: Optional[requests.auth.AuthBase] = None,
        timeout: Optional[int] = 60,
        raise_for_status: bool = True,
        none_fields: Literal["include", "exclude", "empty"] = "exclude",
        bool_fields: Optional[Tuple[Any, Any]] = ("true", "false"),
        **kwargs: Any,
    ):
        """
        Initialize an `ApiClient`, with an optional root url.

        `base_url` will serve as root for relative urls passed to [ApiClient.request()][requests_oauth2client.api_client.ApiClient.request], [ApiClient.get()][requests_oauth2client.api_client.ApiClient.get], etc.
        An `HTTPError` will be raised everytime an API call returns an error code (>= 400), unless you set `raise_for_status` to `False`.
        Additional parameters passed at init time, including `auth` will be used to configure the [Session][requests.Session].

        :param base_url: the base api url, that should be root for all the target API endpoints.
        :param auth: the [requests.auth.AuthBase][] to use as authentication handler.
        :param timeout: the default timeout, in seconds, to use for each request from this ApiClient. Can be set to `None` to disable timeout.
        :param raise_for_status: if `True`, exceptions will be raised everytime a request returns an error code (>= 400).
        :param none_fields: if `"exclude"` (default), data or json fields whose values are `None` are not included in the request. If "include", they are included with string value `None` (this is the default behavior of `requests`). If "empty", they are included with an empty value (as an empty string).
        :param bool_fields: a tuple of (true_value, false_value). Fields from `data` or `params` with a boolean value (`True` or `False`) will be serialized to the corresponding value. This can be useful since some APIs expect a `'true'` or `'false'` value as boolean, and requests serialises `True` to `'True'` and `False` to `'False'`. Set it to `None` to restore default requests behaviour.
        :param kwargs: additional kwargs to configure this session. This parameter may be overridden at request time.
        """
        super(ApiClient, self).__init__()

        self.base_url = base_url
        self.auth = auth
        self.timeout = timeout
        self.raise_for_status = raise_for_status
        self.none_fields = none_fields
        self.bool_fields = bool_fields if bool_fields is not None else (True, False)

        for key, val in kwargs.items():
            setattr(self, key, val)

    def request(  # type: ignore  # noqa: C901
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
        allow_redirects: Optional[bool] = True,
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
        """
        Overridden `request` method that can handle a relative path instead of a full url.

        :param method: the HTTP method to use
        :param url: the url where the request will be sent to. Can be a path instead of a full url; that path will be
        joined to the configured API url. Can also be an iterable of path segments, that will be joined to the root url.
        :param raise_for_status: like the parameter of the same name from `ApiClient.__init__`, but this will be applied for this request only.
        :param none_fields: like the parameter of the same name from `ApiClient.__init__`, but this will be applied for this request only.
        :param bool_fields: like the parameter of the same name from `ApiClient.__init__`, but this will be applied for this request only.
        :return: a [requests.Response][] as returned by requests
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
                data = {
                    key: val if val is not None else "" for key, val in data.items()
                }
            if isinstance(json, Mapping):
                json = {
                    key: val if val is not None else "" for key, val in json.items()
                }

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

        response = super(ApiClient, self).request(
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
        self, url: Union[None, str, bytes, Iterable[Union[str, bytes, int]]] = None
    ) -> str:
        """Given an 'url', that can be relative or absolute, return the matching absolute url, based on the base url.

        :param url: a (possibly relative) url
        :return: the matching absolute url
        """
        if self.base_url:
            if url is not None:
                if not isinstance(url, (str, bytes)):
                    try:
                        url = "/".join(
                            [
                                part.decode() if isinstance(part, bytes) else str(part)
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

    def get(  # type: ignore
        self,
        url: Union[None, str, bytes, Iterable[Union[str, bytes, int]]] = None,
        raise_for_status: Optional[bool] = None,
        **kwargs: Any,
    ) -> requests.Response:
        """
        Send a GET request. Return a [Response][requests.Response] object.

        The passed `url` may be relative to the url passed at initialization time.
        It takes the same parameters as [ApiClient.request()][requests_oauth2client.api_client.ApiClient.request].

        :param url: a url where the request will be sent.
        :param raise_for_status: overrides the `raises_for_status` parameter passed at initialization time.
        :param none_data_fields: if `"exclude"` (default), data fields whose values are `None` are not included in the request. If "include", they are included with string value `None` (this is the default behavior of `requests`). If "empty", they are included with an empty value (as an empty string).
        :param kwargs: Optional arguments that [request()][requests.request] takes.
        :return: a [Response][requests.Response] object.
        :raises requests.HTTPError: if `raises_for_status` is True (in this request or at initialization time) and an error response is returned.
        and an error response is returned.
        """
        return self.request("GET", url, raise_for_status=raise_for_status, **kwargs)

    def post(self, url: Optional[Union[str, bytes, Iterable[Union[str, bytes]]]] = None, raise_for_status: Optional[bool] = None, **kwargs: Any) -> requests.Response:  # type: ignore
        """
        Send a POST request. Return a [Response][requests.Response] object.

        The passed `url` may be relative to the url passed at initialization time.
        It takes the same parameters as [ApiClient.request()][requests_oauth2client.api_client.ApiClient.request].

        :param url: a url where the request will be sent.
        :param raise_for_status: overrides the `raises_for_status` parameter passed at initialization time.
        :param kwargs: Optional arguments that ``request`` takes.
        :return: a [Response][requests.Response] object.
        :raises requests.HTTPError: if `raises_for_status` is True (in this request or at initialization time) and an error response is returned.
        """
        return self.request("POST", url, raise_for_status=raise_for_status, **kwargs)

    def patch(self, url: Optional[Union[str, bytes, Iterable[Union[str, bytes]]]] = None, raise_for_status: Optional[bool] = None, **kwargs: Any) -> requests.Response:  # type: ignore
        """
        Send a PATCH request. Return a [Response][requests.Response] object.

        The passed `url` may be relative to the url passed at initialization time.
        It takes the same parameters as [ApiClient.request()][requests_oauth2client.api_client.ApiClient.request].

        :param url: a url where the request will be sent.
        :param raise_for_status: overrides the `raises_for_status` parameter passed at initialization time.
        :param kwargs: Optional arguments that ``request`` takes.
        :return: a [Response][requests.Response] object.
        :raises requests.HTTPError: if `raises_for_status` is True (in this request or at initialization time) and an error response is returned.
        """
        return self.request("PATCH", url, raise_for_status=raise_for_status, **kwargs)

    def put(self, url: Optional[Union[str, bytes, Iterable[Union[str, bytes]]]] = None, raise_for_status: Optional[bool] = None, **kwargs: Any) -> requests.Response:  # type: ignore
        """
        Send a PUT request. Return a [Response][requests.Response] object.

        The passed `url` may be relative to the url passed at initialization time.
        It takes the same parameters as [ApiClient.request()][requests_oauth2client.api_client.ApiClient.request].

        :param url: a url where the request will be sent.
        :param raise_for_status: overrides the `raises_for_status` parameter passed at initialization time.
        :param kwargs: Optional arguments that ``request`` takes.
        :return: a a [Response][requests.Response] object.
        :raises requests.HTTPError: if `raises_for_status` is True (in this request or at initialization time) and an error response is returned.
        """
        return self.request("PUT", url, raise_for_status=raise_for_status, **kwargs)

    def delete(  # type: ignore
        self,
        url: Optional[Union[str, bytes, Iterable[Union[str, bytes]]]] = None,
        raise_for_status: Optional[bool] = None,
        **kwargs: Any,
    ) -> requests.Response:
        """
        Send a DELETE request. Return a [Response][requests.Response] object.

        The passed `url` may be relative to the url passed at initialization time.
        It takes the same parameters as [ApiClient.request()][requests_oauth2client.api_client.ApiClient.request].

        :param url: a url where the request will be sent.
        :param raise_for_status: overrides the `raises_for_status` parameter passed at initialization time.
        :param kwargs: Optional arguments that ``request`` takes.
        :return: a a [Response][requests.Response] object.
        :raises requests.HTTPError: if `raises_for_status` is True (in this request or at initialization time) and an error response is returned.
        """
        return self.request("DELETE", url, raise_for_status=raise_for_status, **kwargs)
