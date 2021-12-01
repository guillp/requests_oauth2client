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
        url: Optional[str] = None,
        auth: Optional[requests.auth.AuthBase] = None,
        timeout: Optional[int] = 60,
        raise_for_status: bool = True,
        **kwargs: Any,
    ):
        """
        Initialize an `ApiClient`, with an optional root url.

        `url` will serve as root for relative urls passed to [ApiClient.request()][requests_oauth2client.api_client.ApiClient.request], [ApiClient.get()][requests_oauth2client.api_client.ApiClient.get], etc.
        An `HTTPError` will be raised everytime an API call returns an error code (>= 400), unless you set `raise_for_status` to `False`.
        Additional parameters passed at init time, including `auth` will be used to configure the [Session][requests.Session].

        :param url: the base api url.
        :param auth: the [requests.auth.AuthBase][] to use as authentication handler.
        :param timeout: the default timeout, in seconds, to use for each request from this ApiClient. Can be set to `None` to disable timeout.
        :param raise_for_status: if `True`, exceptions will be raised everytime a request returns an error code (>= 400).
        :param kwargs: additional kwargs to configure this session. This parameter may be overridden at request time.
        """
        super(ApiClient, self).__init__()

        self.url = url
        self.auth = auth
        self.timeout = timeout
        self.raise_for_status = raise_for_status

        for key, val in kwargs.items():
            setattr(self, key, val)

    def request(  # type: ignore
        self,
        method: str,
        url: Union[None, str, bytes, Iterable[Union[str, bytes, int]]] = None,
        params: Union[None, bytes, MutableMapping[str, str]] = None,
        data: Union[
            None,
            str,
            bytes,
            MutableMapping[str, Any],
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
    ) -> requests.Response:
        """
        Overridden `request` method that can handle a relative path instead of a full url.

        :param method: the HTTP method to use
        :param url: the url where the request will be sent to. Can be a path instead of a full url; that path will be
        joined to the configured API url. Can also be an iterable of path segments, that will be joined to the root url.
        :return: a [requests.Response][] as returned by requests
        """
        if self.url:
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

                url = urljoin(self.url + "/", url.lstrip("/"))
            else:
                url = self.url

        if url is None or not isinstance(url, str):
            raise ValueError("No url to send the request to")

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
