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
    A Wrapper around :class:`requests.Session` to simplify Rest API calls.
    This allows setting a root url at creation time, then passing relative urls at request time.
    It may also raise exceptions instead of returning error responses.

    Basic usage:

        from requests_oauth2client import ApiClient
        api = ApiClient("https://myapi.local/resource")
        resp = api.get("/myid") # this will send a GET request to https://myapi.local/resource/myid

    """

    def __init__(
        self,
        url: Optional[str] = None,
        auth: Optional[requests.auth.AuthBase] = None,
        raise_for_status: bool = True,
    ):
        """
        :param url: the base api url. This url will serve as root for relative urls passed to :method:`ApiClient.request()`, :method:`ApiClient.get()`, etc.
        :param auth: the :class:`requests.auth.AuthBase` to use as authentication handler.
        :param raise_for_status: if `True`, exceptions will be raised everytime a request returns an error code (>= 400).
        This parameter may be overridden at request time.
        """
        super(ApiClient, self).__init__()

        self.url = url
        self.auth = auth
        self.raise_for_status = raise_for_status

    def request(  # type: ignore
        self,
        method: str,
        url: Optional[Union[str, bytes, Iterable[Union[str, bytes]]]] = None,
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
        A customized request method to handle a path instead of a full url.
        :param method: the HTTP method to use
        :param url: the url where the request will be sent to. Can be a path instead of a full url; that path will be
        joined to the configured API url.
        :return: a :class:`requests.Response` as returned by requests
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
        url: Optional[Union[str, bytes, Iterable[Union[str, bytes]]]] = None,
        raise_for_status: Optional[bool] = None,
        **kwargs: Any,
    ) -> requests.Response:
        """
        Sends a GET request. Returns :class:`Response` object.
        The passed `url` may be relative to the url passed at initialization time.

        :param url: a url where the request will be sent.
        :param raise_for_status: overrides the `raises_for_status` parameter passed at initialization time.
        :param kwargs: Optional arguments that ``request`` takes.
        :return: a :class:`requests.Response` object.
        :raises: a :class:`requests.HTTPError` if `raise_for_status` is True (in this request or at initialization time)
        and an error response is returned.
        """
        return self.request("GET", url, raise_for_status=raise_for_status, **kwargs)

    def post(self, url: Optional[Union[str, bytes, Iterable[Union[str, bytes]]]] = None, raise_for_status: Optional[bool] = None, **kwargs: Any) -> requests.Response:  # type: ignore
        """
        Sends a POST request. Returns :class:`Response` object.
        The passed `url` may be relative to the url passed at initialization time.

        :param url: a url where the request will be sent.
        :param raise_for_status: overrides the `raises_for_status` parameter passed at initialization time.
        :param kwargs: Optional arguments that ``request`` takes.
        :return: a :class:`requests.Response` object.
        :raises: a :class:`requests.HTTPError` if `raises_for_status` is True (in this request or at initialization time) and an error response is returned.
        """
        return self.request("POST", url, raise_for_status=raise_for_status, **kwargs)

    def patch(self, url: Optional[Union[str, bytes, Iterable[Union[str, bytes]]]] = None, raise_for_status: Optional[bool] = None, **kwargs: Any) -> requests.Response:  # type: ignore
        """
        Sends a PATCH request. Returns :class:`Response` object.
        The passed `url` may be relative to the url passed at initialization time.

        :param url: a url where the request will be sent.
        :param raise_for_status: overrides the `raises_for_status` parameter passed at initialization time.
        :param kwargs: Optional arguments that ``request`` takes.
        :return: a :class:`requests.Response` object.
        :raises: a :class:`requests.HTTPError` if `raises_for_status` is True (in this request or at initialization time) and an error response is returned.
        """
        return self.request("PATCH", url, raise_for_status=raise_for_status, **kwargs)

    def put(self, url: Optional[Union[str, bytes, Iterable[Union[str, bytes]]]] = None, raise_for_status: Optional[bool] = None, **kwargs: Any) -> requests.Response:  # type: ignore
        """
        Sends a PUT request. Returns :class:`Response` object.
        The passed `url` may be relative to the url passed at initialization time.

        :param url: a url where the request will be sent.
        :param raise_for_status: overrides the `raises_for_status` parameter passed at initialization time.
        :param kwargs: Optional arguments that ``request`` takes.
        :return: a :class:`requests.Response` object.
        :raises: a :class:`requests.HTTPError` if `raises_for_status` is True (in this request or at initialization time) and an error response is returned.
        """
        return self.request("PUT", url, raise_for_status=raise_for_status, **kwargs)

    def delete(  # type: ignore
        self,
        url: Optional[Union[str, bytes, Iterable[Union[str, bytes]]]] = None,
        raise_for_status: Optional[bool] = None,
        **kwargs: Any,
    ) -> requests.Response:
        """
        Sends a DELETE request. Returns :class:`Response` object.
        The passed `url` may be relative to the url passed at initialization time.

        :param url: a url where the request will be sent.
        :param raise_for_status: overrides the `raises_for_status` parameter passed at initialization time.
        :param kwargs: Optional arguments that ``request`` takes.
        :return: a :class:`requests.Response` object.
        :raises: a :class:`requests.HTTPError` if `raises_for_status` is True (in this request or at initialization time) and an error response is returned.
        """
        return self.request("DELETE", url, raise_for_status=raise_for_status, **kwargs)
