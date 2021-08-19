from typing import IO, Any, Callable, Iterable, Mapping, MutableMapping, Optional, Tuple, Union
from urllib.parse import urljoin

import requests
from requests.cookies import RequestsCookieJar


class ApiClient(requests.Session):
    """
    A Wrapper around :class:`requests.Session` to simplify Rest API calls.
    """

    def __init__(
        self,
        url: Optional[str] = None,
        auth: Optional[requests.auth.AuthBase] = None,
        raise_for_status: bool = True,
    ):
        """
        :param url: the base api url
        :param auth: the :class:`requests.auth.AuthBase` to use for authentication
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
        :param method: the method to use
        :param url: the url to send the request to. Can be a path instead of a full url; that path will be joined to the
        configured API url.
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
        **kwargs: Any,
    ) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: Optional[Union[str, bytes, Iterable[Union[str, bytes]]]] = None, **kwargs: Any) -> requests.Response:  # type: ignore
        return self.request("POST", url, **kwargs)

    def patch(self, url: Optional[Union[str, bytes, Iterable[Union[str, bytes]]]] = None, **kwargs: Any) -> requests.Response:  # type: ignore
        return self.request("PATCH", url, **kwargs)

    def put(self, url: Optional[Union[str, bytes, Iterable[Union[str, bytes]]]] = None, **kwargs: Any) -> requests.Response:  # type: ignore
        return self.request("PUT", url, **kwargs)

    def delete(  # type: ignore
        self,
        url: Optional[Union[str, bytes, Iterable[Union[str, bytes]]]] = None,
        **kwargs: Any,
    ) -> requests.Response:
        return self.request("DELETE", url, **kwargs)
