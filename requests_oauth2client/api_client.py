from urllib.parse import urljoin

import requests


class ApiClient(requests.Session):
    """
    A Wrapper around :class:`requests.Session` to simplify Rest API calls.
    """

    def __init__(
        self, url: str, auth: requests.auth.AuthBase = None, raise_for_status: bool = True,
    ):
        """
        :param url: the base api url
        :param auth: the :class:`requests.auth.AuthBase` to use for authentication
        """
        super(ApiClient, self).__init__()

        self.url = url
        self.auth = auth
        self.raise_exc = raise_for_status

    def request(self, method, url=None, **kwargs):
        """
        A customized request method to handle a path instead of a full url.
        :param method: the method to use
        :param url: the url to send the request to. Can be a path instead of a full url; that path will be joined to the
        configured API url.
        :param kwargs: additional arguments to :method:`request()`
        :return: a :class:`requests.Response` as returned by requests
        """
        if self.url:
            if url:
                url = urljoin(self.url + "/", url.lstrip("/"))
            else:
                url = self.url

        response = super(ApiClient, self).request(method, url, **kwargs)

        if self.raise_exc:
            response.raise_for_status()
        return response

    def get(self, url=None, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url=None, **kwargs):
        return self.request("POST", url, **kwargs)

    def patch(self, url=None, **kwargs):
        return self.request("PATCH", url, **kwargs)

    def put(self, url=None, **kwargs):
        return self.request("PUT", url, **kwargs)

    def delete(self, url=None, **kwargs):
        return self.request("DELETE", url, **kwargs)
