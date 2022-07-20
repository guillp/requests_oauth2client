from urllib.parse import urljoin

import pytest
import requests
from requests import HTTPError

from requests_oauth2client import ApiClient, BearerAuth
from tests.conftest import RequestsMocker, RequestValidatorType, join_url


def test_session_at_init() -> None:
    session = requests.Session()
    api = ApiClient(session=session)
    assert api.session == session


def test_get(
    requests_mock: RequestsMocker,
    api: ApiClient,
    access_token: str,
    target_api: str,
    target_path: str,
    bearer_auth_validator: RequestValidatorType,
) -> None:
    target_uri = join_url(target_api, target_path)
    requests_mock.get(target_uri)
    response = api.get(target_path)

    assert response.ok
    assert requests_mock.last_request is not None
    assert requests_mock.last_request.url == target_uri
    assert requests_mock.last_request.method == "GET"
    bearer_auth_validator(requests_mock.last_request, access_token=access_token)


def test_post(
    requests_mock: RequestsMocker,
    api: ApiClient,
    access_token: str,
    target_api: str,
    target_path: str,
    bearer_auth_validator: RequestValidatorType,
) -> None:
    target_uri = join_url(target_api, target_path)
    requests_mock.post(target_uri)
    response = api.post(target_path)

    assert response.ok
    assert requests_mock.last_request is not None
    assert requests_mock.last_request.method == "POST"
    assert requests_mock.last_request.url == target_uri
    bearer_auth_validator(requests_mock.last_request, access_token=access_token)


def test_patch(
    requests_mock: RequestsMocker,
    api: ApiClient,
    access_token: str,
    target_api: str,
    target_path: str,
    bearer_auth_validator: RequestValidatorType,
) -> None:
    target_uri = join_url(target_api, target_path)
    requests_mock.patch(target_uri)
    response = api.patch(target_path)

    assert response.ok
    assert requests_mock.last_request is not None
    assert requests_mock.last_request.method == "PATCH"
    assert requests_mock.last_request.url == target_uri
    bearer_auth_validator(requests_mock.last_request, access_token=access_token)


def test_put(
    requests_mock: RequestsMocker,
    api: ApiClient,
    access_token: str,
    target_api: str,
    target_path: str,
    bearer_auth_validator: RequestValidatorType,
) -> None:
    target_uri = join_url(target_api, target_path)
    requests_mock.put(target_uri)
    response = api.put(target_path)

    assert response.ok
    assert requests_mock.last_request is not None
    assert requests_mock.last_request.method == "PUT"
    assert requests_mock.last_request.url == target_uri
    bearer_auth_validator(requests_mock.last_request, access_token=access_token)


def test_delete(
    requests_mock: RequestsMocker,
    api: ApiClient,
    access_token: str,
    target_api: str,
    target_path: str,
    bearer_auth_validator: RequestValidatorType,
) -> None:
    target_uri = join_url(target_api, target_path)
    requests_mock.delete(target_uri)
    response = api.delete(target_path)

    assert response.ok
    assert requests_mock.last_request is not None
    assert requests_mock.last_request.method == "DELETE"
    assert requests_mock.last_request.url == target_uri
    bearer_auth_validator(requests_mock.last_request, access_token=access_token)


def test_fail(
    requests_mock: RequestsMocker,
    api: ApiClient,
    access_token: str,
    target_api: str,
    bearer_auth_validator: RequestValidatorType,
) -> None:
    requests_mock.get(target_api, status_code=400)
    with pytest.raises(HTTPError):
        api.get()
    assert requests_mock.last_request is not None
    assert requests_mock.last_request.method == "GET"
    assert requests_mock.last_request.url == target_api
    bearer_auth_validator(requests_mock.last_request, access_token=access_token)


def test_no_url_at_init(requests_mock: RequestsMocker, target_api: str) -> None:
    api_client = ApiClient()
    requests_mock.get(target_api)
    resp = api_client.get(target_api)
    assert resp.ok


def test_no_url_fail() -> None:
    api_client = ApiClient()
    with pytest.raises(ValueError):
        api_client.get()


def test_url_as_bytes(requests_mock: RequestsMocker, target_api: str) -> None:
    api = ApiClient(target_api)

    requests_mock.get(target_api)
    resp = api.get()
    assert resp.ok
    resp = api.get(target_api.encode())
    assert resp.ok


def test_url_as_iterable(requests_mock: RequestsMocker, target_api: str) -> None:
    api = ApiClient(target_api)

    target_uri = join_url(target_api, "/resource/1234/foo")
    requests_mock.get(target_uri)
    response = api.get(["resource", "1234", "foo"])
    assert response.ok
    assert requests_mock.last_request is not None
    assert requests_mock.last_request.method == "GET"
    assert requests_mock.last_request.url == target_uri

    response = api.get(["resource", b"1234", "foo"])
    assert response.ok
    assert requests_mock.last_request is not None
    assert requests_mock.last_request.method == "GET"
    assert requests_mock.last_request.url == target_uri

    response = api.get(["resource", 1234, "/foo"])
    assert response.ok
    assert requests_mock.last_request is not None
    assert requests_mock.last_request.method == "GET"
    assert requests_mock.last_request.url == target_uri


def test_raise_for_status(requests_mock: RequestsMocker, target_api: str) -> None:
    api = ApiClient(target_api, raise_for_status=False)

    requests_mock.get(target_api, status_code=400, json={"status": "error"})
    resp = api.get()
    assert not resp.ok
    with pytest.raises(HTTPError):
        api.get(raise_for_status=True)

    api_raises = ApiClient(target_api, raise_for_status=True)
    with pytest.raises(HTTPError):
        api_raises.get()

    assert not api_raises.get(raise_for_status=False).ok


def test_other_api(
    requests_mock: RequestsMocker,
    access_token: str,
    bearer_auth: BearerAuth,
    bearer_auth_validator: RequestValidatorType,
) -> None:
    api = ApiClient("https://some.api/foo", auth=bearer_auth)
    other_api = "https://other.api/somethingelse"
    requests_mock.get(other_api, json={"status": "success"})
    response = api.get(other_api)
    assert response.ok
    assert requests_mock.last_request is not None
    assert requests_mock.last_request.method == "GET"
    assert requests_mock.last_request.url == other_api
    bearer_auth_validator(requests_mock.last_request, access_token=access_token)


def test_url_type(target_api: str) -> None:
    api = ApiClient(target_api)
    with pytest.raises(TypeError):
        api.get(True)  # type: ignore[arg-type]


def test_additional_kwargs(target_api: str) -> None:
    proxies = {"https": "http://localhost:8888"}
    api = ApiClient(target_api, proxies=proxies, timeout=10)
    assert api.session.proxies == proxies
    assert api.timeout == 10


def test_none_fields(requests_mock: RequestsMocker, target_api: str) -> None:
    requests_mock.post(target_api)

    api_exclude = ApiClient(target_api)
    assert api_exclude.none_fields == "exclude"
    api_exclude.post(json={"foo": "bar", "none": None})
    assert requests_mock.last_request is not None
    assert requests_mock.last_request.json() == {"foo": "bar"}

    assert requests_mock.last_request is not None
    api_exclude.post(data={"foo": "bar", "none": None})
    assert requests_mock.last_request is not None
    assert requests_mock.last_request.text == "foo=bar"

    api_include = ApiClient(target_api, none_fields="include")
    api_include.post(json={"foo": "bar", "none": None})
    assert requests_mock.last_request is not None
    assert requests_mock.last_request.json() == {"foo": "bar", "none": None}

    api_include.post(data={"foo": "bar", "none": None})
    assert requests_mock.last_request is not None
    assert requests_mock.last_request.text == "foo=bar"

    api_include = ApiClient(target_api, none_fields="empty")
    api_include.post(json={"foo": "bar", "none": None})
    assert requests_mock.last_request is not None
    assert requests_mock.last_request.json() == {"foo": "bar", "none": ""}

    api_include.post(data={"foo": "bar", "none": None})
    assert requests_mock.last_request is not None
    assert requests_mock.last_request.text == "foo=bar&none="


def test_bool_fields(requests_mock: RequestsMocker, target_api: str) -> None:
    requests_mock.post(target_api)

    api_default = ApiClient(target_api)
    api_default.post(
        data={"foo": "bar", "true": True, "false": False},
        params={"foo": "bar", "true": True, "false": False},
    )
    assert requests_mock.last_request is not None
    assert requests_mock.last_request.query == "foo=bar&true=true&false=false"
    assert requests_mock.last_request.text == "foo=bar&true=true&false=false"

    api_default.post(
        data={"foo": "bar", "true": True, "false": False},
        params={"foo": "bar", "true": True, "false": False},
        bool_fields=("OK", "KO"),
    )
    assert requests_mock.last_request is not None
    assert requests_mock.last_request.query == "foo=bar&true=OK&false=KO"
    assert requests_mock.last_request.text == "foo=bar&true=OK&false=KO"

    api_none = ApiClient(target_api, bool_fields=None)  # default behviour or requests
    api_none.post(
        data={"foo": "bar", "true": True, "false": False},
        params={"foo": "bar", "true": True, "false": False},
    )
    assert requests_mock.last_request is not None
    assert requests_mock.last_request.query == "foo=bar&true=True&false=False"
    assert requests_mock.last_request.text == "foo=bar&true=True&false=False"

    api_yesno = ApiClient(target_api, bool_fields=("yes", "no"))
    api_yesno.post(
        data={"foo": "bar", "true": True, "false": False},
        params={"foo": "bar", "true": True, "false": False},
    )
    assert requests_mock.last_request is not None
    assert requests_mock.last_request.query == "foo=bar&true=yes&false=no"
    assert requests_mock.last_request.text == "foo=bar&true=yes&false=no"

    api_1_0 = ApiClient(target_api, bool_fields=(1, 0))
    api_1_0.post(
        data={"foo": "bar", "true": True, "false": False},
        params={"foo": "bar", "true": True, "false": False},
    )
    assert requests_mock.last_request is not None
    assert requests_mock.last_request.query == "foo=bar&true=1&false=0"
    assert requests_mock.last_request.text == "foo=bar&true=1&false=0"


def test_getattr(requests_mock: RequestsMocker, target_api: str) -> None:
    api = ApiClient(target_api)

    requests_mock.post(target_api)
    assert api.post().ok
    assert requests_mock.last_request is not None

    requests_mock.reset_mock()
    requests_mock.post(urljoin(target_api, "foo"))
    assert api.foo.post().ok
    assert requests_mock.last_request is not None

    requests_mock.reset_mock()
    requests_mock.post(urljoin(target_api, "bar"))
    assert api.bar.post().ok
    assert requests_mock.last_request is not None


def test_getitem(requests_mock: RequestsMocker, target_api: str) -> None:
    api = ApiClient(target_api)

    requests_mock.post(target_api)
    assert api.post().ok
    assert requests_mock.last_request is not None

    requests_mock.reset_mock()
    requests_mock.post(urljoin(target_api, "foo"))
    assert api["foo"].post().ok
    assert requests_mock.last_request is not None

    requests_mock.reset_mock()
    requests_mock.post(urljoin(target_api, "bar"))
    assert api["bar"].post().ok
    assert requests_mock.last_request is not None


def test_contextmanager(requests_mock: RequestsMocker, target_api: str) -> None:
    requests_mock.post(target_api)

    with ApiClient(target_api) as api:
        api.post()

    assert requests_mock.last_request is not None
