from typing import Callable

import pytest
from requests import HTTPError
from requests_mock import Mocker

from requests_oauth2client import ApiClient, BearerAuth
from tests.conftest import RequestValidatorType, join_url


def test_get(
    requests_mock: Mocker,
    api: ApiClient,
    access_token: str,
    bearer_auth: BearerAuth,
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
    requests_mock: Mocker,
    api: ApiClient,
    access_token: str,
    bearer_auth: BearerAuth,
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
    requests_mock: Mocker,
    api: ApiClient,
    access_token: str,
    bearer_auth: BearerAuth,
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
    requests_mock: Mocker,
    api: ApiClient,
    access_token: str,
    bearer_auth: BearerAuth,
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
    requests_mock: Mocker,
    api: ApiClient,
    access_token: str,
    bearer_auth: BearerAuth,
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
    requests_mock: Mocker,
    api: ApiClient,
    access_token: str,
    bearer_auth: BearerAuth,
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


def test_no_url_at_init(requests_mock: Mocker, target_api: str) -> None:
    api_client = ApiClient()
    requests_mock.get(target_api)
    resp = api_client.get(target_api)
    assert resp.ok


def test_no_url_fail() -> None:
    api_client = ApiClient()
    with pytest.raises(ValueError):
        api_client.get()


def test_url_as_bytes(requests_mock: Mocker, target_api: str) -> None:
    api = ApiClient(target_api)

    requests_mock.get(target_api)
    resp = api.get()
    assert resp.ok
    resp = api.get(target_api.encode())
    assert resp.ok


def test_url_as_iterable(requests_mock: Mocker, target_api: str) -> None:
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


def test_raise_for_status(requests_mock: Mocker, target_api: str) -> None:
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
    requests_mock: Mocker,
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
        api.get(True)  # type: ignore


def test_additional_kwargs(target_api: str) -> None:
    proxies = {"https": "http://localhost:8888"}
    api = ApiClient(target_api, proxies=proxies, timeout=10)
    assert api.proxies == proxies
    assert api.timeout == 10


def test_ignore_none_fields(requests_mock: Mocker, target_api: str) -> None:
    requests_mock.post(target_api)

    api_exclude = ApiClient(target_api)
    assert api_exclude.none_fields == "exclude"
    api_exclude.post(json={"foo": "bar", "none": None})
    assert requests_mock.last_request.json() == {"foo": "bar"}
    api_exclude.post(data={"foo": "bar", "none": None})
    assert requests_mock.last_request.text == "foo=bar"

    api_include = ApiClient(target_api, none_fields="include")
    api_include.post(json={"foo": "bar", "none": None})
    assert requests_mock.last_request.json() == {"foo": "bar", "none": None}
    api_include.post(data={"foo": "bar", "none": None})
    assert requests_mock.last_request.text == "foo=bar"

    api_include = ApiClient(target_api, none_fields="empty")
    api_include.post(json={"foo": "bar", "none": None})
    assert requests_mock.last_request.json() == {"foo": "bar", "none": ""}
    api_include.post(data={"foo": "bar", "none": None})
    assert requests_mock.last_request.text == "foo=bar&none="
