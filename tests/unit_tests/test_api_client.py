import pytest
from requests import HTTPError

from requests_oauth2client import ApiClient


def test_get(
    requests_mock,
    api,
    access_token,
    bearer_auth,
    target_api,
    target_path,
    join_url,
    bearer_auth_validator,
):
    target_uri = join_url(target_api, target_path)
    requests_mock.get(target_uri)
    response = api.get(target_path)
    assert response.ok
    assert requests_mock.last_request.url == target_uri
    assert requests_mock.last_request.method == "GET"
    bearer_auth_validator(requests_mock.last_request, access_token)


def test_post(
    requests_mock,
    api,
    access_token,
    bearer_auth,
    target_api,
    target_path,
    join_url,
    bearer_auth_validator,
):
    target_uri = join_url(target_api, target_path)
    requests_mock.post(target_uri)
    response = api.post(target_path)
    assert response.ok
    assert requests_mock.last_request.method == "POST"
    assert requests_mock.last_request.url == target_uri
    bearer_auth_validator(requests_mock.last_request, access_token)


def test_patch(
    requests_mock,
    api,
    access_token,
    bearer_auth,
    target_api,
    target_path,
    join_url,
    bearer_auth_validator,
):
    target_uri = join_url(target_api, target_path)
    requests_mock.patch(target_uri)
    response = api.patch(target_path)
    assert response.ok
    assert requests_mock.last_request.method == "PATCH"
    assert requests_mock.last_request.url == target_uri
    bearer_auth_validator(requests_mock.last_request, access_token)


def test_put(
    requests_mock,
    api,
    access_token,
    bearer_auth,
    target_api,
    target_path,
    join_url,
    bearer_auth_validator,
):
    target_uri = join_url(target_api, target_path)
    requests_mock.put(target_uri)
    response = api.put(target_path)
    assert response.ok
    assert requests_mock.last_request.method == "PUT"
    assert requests_mock.last_request.url == target_uri
    bearer_auth_validator(requests_mock.last_request, access_token)


def test_delete(
    requests_mock,
    api,
    access_token,
    bearer_auth,
    target_api,
    target_path,
    join_url,
    bearer_auth_validator,
):
    target_uri = join_url(target_api, target_path)
    requests_mock.delete(target_uri)
    response = api.delete(target_path)

    assert response.ok
    assert requests_mock.last_request.method == "DELETE"
    assert requests_mock.last_request.url == target_uri
    bearer_auth_validator(requests_mock.last_request, access_token)


def test_fail(requests_mock, api, access_token, bearer_auth, target_api, bearer_auth_validator):
    requests_mock.get(target_api, status_code=400)
    with pytest.raises(HTTPError):
        api.get()
    assert requests_mock.last_request.method == "GET"
    assert requests_mock.last_request.url == target_api
    bearer_auth_validator(requests_mock.last_request, access_token)


def test_no_url_at_init(requests_mock, target_api):
    api_client = ApiClient()
    requests_mock.get(target_api)
    resp = api_client.get(target_api)
    assert resp.ok


def test_no_url_fail():
    api_client = ApiClient()
    with pytest.raises(ValueError):
        api_client.get()


def test_url_as_bytes(requests_mock, target_api):
    api = ApiClient(target_api)

    requests_mock.get(target_api)
    resp = api.get()
    assert resp.ok
    resp = api.get(target_api.encode())
    assert resp.ok


def test_url_as_iterable(requests_mock, target_api, join_url):
    api = ApiClient(target_api)

    target_uri = join_url(target_api, "/resource/1234/foo")
    requests_mock.get(target_uri)
    response = api.get(["resource", "1234", "foo"])
    assert response.ok
    assert requests_mock.last_request.method == "GET"
    assert requests_mock.last_request.url == target_uri

    response = api.get(["resource", b"1234", "foo"])
    assert response.ok
    assert requests_mock.last_request.method == "GET"
    assert requests_mock.last_request.url == target_uri

    response = api.get(["resource", 1234, "/foo"])
    assert response.ok
    assert requests_mock.last_request.method == "GET"
    assert requests_mock.last_request.url == target_uri


def test_raise_for_status(requests_mock, target_api):
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


def test_other_api(requests_mock, access_token, bearer_auth, bearer_auth_validator):
    api = ApiClient("https://some.api/foo", auth=bearer_auth)
    other_api = "https://other.api/somethingelse"
    requests_mock.get(other_api, json={"status": "success"})
    response = api.get(other_api)
    assert response.ok
    assert requests_mock.last_request.method == "GET"
    assert requests_mock.last_request.url == other_api
    bearer_auth_validator(requests_mock.last_request, access_token)


def test_url_type(target_api):
    api = ApiClient(target_api)
    with pytest.raises(TypeError):
        api.get(True)
