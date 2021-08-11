import pytest
from requests import HTTPError

from requests_oauth2client import BearerAuth
from requests_oauth2client.api_client import ApiClient


def test_api_client(requests_mock):
    ACCESS_TOKEN = "my_access_token"
    API_ENDPOINT = "https://localhost/myproject/myapi"
    auth = BearerAuth(ACCESS_TOKEN)
    api = ApiClient(API_ENDPOINT, auth=auth)

    requests_mock.get(API_ENDPOINT, json={"status": "success"})
    response = api.get()
    assert response.ok
    assert requests_mock.last_request.url == API_ENDPOINT
    assert requests_mock.last_request.method == "GET"
    assert requests_mock.last_request.headers.get("Authorization") == f"Bearer {ACCESS_TOKEN}"

    requests_mock.get(API_ENDPOINT + "/resource", json={"status": "success"})
    response = api.get("/resource")
    assert response.ok
    assert requests_mock.last_request.url == API_ENDPOINT + "/resource"
    assert requests_mock.last_request.method == "GET"
    assert requests_mock.last_request.headers.get("Authorization") == f"Bearer {ACCESS_TOKEN}"

    requests_mock.get(API_ENDPOINT + "/resource", json={"status": "success"})
    response = api.get("resource")
    assert response.ok
    assert requests_mock.last_request.url == API_ENDPOINT + "/resource"
    assert requests_mock.last_request.method == "GET"
    assert requests_mock.last_request.headers.get("Authorization") == f"Bearer {ACCESS_TOKEN}"

    OTHER_API = "https://other.api/somethingelse"
    requests_mock.get(OTHER_API, json={"status": "success"})
    response = api.get(OTHER_API)
    assert response.ok
    assert requests_mock.last_request.method == "GET"
    assert requests_mock.last_request.url == OTHER_API
    assert requests_mock.last_request.headers.get("Authorization") == f"Bearer {ACCESS_TOKEN}"

    requests_mock.post(API_ENDPOINT + "/resource", json={"status": "success"})
    response = api.post("/resource")
    assert response.ok
    assert requests_mock.last_request.method == "POST"
    assert requests_mock.last_request.url == API_ENDPOINT + "/resource"
    assert requests_mock.last_request.headers.get("Authorization") == f"Bearer {ACCESS_TOKEN}"

    requests_mock.patch(API_ENDPOINT + "/resource", json={"status": "success"})
    response = api.patch("/resource")
    assert response.ok
    assert requests_mock.last_request.method == "PATCH"
    assert requests_mock.last_request.url == API_ENDPOINT + "/resource"
    assert requests_mock.last_request.headers.get("Authorization") == f"Bearer {ACCESS_TOKEN}"

    requests_mock.put(API_ENDPOINT + "/resource", json={"status": "success"})
    response = api.put("/resource")
    assert response.ok
    assert requests_mock.last_request.method == "PUT"
    assert requests_mock.last_request.url == API_ENDPOINT + "/resource"
    assert requests_mock.last_request.headers.get("Authorization") == f"Bearer {ACCESS_TOKEN}"

    requests_mock.delete(API_ENDPOINT + "/resource", json={"status": "success"})
    response = api.delete("/resource")
    assert response.ok
    assert requests_mock.last_request.method == "DELETE"
    assert requests_mock.last_request.url == API_ENDPOINT + "/resource"
    assert requests_mock.last_request.headers.get("Authorization") == f"Bearer {ACCESS_TOKEN}"

    requests_mock.get(API_ENDPOINT + "/fail", status_code=400, json={"status": "error"})
    with pytest.raises(HTTPError):
        response = api.get("/fail")
    assert requests_mock.last_request.method == "GET"
    assert requests_mock.last_request.url == API_ENDPOINT + "/fail"
    assert requests_mock.last_request.headers.get("Authorization") == f"Bearer {ACCESS_TOKEN}"


def test_no_url(requests_mock):
    api_client = ApiClient()
    requests_mock.get("https://localhost")
    resp = api_client.get("https://localhost")
    assert resp.ok

    with pytest.raises(ValueError):
        api_client.get()


def test_url_as_bytes(requests_mock):
    API_ENDPOINT = "https://localhost/myproject/myapi"
    api = ApiClient(API_ENDPOINT)

    requests_mock.get(API_ENDPOINT, json={"status": "success"})
    resp = api.get()
    assert resp.ok
    resp = api.get(API_ENDPOINT.encode())
    assert resp.ok


def test_raise_for_status(requests_mock):
    API_ENDPOINT = "https://localhost/myproject/myapi"
    api = ApiClient(API_ENDPOINT, raise_for_status=False)

    requests_mock.get(API_ENDPOINT, status_code=400, json={"status": "error"})
    resp = api.get()
    assert not resp.ok

    api_raises = ApiClient(API_ENDPOINT, raise_for_status=True)
    with pytest.raises(HTTPError):
        api_raises.get()
