import pytest
from requests import HTTPError
from requests_mock import ANY

from requests_oauth2client import BearerAuth
from requests_oauth2client.api_client import ApiClient


def test_api_client(requests_mock):
    ACCESS_TOKEN = "my_access_token"
    API_ENDPOINT = "https://localhost/myproject/myapi"
    auth = BearerAuth(ACCESS_TOKEN)
    api = ApiClient(API_ENDPOINT, auth=auth)

    def api_callback(request, context):
        assert request.headers.get("Authorization") == f"Bearer {ACCESS_TOKEN}"

        if not request.path.endswith("fail"):
            return {"status": "success", "url": request.url, "method": request.method}
        else:
            context.status_code = 400
            return {"status": "error", "url": request.url, "method": request.method}

    requests_mock.register_uri(
        ANY, ANY, json=api_callback,
    )

    response = api.get()
    assert response.ok
    assert response.json()["url"] == API_ENDPOINT
    assert response.json()["method"] == "GET"

    response = api.get("resource")
    assert response.ok
    assert response.json()["url"] == API_ENDPOINT + "/resource"

    response = api.get("/resource")
    assert response.ok
    assert response.json()["url"] == API_ENDPOINT + "/resource"

    OTHER_API = "https://other.api/somethingelse"
    response = api.get(OTHER_API)
    assert response.ok
    assert response.json()["url"] == OTHER_API

    response = api.post("/resource")
    assert response.ok
    assert response.json()["url"] == API_ENDPOINT + "/resource"
    assert response.json()["method"] == "POST"

    response = api.patch("/resource")
    assert response.ok
    assert response.json()["url"] == API_ENDPOINT + "/resource"
    assert response.json()["method"] == "PATCH"

    response = api.put("/resource")
    assert response.ok
    assert response.json()["url"] == API_ENDPOINT + "/resource"
    assert response.json()["method"] == "PUT"

    response = api.delete("/resource")
    assert response.ok
    assert response.json()["url"] == API_ENDPOINT + "/resource"
    assert response.json()["method"] == "DELETE"

    with pytest.raises(HTTPError):
        response = api.get("/fail")
