import pytest
import requests

from requests_oauth2client import BearerAuth


@pytest.fixture()
def access_token():
    return "TEST_ACCESS_TOKEN"


def test_bearer_auth(requests_mock, access_token):
    api = "http://localhost/"
    requests_mock.post(api)
    auth = BearerAuth(access_token)
    response = requests.post(api, auth=auth)
    assert response.ok
    assert requests_mock.last_request.headers.get("Authorization") == f"Bearer {access_token}"


def test_bearer_auth_none(requests_mock):
    api = "http://localhost/"
    requests_mock.post(api)
    auth = BearerAuth()
    response = requests.post(api, auth=auth)
    assert response.ok
    assert requests_mock.last_request.headers.get("Authorization") is None
