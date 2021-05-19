import pytest
import requests
from requests_mock import ANY

from requests_oauth2client import BearerAuth


@pytest.fixture()
def access_token():
    return "TEST_ACCESS_TOKEN"


def test_bearer_auth(requests_mock, access_token):
    def callback(request, context):
        received_authorization_header = request.headers.get("Authorization")
        expected_authorization_header = f"Bearer {access_token}"
        assert received_authorization_header == expected_authorization_header

    requests_mock.post(
        ANY, json=callback,
    )

    API = "http://localhost/"
    auth = BearerAuth(access_token)
    response = requests.post(API, auth=auth)
    assert response.ok


def test_bearer_auth_none(requests_mock):
    def callback(request, context):
        received_authorization_header = request.headers.get("Authorization")
        assert received_authorization_header == None

    requests_mock.post(ANY, json=callback)

    API = "http://localhost/"
    auth = BearerAuth()
    response = requests.post(API, auth=auth)
    assert response.ok
