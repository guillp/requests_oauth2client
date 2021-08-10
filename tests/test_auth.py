from datetime import datetime, timedelta
from urllib.parse import parse_qs

import pytest
import requests

from requests_oauth2client import (BearerAuth, BearerToken, OAuth2AccessTokenAuth,
                                   OAuth2AuthorizationCodeAuth, OAuth2Client)
from requests_oauth2client.exceptions import ExpiredToken


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


def test_expired_token():
    minutes_ago = datetime.now() - timedelta(minutes=3)
    token = BearerToken(access_token="foo", expires_at=minutes_ago)
    auth = BearerAuth(token)
    with pytest.raises(ExpiredToken):
        requests.post("http://localhost/test", auth=auth)


def test_access_token_auth(requests_mock):
    token_endpoint = "https://myas.local/token"
    client_id = "client_id"
    client_secret = "client_secret"
    api_url = "https://myapi.local/api"

    access_token = "access_token"
    refresh_token = "refresh_token"
    new_access_token = "new_access_token"
    new_refresh_token = "new_refresh_token"

    minutes_ago = datetime.now() - timedelta(minutes=3)
    token = BearerToken(
        access_token=access_token, refresh_token=refresh_token, expires_at=minutes_ago
    )
    client = OAuth2Client(token_endpoint, (client_id, client_secret))
    auth = OAuth2AccessTokenAuth(client, token)

    requests_mock.post(api_url)
    requests_mock.post(
        token_endpoint,
        json={
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "expires_in": 3600,
            "token_type": "Bearer",
        },
    )
    requests.post(api_url, auth=auth)

    assert len(requests_mock.request_history) == 2
    refresh_request = requests_mock.request_history[0]
    api_request = requests_mock.request_history[-1]

    assert refresh_request.url == token_endpoint
    refresh_params = parse_qs(refresh_request.body)
    assert refresh_params["grant_type"] == ["refresh_token"]
    assert refresh_params["refresh_token"] == [refresh_token]
    assert refresh_params["client_id"] == [client_id]
    assert refresh_params["client_secret"] == [client_secret]

    assert api_request.url == api_url
    assert api_request.headers.get("Authorization") == f"Bearer {new_access_token}"

    assert auth.token.access_token == new_access_token
    assert auth.token.refresh_token == new_refresh_token


def test_authorization_code_auth(requests_mock):
    token_endpoint = "https://myas.local/token"
    client_id = "client_id"
    client_secret = "client_secret"
    api_url = "https://myapi.local/api"

    authorization_code = "authorization_code"
    access_token = "access_token"
    refresh_token = "refresh_token"

    client = OAuth2Client(token_endpoint, (client_id, client_secret))
    auth = OAuth2AuthorizationCodeAuth(client, authorization_code)

    requests_mock.post(api_url)
    requests_mock.post(
        token_endpoint,
        json={
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_in": 3600,
            "token_type": "Bearer",
        },
    )
    requests.post(api_url, auth=auth)

    assert len(requests_mock.request_history) == 2
    code_request = requests_mock.request_history[0]
    api_request = requests_mock.request_history[-1]

    assert code_request.url == token_endpoint
    refresh_params = parse_qs(code_request.body)
    assert refresh_params["grant_type"] == ["authorization_code"]
    assert refresh_params["code"] == [authorization_code]
    assert refresh_params["client_id"] == [client_id]
    assert refresh_params["client_secret"] == [client_secret]

    assert api_request.url == api_url
    assert api_request.headers.get("Authorization") == f"Bearer {access_token}"

    assert auth.token.access_token == access_token
    assert auth.token.refresh_token == refresh_token

    requests_mock.reset_mock()
    requests.post(api_url, auth=auth)
    assert len(requests_mock.request_history) == 1
