from datetime import datetime, timedelta
from urllib.parse import parse_qs

import pytest
import requests

from requests_oauth2client import (
    BearerAuth,
    BearerToken,
    ExpiredAccessToken,
    OAuth2AccessTokenAuth,
    OAuth2AuthorizationCodeAuth,
    OAuth2Client,
    OAuth2DeviceCodeAuth,
)
from tests.conftest import RequestsMocker


@pytest.fixture()
def minutes_ago() -> datetime:
    return datetime.now() - timedelta(minutes=3)


def test_bearer_auth(
    requests_mock: RequestsMocker,
    target_api: str,
    bearer_auth: BearerAuth,
    access_token: str,
) -> None:
    requests_mock.post(target_api)
    response = requests.post(target_api, auth=bearer_auth)
    assert response.ok
    assert requests_mock.last_request is not None
    assert requests_mock.last_request.headers.get("Authorization") == f"Bearer {access_token}"


def test_bearer_auth_none(requests_mock: RequestsMocker, target_api: str) -> None:
    requests_mock.post(target_api)
    auth = BearerAuth()
    response = requests.post(target_api, auth=auth)
    assert response.ok
    assert requests_mock.last_request is not None
    assert requests_mock.last_request.headers.get("Authorization") is None


def test_expired_token(minutes_ago: datetime) -> None:
    token = BearerToken(access_token="foo", expires_at=minutes_ago)
    auth = BearerAuth(token)
    with pytest.raises(ExpiredAccessToken):
        requests.post("http://localhost/test", auth=auth)


def test_access_token_auth(
    requests_mock: RequestsMocker,
    target_uri: str,
    token_endpoint: str,
    client_id: str,
    client_secret: str,
    minutes_ago: datetime,
) -> None:
    access_token = "access_token"
    refresh_token = "refresh_token"
    new_access_token = "new_access_token"
    new_refresh_token = "new_refresh_token"

    token = BearerToken(
        access_token=access_token, refresh_token=refresh_token, expires_at=minutes_ago
    )
    client = OAuth2Client(token_endpoint, (client_id, client_secret))
    auth = OAuth2AccessTokenAuth(client, token)

    requests_mock.post(target_uri)
    requests_mock.post(
        token_endpoint,
        json={
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "expires_in": 3600,
            "token_type": "Bearer",
        },
    )
    requests.post(target_uri, auth=auth)

    assert len(requests_mock.request_history) == 2
    refresh_request = requests_mock.request_history[0]
    api_request = requests_mock.request_history[-1]

    assert refresh_request.url == token_endpoint
    refresh_params = parse_qs(refresh_request.body)
    assert refresh_params["grant_type"] == ["refresh_token"]
    assert refresh_params["refresh_token"] == [refresh_token]
    assert refresh_params["client_id"] == [client_id]
    assert refresh_params["client_secret"] == [client_secret]

    assert api_request.url == target_uri
    assert api_request.headers.get("Authorization") == f"Bearer {new_access_token}"

    assert auth.token is not None
    assert auth.token.access_token == new_access_token
    assert auth.token.refresh_token == new_refresh_token


def test_authorization_code_auth(
    requests_mock: RequestsMocker,
    target_api: str,
    token_endpoint: str,
    client_id: str,
    client_secret: str,
    authorization_code: str,
    access_token: str,
    refresh_token: str,
) -> None:

    client = OAuth2Client(token_endpoint, (client_id, client_secret))
    auth = OAuth2AuthorizationCodeAuth(client, authorization_code)

    requests_mock.post(target_api)
    requests_mock.post(
        token_endpoint,
        json={
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_in": 3600,
            "token_type": "Bearer",
        },
    )
    requests.post(target_api, auth=auth)

    assert len(requests_mock.request_history) == 2
    code_request = requests_mock.request_history[0]
    api_request = requests_mock.request_history[-1]

    assert code_request.url == token_endpoint
    refresh_params = parse_qs(code_request.body)
    assert refresh_params["grant_type"] == ["authorization_code"]
    assert refresh_params["code"] == [authorization_code]
    assert refresh_params["client_id"] == [client_id]
    assert refresh_params["client_secret"] == [client_secret]

    assert api_request.url == target_api
    assert api_request.headers.get("Authorization") == f"Bearer {access_token}"

    assert auth.token is not None
    assert auth.token.access_token == access_token
    assert auth.token.refresh_token == refresh_token

    requests_mock.reset_mock()
    requests.post(target_api, auth=auth)
    assert len(requests_mock.request_history) == 1


def test_device_code_auth(
    requests_mock: RequestsMocker,
    target_api: str,
    device_authorization_endpoint: str,
    token_endpoint: str,
    client_id: str,
    client_secret: str,
    device_code: str,
    user_code: str,
    verification_uri: str,
    verification_uri_complete: str,
    access_token: str,
    refresh_token: str,
) -> None:

    oauth2client = OAuth2Client(
        token_endpoint=token_endpoint,
        device_authorization_endpoint=device_authorization_endpoint,
        auth=(client_id, client_secret),
    )
    requests_mock.post(
        device_authorization_endpoint,
        json={
            "device_code": device_code,
            "user_code": user_code,
            "verification_uri": verification_uri,
            "verification_uri_complete": verification_uri_complete,
            "expires_in": 300,
            "interval": 1,
        },
    )

    da_resp = oauth2client.authorize_device()

    requests_mock.reset_mock()
    requests_mock.post(
        token_endpoint,
        json={
            "access_token": access_token,
            "expires_in": 60,
            "refresh_token": refresh_token,
        },
    )
    requests_mock.post(target_api)

    auth = OAuth2DeviceCodeAuth(
        client=oauth2client, device_code=da_resp.device_code, interval=1, expires_in=60
    )
    assert requests.post(target_api, auth=auth)
    assert len(requests_mock.request_history) == 2
    device_code_request = requests_mock.request_history[0]
    api_request = requests_mock.request_history[1]

    assert device_code_request.url == token_endpoint
    da_params = parse_qs(device_code_request.body)
    assert da_params["grant_type"] == ["urn:ietf:params:oauth:grant-type:device_code"]
    assert da_params["device_code"] == [device_code]
    assert da_params["client_id"] == [client_id]
    assert da_params["client_secret"] == [client_secret]

    assert api_request.url == target_api
    assert api_request.headers.get("Authorization") == f"Bearer {access_token}"

    assert auth.token is not None
    assert auth.token.access_token == access_token
    assert auth.token.refresh_token == refresh_token

    requests_mock.reset_mock()
    requests.post(target_api, auth=auth)
    assert requests_mock.last_request is not None
    assert requests_mock.last_request.url == target_api
