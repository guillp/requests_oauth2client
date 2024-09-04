from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs

import pytest
import requests

from requests_oauth2client import (
    BearerToken,
    ExpiredAccessToken,
    NonRenewableTokenError,
    OAuth2AccessTokenAuth,
    OAuth2AuthorizationCodeAuth,
    OAuth2Client,
    OAuth2ClientCredentialsAuth,
    OAuth2DeviceCodeAuth,
    OAuth2ResourceOwnerPasswordAuth,
)
from tests.conftest import RequestsMocker


@pytest.fixture
def minutes_ago() -> datetime:
    return datetime.now(tz=timezone.utc) - timedelta(minutes=3)


def test_bearer_auth(
    requests_mock: RequestsMocker,
    target_api: str,
    bearer_token: BearerToken,
    access_token: str,
) -> None:
    requests_mock.post(target_api)
    response = requests.post(target_api, auth=bearer_token)
    assert response.ok
    assert requests_mock.last_request is not None
    assert requests_mock.last_request.headers.get("Authorization") == f"Bearer {access_token}"


def test_expired_token(minutes_ago: datetime) -> None:
    token = BearerToken(access_token="foo", expires_at=minutes_ago)
    with pytest.raises(ExpiredAccessToken):
        requests.post("http://localhost/test", auth=token)


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

    token = BearerToken(access_token=access_token, refresh_token=refresh_token, expires_at=minutes_ago)
    client = OAuth2Client(token_endpoint, (client_id, client_secret))
    auth = OAuth2AccessTokenAuth(client, token)

    assert auth.client is client
    assert auth.token is token

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

    assert OAuth2AccessTokenAuth(client, token=access_token).token == BearerToken(access_token)


def test_client_credentials_auth(
    requests_mock: RequestsMocker,
    target_api: str,
    token_endpoint: str,
    client_id: str,
    client_secret: str,
    access_token: str,
    refresh_token: str,
) -> None:
    client = OAuth2Client(token_endpoint, (client_id, client_secret))
    auth = OAuth2ClientCredentialsAuth(client)

    assert auth.client is client
    assert auth.token is None

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
    cc_request = requests_mock.request_history[0]
    api_request = requests_mock.request_history[-1]

    assert cc_request.url == token_endpoint
    refresh_params = parse_qs(cc_request.body)
    assert refresh_params["grant_type"] == ["client_credentials"]
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

    assert OAuth2ClientCredentialsAuth(client, token=access_token).token == BearerToken(access_token)
    assert OAuth2ClientCredentialsAuth(client, token=BearerToken(access_token)).token == BearerToken(access_token)


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

    assert auth.client is client
    assert auth.code is authorization_code
    assert auth.token is None

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

    assert OAuth2AuthorizationCodeAuth(client, code=authorization_code, token=access_token).token == BearerToken(
        access_token
    )


def test_ropc_auth(
    requests_mock: RequestsMocker,
    target_api: str,
    token_endpoint: str,
    client_id: str,
    client_secret: str,
    access_token: str,
    refresh_token: str,
) -> None:
    oauth2client = OAuth2Client(
        token_endpoint=token_endpoint,
        client_id=client_id,
        client_secret=client_secret,
    )
    username = "my_user1"
    password = "T0t@lly_5eCur3!"

    auth = OAuth2ResourceOwnerPasswordAuth(client=oauth2client, username=username, password=password)

    assert auth.client is oauth2client
    assert auth.username is username
    assert auth.password is password
    assert auth.token is None

    requests_mock.post(
        token_endpoint,
        json={
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": "3600",
        },
    )
    requests_mock.post(target_api)

    assert requests.post(target_api, auth=auth).ok

    assert len(requests_mock.request_history) == 2

    token_request = requests_mock.request_history[0]
    token_params = parse_qs(token_request.body)
    assert token_params["grant_type"] == ["password"]
    assert token_params["username"] == [username]
    assert token_params["password"] == [password]

    api_request = requests_mock.request_history[1]
    assert api_request.url == target_api
    assert api_request.headers.get("Authorization") == f"Bearer {access_token}"

    assert auth.token is not None
    assert auth.token.access_token == access_token
    assert auth.token.refresh_token == refresh_token

    requests_mock.reset_mock()
    requests.post(target_api, auth=auth)
    assert requests_mock.last_request is not None
    assert requests_mock.last_request.url == target_api

    assert OAuth2ResourceOwnerPasswordAuth(
        oauth2client, username=username, password=password, token=access_token
    ).token == BearerToken(access_token)


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

    auth = OAuth2DeviceCodeAuth(client=oauth2client, device_code=da_resp.device_code, interval=1, expires_in=60)
    assert auth.client is oauth2client
    assert auth.device_code is da_resp.device_code
    assert auth.token is None

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

    auth.forget_token()
    with pytest.raises(NonRenewableTokenError):
        requests.post(target_api, auth=auth)

    assert OAuth2DeviceCodeAuth(oauth2client, device_code=device_code, token=access_token).token == BearerToken(
        access_token
    )
