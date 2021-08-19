import secrets
from urllib.parse import parse_qs

import pytest

from requests_oauth2client import ClientSecretBasic, OAuth2Client
from requests_oauth2client.client_authentication import PublicApp
from requests_oauth2client.device_authorization import (DeviceAuthorizationClient,
                                                        DeviceAuthorizationPoolingJob)
from requests_oauth2client.exceptions import (DeviceAuthorizationError,
                                              InvalidDeviceAuthorizationResponse)


@pytest.fixture(params=["device", "oauth/device"])
def device_authorization_endpoint(request, issuer, join_url):
    return join_url(issuer, request.param)


@pytest.mark.slow
def test_device_authorization(
    requests_mock, device_authorization_endpoint, token_endpoint, client_id, client_secret
):
    device_code = secrets.token_urlsafe()
    user_code = secrets.token_urlsafe(6)
    verification_uri = "https://test.com/verify_device"

    da_client = DeviceAuthorizationClient(
        device_authorization_endpoint=device_authorization_endpoint,
        auth=(client_id, client_secret),
    )

    requests_mock.post(
        device_authorization_endpoint,
        json={
            "device_code": device_code,
            "user_code": user_code,
            "verification_uri": verification_uri,
            "expires_in": 3600,
        },
    )
    device_auth_resp = da_client.authorize_device()
    assert device_auth_resp.device_code
    assert device_auth_resp.user_code
    assert device_auth_resp.verification_uri
    assert not device_auth_resp.is_expired()

    params = parse_qs(requests_mock.last_request.text)
    assert params.get("client_id") == [client_id]
    assert params.get("client_secret") == [client_secret]

    access_token = secrets.token_urlsafe()

    requests_mock.post(
        token_endpoint,
        [
            {"json": {"error": "authorization_pending"}, "status_code": 400},
            {"json": {"error": "slow_down"}, "status_code": 400},
            {
                "json": {
                    "access_token": access_token,
                    "token_type": "Bearer",
                    "expires_in": 3600,
                }
            },
        ],
    )

    client = OAuth2Client(token_endpoint, (client_id, client_secret))
    pool_job = DeviceAuthorizationPoolingJob(
        client, device_auth_resp.device_code, interval=device_auth_resp.interval
    )

    # 1st attempt: authorization_pending
    resp = pool_job()
    params = parse_qs(requests_mock.last_request.text)
    assert params.get("client_id")[0] == client_id
    assert params.get("client_secret")[0] == client_secret

    assert pool_job.interval == 5
    assert resp is None

    # 2nd attempt: slow down
    resp = pool_job()
    params = parse_qs(requests_mock.last_request.text)
    assert params.get("client_id") == [client_id]
    assert params.get("client_secret") == [client_secret]

    assert pool_job.interval == 10
    assert resp is None

    # 3rd attempt: access token delivered
    resp = pool_job()
    params = parse_qs(requests_mock.last_request.text)
    assert params.get("client_id") == [client_id]
    assert params.get("client_secret") == [client_secret]

    assert not resp.is_expired()


def test_auth_handler(device_authorization_endpoint, client_id, client_secret):
    auth = ClientSecretBasic(client_id, client_secret)
    da_client = DeviceAuthorizationClient(
        device_authorization_endpoint=device_authorization_endpoint,
        auth=auth,
    )

    assert da_client.auth == auth

    da_client = DeviceAuthorizationClient(
        device_authorization_endpoint=device_authorization_endpoint,
        auth=client_id,
    )

    assert isinstance(da_client.auth, PublicApp) and da_client.auth.client_id == client_id


def test_invalid_response(
    requests_mock, device_authorization_endpoint, client_id, client_secret
):

    da_client = DeviceAuthorizationClient(
        device_authorization_endpoint=device_authorization_endpoint,
        auth=(client_id, client_secret),
    )

    requests_mock.post(
        device_authorization_endpoint,
        status_code=500,
        json={"error": "server_error"},
    )
    with pytest.raises(DeviceAuthorizationError):
        da_client.authorize_device()

    requests_mock.post(
        device_authorization_endpoint,
        status_code=500,
        json={"foo": "bar"},
    )
    with pytest.raises(InvalidDeviceAuthorizationResponse):
        da_client.authorize_device()
