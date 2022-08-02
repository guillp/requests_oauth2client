import secrets

import pytest
from furl import Query  # type: ignore[import]
from requests_mock import Mocker

from requests_oauth2client import (
    BearerToken,
    ClientSecretBasic,
    DeviceAuthorizationError,
    DeviceAuthorizationPoolingJob,
    InvalidDeviceAuthorizationResponse,
    OAuth2Client,
    PublicApp,
)
from tests.conftest import FixtureRequest, join_url


@pytest.fixture(params=["device", "oauth/device"])
def device_authorization_endpoint(request: FixtureRequest, issuer: str) -> str:
    return join_url(issuer, request.param)


@pytest.mark.slow
def test_device_authorization(
    requests_mock: Mocker,
    device_authorization_endpoint: str,
    token_endpoint: str,
    client_id: str,
    client_secret: str,
) -> None:
    device_code = secrets.token_urlsafe()
    user_code = secrets.token_urlsafe(6)
    verification_uri = "https://test.com/verify_device"

    client = OAuth2Client(
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
            "expires_in": 3600,
            "interval": 1,
        },
    )
    device_auth_resp = client.authorize_device()
    assert device_auth_resp.device_code
    assert device_auth_resp.user_code
    assert device_auth_resp.verification_uri
    assert not device_auth_resp.is_expired()

    assert requests_mock.last_request is not None
    params = Query(requests_mock.last_request.text).params
    assert params.get("client_id") == client_id
    assert params.get("client_secret") == client_secret

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

    pool_job = DeviceAuthorizationPoolingJob(
        client,
        device_auth_resp,
        interval=1,
        slow_down_interval=2,
    )

    # 1st attempt: authorization_pending
    resp = pool_job()
    assert requests_mock.last_request is not None
    params = Query(requests_mock.last_request.text).params
    assert params.get("client_id") == client_id
    assert params.get("client_secret") == client_secret

    assert pool_job.interval == 1
    assert resp is None

    # 2nd attempt: slow down
    resp = pool_job()
    assert requests_mock.last_request is not None
    params = Query(requests_mock.last_request.text).params
    assert params.get("client_id") == client_id
    assert params.get("client_secret") == client_secret

    assert pool_job.interval == 3
    assert resp is None

    # 3rd attempt: access token delivered
    resp = pool_job()
    assert isinstance(resp, BearerToken)
    assert requests_mock.last_request is not None
    params = Query(requests_mock.last_request.text).params
    assert params.get("client_id") == client_id
    assert params.get("client_secret") == client_secret

    assert not resp.is_expired()


def test_auth_handler(
    token_endpoint: str,
    device_authorization_endpoint: str,
    client_id: str,
    client_secret: str,
) -> None:
    auth = ClientSecretBasic(client_id, client_secret)
    da_client = OAuth2Client(
        token_endpoint=token_endpoint,
        device_authorization_endpoint=device_authorization_endpoint,
        auth=auth,
    )

    assert da_client.auth == auth

    da_client = OAuth2Client(
        token_endpoint=token_endpoint,
        device_authorization_endpoint=device_authorization_endpoint,
        auth=client_id,
    )

    assert isinstance(da_client.auth, PublicApp) and da_client.auth.client_id == client_id


def test_invalid_response(
    requests_mock: Mocker,
    token_endpoint: str,
    device_authorization_endpoint: str,
    client_id: str,
    client_secret: str,
) -> None:

    da_client = OAuth2Client(
        token_endpoint=token_endpoint,
        device_authorization_endpoint=device_authorization_endpoint,
        auth=(client_id, client_secret),
    )

    requests_mock.post(
        device_authorization_endpoint,
        status_code=500,
        json={"error": "unknown_error"},
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
