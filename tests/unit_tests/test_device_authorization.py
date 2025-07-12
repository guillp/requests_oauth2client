import time
from datetime import datetime, timezone

import pytest
from freezegun import freeze_time
from freezegun.api import FrozenDateTimeFactory
from pytest_mock import MockerFixture

from requests_oauth2client import (
    BearerToken,
    ClientSecretPost,
    DeviceAuthorizationError,
    DeviceAuthorizationPollingJob,
    DeviceAuthorizationResponse,
    InvalidDeviceAuthorizationResponse,
    OAuth2Client,
    UnauthorizedClient,
)
from tests.conftest import RequestsMocker, RequestValidatorType


def test_device_authorization_response(
    device_code: str,
    user_code: str,
    verification_uri: str,
    verification_uri_complete: str,
) -> None:
    response = DeviceAuthorizationResponse(
        device_code=device_code,
        user_code=user_code,
        verification_uri=verification_uri,
        verification_uri_complete=verification_uri_complete,
        expires_in=180,
        interval=10,
    )

    assert not response.is_expired()
    assert response.device_code == device_code
    assert response.user_code == user_code
    assert response.verification_uri == verification_uri
    assert response.verification_uri_complete == verification_uri_complete
    assert isinstance(response.expires_at, datetime)
    assert response.expires_at > datetime.now(tz=timezone.utc)
    assert response.interval == 10


def test_device_authorization_response_expires_at(
    device_code: str,
    user_code: str,
    verification_uri: str,
    verification_uri_complete: str,
) -> None:
    expires_at = datetime(year=2021, month=1, day=1, hour=0, minute=0, second=0, tzinfo=timezone.utc)
    response = DeviceAuthorizationResponse(
        device_code=device_code,
        user_code=user_code,
        verification_uri=verification_uri,
        verification_uri_complete=verification_uri_complete,
        expires_at=expires_at,
        interval=10,
    )

    assert response.is_expired()
    assert response.device_code == device_code
    assert response.user_code == user_code
    assert response.verification_uri == verification_uri
    assert response.verification_uri_complete == verification_uri_complete
    assert response.expires_at == expires_at
    assert response.interval == 10


def test_device_authorization_response_no_expiration(
    device_code: str,
    user_code: str,
    verification_uri: str,
    verification_uri_complete: str,
) -> None:
    response = DeviceAuthorizationResponse(
        device_code=device_code,
        user_code=user_code,
        verification_uri=verification_uri,
        verification_uri_complete=verification_uri_complete,
        interval=10,
    )

    assert not response.is_expired()
    assert response.device_code == device_code
    assert response.user_code == user_code
    assert response.verification_uri == verification_uri
    assert response.verification_uri_complete == verification_uri_complete
    assert response.expires_at is None
    assert response.interval == 10


@pytest.fixture
def device_authorization_client(
    token_endpoint: str,
    device_authorization_endpoint: str,
    client_id: str,
    client_secret: str,
) -> OAuth2Client:
    client = OAuth2Client(
        token_endpoint=token_endpoint,
        device_authorization_endpoint=device_authorization_endpoint,
        auth=(client_id, client_secret),
    )

    assert client.device_authorization_endpoint == device_authorization_endpoint
    assert isinstance(client.auth, ClientSecretPost)
    assert client.auth.client_id == client_id
    assert client.auth.client_secret == client_secret

    return client


def test_device_authorization_client(
    requests_mock: RequestsMocker,
    device_authorization_client: OAuth2Client,
    device_authorization_endpoint: str,
    device_code: str,
    user_code: str,
    verification_uri: str,
    verification_uri_complete: str,
    client_secret_post_auth_validator: RequestValidatorType,
    client_id: str,
    client_secret: str,
) -> None:
    requests_mock.post(
        device_authorization_endpoint,
        json={
            "device_code": device_code,
            "user_code": user_code,
            "verification_uri": verification_uri,
            "verification_uri_complete": verification_uri_complete,
            "expires_in": 300,
            "interval": 7,
        },
    )

    device_authorization_client.authorize_device()
    assert requests_mock.called_once
    client_secret_post_auth_validator(requests_mock.last_request, client_id=client_id, client_secret=client_secret)


def test_device_authorization_client_error(
    requests_mock: RequestsMocker,
    device_authorization_client: OAuth2Client,
    device_authorization_endpoint: str,
    client_secret_post_auth_validator: RequestValidatorType,
    client_id: str,
    client_secret: str,
) -> None:
    requests_mock.post(
        device_authorization_endpoint,
        status_code=400,
        json={
            "error": "unauthorized_client",
        },
    )

    with pytest.raises(UnauthorizedClient):
        device_authorization_client.authorize_device()
    assert requests_mock.called_once
    client_secret_post_auth_validator(requests_mock.last_request, client_id=client_id, client_secret=client_secret)


def test_device_authorization_invalid_errors(
    requests_mock: RequestsMocker,
    device_authorization_client: OAuth2Client,
    device_authorization_endpoint: str,
    client_secret_post_auth_validator: RequestValidatorType,
    client_id: str,
    client_secret: str,
) -> None:
    requests_mock.post(
        device_authorization_endpoint,
        status_code=400,
        json={
            "error": "foo",
        },
    )

    with pytest.raises(DeviceAuthorizationError):
        device_authorization_client.authorize_device()
    assert requests_mock.called_once
    client_secret_post_auth_validator(requests_mock.last_request, client_id=client_id, client_secret=client_secret)

    requests_mock.reset_mock()
    requests_mock.post(
        device_authorization_endpoint,
        status_code=400,
        json={
            "foo": "bar",
        },
    )

    with pytest.raises(InvalidDeviceAuthorizationResponse):
        device_authorization_client.authorize_device()
    assert requests_mock.called_once
    client_secret_post_auth_validator(requests_mock.last_request, client_id=client_id, client_secret=client_secret)


@freeze_time()
def test_device_authorization_polling_job(
    requests_mock: RequestsMocker,
    token_endpoint: str,
    client_id: str,
    client_secret: str,
    device_code: str,
    device_code_grant_validator: RequestValidatorType,
    access_token: str,
    freezer: FrozenDateTimeFactory,
    mocker: MockerFixture,
) -> None:
    interval = 20
    client = OAuth2Client(token_endpoint, auth=(client_id, client_secret))
    job = DeviceAuthorizationPollingJob(
        client=client,
        device_code=device_code,
        interval=interval,
    )
    assert job.interval == interval
    assert job.slow_down_interval == 5

    assert job == DeviceAuthorizationPollingJob(
        client,
        DeviceAuthorizationResponse(
            device_code=device_code, user_code="foo", verification_uri="https://foo.bar", interval=interval
        ),
    )

    requests_mock.post(token_endpoint, status_code=401, json={"error": "authorization_pending"})
    mocker.patch("time.sleep")

    assert job() is None
    time.sleep.assert_called_once_with(interval)  # type: ignore[attr-defined]
    assert requests_mock.called_once
    assert job.interval == interval
    device_code_grant_validator(requests_mock.last_request, device_code=device_code)

    requests_mock.reset_mock()
    requests_mock.post(token_endpoint, status_code=401, json={"error": "slow_down"})
    time.sleep.reset_mock()  # type: ignore[attr-defined]

    assert job() is None
    time.sleep.assert_called_once_with(interval)  # type: ignore[attr-defined]
    assert requests_mock.called_once
    assert job.interval == interval + job.slow_down_interval
    device_code_grant_validator(requests_mock.last_request, device_code=device_code)

    requests_mock.reset_mock()
    requests_mock.post(token_endpoint, json={"access_token": access_token})
    time.sleep.reset_mock()  # type: ignore[attr-defined]

    token = job()
    time.sleep.assert_called_once_with(interval + job.slow_down_interval)  # type: ignore[attr-defined]
    assert requests_mock.called_once
    assert isinstance(token, BearerToken)
    assert token.access_token == access_token


def test_no_device_authorization_endpoint(token_endpoint: str, client_id: str, client_secret: str) -> None:
    client = OAuth2Client(token_endpoint, (client_id, client_secret))
    with pytest.raises(AttributeError):
        client.authorize_device()
