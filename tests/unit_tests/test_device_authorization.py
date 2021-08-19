from datetime import datetime

import pytest

from requests_oauth2client import (BearerToken, ClientSecretPost, DeviceAuthorizationClient,
                                   DeviceAuthorizationPoolingJob,
                                   InvalidDeviceAuthorizationResponse, OAuth2Client,
                                   UnauthorizedClient)
from requests_oauth2client.device_authorization import DeviceAuthorizationResponse


def test_device_authorization_response(
    device_code, user_code, verification_uri, verification_uri_complete
):

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
    assert response.expires_at > datetime.now()
    assert response.interval == 10


def test_device_authorization_response_expires_at(
    device_code, user_code, verification_uri, verification_uri_complete
):
    expires_at = datetime(year=2021, month=1, day=1, hour=0, minute=0, second=0)
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
    device_code, user_code, verification_uri, verification_uri_complete
):

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


@pytest.fixture()
def device_authorization_client(
    device_authorization_endpoint, client_id, client_secret, device_code
):
    client = DeviceAuthorizationClient(
        device_authorization_endpoint=device_authorization_endpoint,
        auth=(client_id, client_secret),
    )

    assert client.device_authorization_endpoint == device_authorization_endpoint
    assert isinstance(client.auth, ClientSecretPost)
    assert client.auth.client_id == client_id
    assert client.auth.client_secret == client_secret

    return client


def test_device_authorization_client(
    requests_mock,
    device_authorization_client,
    device_authorization_endpoint,
    device_code,
    user_code,
    verification_uri,
    verification_uri_complete,
    client_secret_post_auth_validator,
    client_id,
    client_secret,
):
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
    client_secret_post_auth_validator(
        requests_mock.last_request, client_id=client_id, client_secret=client_secret
    )


def test_device_authorization_client_error(
    requests_mock,
    device_authorization_client,
    device_authorization_endpoint,
    client_secret_post_auth_validator,
    client_id,
    client_secret,
):
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
    client_secret_post_auth_validator(
        requests_mock.last_request, client_id=client_id, client_secret=client_secret
    )


def test_device_authorization_client_error(
    requests_mock,
    device_authorization_client,
    device_authorization_endpoint,
    client_secret_post_auth_validator,
    client_id,
    client_secret,
):
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
    client_secret_post_auth_validator(
        requests_mock.last_request, client_id=client_id, client_secret=client_secret
    )


def test_device_authorization_pooling_job(
    requests_mock,
    token_endpoint,
    client_id,
    client_secret,
    device_code,
    device_code_grant_validator,
    access_token,
):
    client = OAuth2Client(token_endpoint, auth=(client_id, client_secret))
    job = DeviceAuthorizationPoolingJob(
        client=client,
        device_code=device_code,
        interval=1,
    )

    requests_mock.post(token_endpoint, status_code=401, json={"error": "authorization_pending"})
    assert job() is None
    assert requests_mock.called_once
    device_code_grant_validator(requests_mock.last_request, device_code=device_code)

    requests_mock.post(token_endpoint, json={"access_token": access_token})
    token = job()
    assert isinstance(token, BearerToken)
    assert token.access_token == access_token
