from __future__ import annotations

import time
from datetime import datetime
from typing import TYPE_CHECKING

import pytest
from freezegun import freeze_time

from requests_oauth2client import (
    BackChannelAuthenticationPoolingJob,
    BackChannelAuthenticationResponse,
    BaseClientAuthenticationMethod,
    BearerToken,
    InvalidAcrValuesParam,
    InvalidBackChannelAuthenticationResponse,
    OAuth2Client,
    UnauthorizedClient,
)

if TYPE_CHECKING:
    from freezegun.api import FrozenDateTimeFactory
    from jwskate import Jwk
    from pytest_mock import MockerFixture

    from tests.conftest import RequestsMocker, RequestValidatorType


@freeze_time()
def test_backchannel_authentication_response(auth_req_id: str) -> None:
    bca_resp = BackChannelAuthenticationResponse(auth_req_id=auth_req_id, expires_in=10, interval=10, foo="bar")

    assert bca_resp.auth_req_id == auth_req_id
    assert bca_resp.interval == 10
    assert not bca_resp.is_expired()
    assert isinstance(bca_resp.expires_at, datetime)
    assert isinstance(bca_resp.expires_in, int)
    assert bca_resp.expires_in == 10
    assert bca_resp.foo == "bar"
    with pytest.raises(AttributeError):
        bca_resp.notfound


def test_backchannel_authentication_response_defaults(auth_req_id: str) -> None:
    bca_resp = BackChannelAuthenticationResponse(
        auth_req_id=auth_req_id,
    )

    assert bca_resp.auth_req_id == auth_req_id
    assert bca_resp.interval == 20
    assert not bca_resp.is_expired()
    assert bca_resp.expires_at is None
    assert bca_resp.expires_in is None


@pytest.fixture
def bca_client(
    token_endpoint: str,
    backchannel_authentication_endpoint: str,
    client_auth_method: BaseClientAuthenticationMethod,
) -> OAuth2Client:
    bca_client = OAuth2Client(
        token_endpoint=token_endpoint,
        backchannel_authentication_endpoint=backchannel_authentication_endpoint,
        auth=client_auth_method,
    )
    assert bca_client.backchannel_authentication_endpoint == backchannel_authentication_endpoint
    assert bca_client.auth == client_auth_method

    return bca_client


@freeze_time()
def test_backchannel_authentication(
    requests_mock: RequestsMocker,
    backchannel_authentication_endpoint: str,
    bca_client: OAuth2Client,
    auth_req_id: str,
    scope: None | str | list[str],
    backchannel_auth_request_validator: RequestValidatorType,
    ciba_request_validator: RequestValidatorType,
    token_endpoint: str,
    access_token: str,
) -> None:
    requests_mock.post(
        backchannel_authentication_endpoint,
        json={"auth_req_id": auth_req_id, "expires_in": 360, "interval": 3},
    )
    bca_resp = bca_client.backchannel_authentication_request(scope=scope, login_hint="user@example.com")

    assert requests_mock.called_once
    backchannel_auth_request_validator(requests_mock.last_request, scope=scope, login_hint="user@example.com")

    assert isinstance(bca_resp, BackChannelAuthenticationResponse)
    assert bca_resp.expires_in == 360

    requests_mock.post(token_endpoint, json={"access_token": access_token, "token_type": "Bearer"})

    token_resp = bca_client.ciba(bca_resp)
    assert isinstance(token_resp, BearerToken)
    ciba_request_validator(requests_mock.last_request, auth_req_id=auth_req_id)

    requests_mock.reset()
    bca_client.ciba(BackChannelAuthenticationResponse(auth_req_id=auth_req_id))
    assert requests_mock.called_once
    ciba_request_validator(requests_mock.last_request, auth_req_id=auth_req_id)


@freeze_time()
def test_backchannel_authentication_scope_acr_values_as_list(
    requests_mock: RequestsMocker,
    backchannel_authentication_endpoint: str,
    bca_client: OAuth2Client,
    auth_req_id: str,
    backchannel_auth_request_validator: RequestValidatorType,
) -> None:
    scope = ("openid", "email", "profile")
    acr_values = ("reinforced", "strong")

    requests_mock.post(
        backchannel_authentication_endpoint,
        json={"auth_req_id": auth_req_id, "expires_in": 360, "interval": 3},
    )
    bca_resp = bca_client.backchannel_authentication_request(
        scope=scope, acr_values=acr_values, login_hint="user@example.com"
    )

    assert requests_mock.called_once
    backchannel_auth_request_validator(
        requests_mock.last_request, scope=scope, acr_values=acr_values, login_hint="user@example.com"
    )

    assert isinstance(bca_resp, BackChannelAuthenticationResponse)
    assert bca_resp.expires_in == 360

    with pytest.raises(ValueError, match="Invalid 'acr_values'") as exc:
        bca_client.backchannel_authentication_request(login_hint="user@example.net", acr_values=1.44)  # type: ignore[arg-type]
    assert exc.type is InvalidAcrValuesParam


def test_backchannel_authentication_invalid_response(
    requests_mock: RequestsMocker,
    backchannel_authentication_endpoint: str,
    bca_client: OAuth2Client,
    scope: None | str | list[str],
    backchannel_auth_request_validator: RequestValidatorType,
) -> None:
    requests_mock.post(
        backchannel_authentication_endpoint,
        json={"foo": "bar"},
    )
    with pytest.raises(InvalidBackChannelAuthenticationResponse):
        bca_client.backchannel_authentication_request(scope=scope, login_hint="user@example.com")

    assert requests_mock.called_once
    backchannel_auth_request_validator(requests_mock.last_request, scope=scope, login_hint="user@example.com")


def test_backchannel_authentication_jwt(
    requests_mock: RequestsMocker,
    backchannel_authentication_endpoint: str,
    bca_client: OAuth2Client,
    private_jwk: Jwk,
    public_jwk: Jwk,
    auth_req_id: str,
    scope: None | str | list[str],
    backchannel_auth_request_jwt_validator: RequestValidatorType,
) -> None:
    requests_mock.post(
        backchannel_authentication_endpoint,
        json={"auth_req_id": auth_req_id, "expires_in": 360, "interval": 3},
    )
    bca_resp = bca_client.backchannel_authentication_request(
        private_jwk=private_jwk, scope=scope, login_hint="user@example.com", alg="RS256"
    )

    assert requests_mock.called_once
    backchannel_auth_request_jwt_validator(
        requests_mock.last_request,
        public_jwk=public_jwk,
        alg="RS256",
        scope=scope,
        login_hint="user@example.com",
    )

    assert isinstance(bca_resp, BackChannelAuthenticationResponse)


def test_backchannel_authentication_error(
    requests_mock: RequestsMocker,
    backchannel_authentication_endpoint: str,
    bca_client: OAuth2Client,
    scope: None | str | list[str],
    backchannel_auth_request_validator: RequestValidatorType,
) -> None:
    requests_mock.post(
        backchannel_authentication_endpoint,
        status_code=400,
        json={"error": "unauthorized_client"},
    )
    with pytest.raises(UnauthorizedClient):
        bca_client.backchannel_authentication_request(scope=scope, login_hint="user@example.com")

    assert requests_mock.called_once
    backchannel_auth_request_validator(requests_mock.last_request, scope=scope, login_hint="user@example.com")


def test_backchannel_authentication_invalid_error(
    requests_mock: RequestsMocker,
    backchannel_authentication_endpoint: str,
    bca_client: OAuth2Client,
    scope: None | str | list[str],
    backchannel_auth_request_validator: RequestValidatorType,
) -> None:
    requests_mock.post(
        backchannel_authentication_endpoint,
        status_code=400,
        json={"foo": "bar"},
    )
    with pytest.raises(InvalidBackChannelAuthenticationResponse):
        bca_client.backchannel_authentication_request(scope=scope, login_hint="user@example.com")

    assert requests_mock.called_once
    backchannel_auth_request_validator(requests_mock.last_request, scope=scope, login_hint="user@example.com")


def test_backchannel_authentication_not_json_error(
    requests_mock: RequestsMocker,
    backchannel_authentication_endpoint: str,
    bca_client: OAuth2Client,
    scope: None | str | list[str],
    backchannel_auth_request_validator: RequestValidatorType,
) -> None:
    requests_mock.post(
        backchannel_authentication_endpoint,
        status_code=400,
        text="Error!",
    )
    with pytest.raises(InvalidBackChannelAuthenticationResponse):
        bca_client.backchannel_authentication_request(scope=scope, login_hint="user@example.com")

    assert requests_mock.called_once
    backchannel_auth_request_validator(requests_mock.last_request, scope=scope, login_hint="user@example.com")


def test_backchannel_authentication_missing_hint(
    bca_client: OAuth2Client,
    scope: None | str | list[str],
) -> None:
    with pytest.raises(ValueError):
        bca_client.backchannel_authentication_request(scope=scope)

    with pytest.raises(ValueError):
        bca_client.backchannel_authentication_request(
            scope=scope, login_hint="user@example.net", login_hint_token="ABCDEF"
        )


def test_backchannel_authentication_invalid_scope(bca_client: OAuth2Client) -> None:
    with pytest.raises(ValueError):
        bca_client.backchannel_authentication_request(
            scope=1.44,  # type: ignore[arg-type]
            login_hint="user@example.net",
        )


def test_pooling_job(
    requests_mock: RequestsMocker,
    bca_client: OAuth2Client,
    token_endpoint: str,
    auth_req_id: str,
    ciba_request_validator: RequestValidatorType,
    access_token: str,
    freezer: FrozenDateTimeFactory,
    mocker: MockerFixture,
) -> None:
    interval = 20
    job = BackChannelAuthenticationPoolingJob(client=bca_client, auth_req_id=auth_req_id, interval=interval)
    assert job.interval == interval
    assert job.slow_down_interval == 5

    assert job == BackChannelAuthenticationPoolingJob(
        bca_client,
        BackChannelAuthenticationResponse(auth_req_id, interval=interval),
    )

    requests_mock.post(token_endpoint, status_code=401, json={"error": "authorization_pending"})
    mocker.patch("time.sleep")

    assert job() is None
    time.sleep.assert_called_once_with(job.interval)  # type: ignore[attr-defined]
    time.sleep.reset_mock()  # type: ignore[attr-defined]
    assert requests_mock.called_once
    assert job.interval == interval

    ciba_request_validator(requests_mock.last_request, auth_req_id=auth_req_id)

    freezer.tick(job.interval)
    requests_mock.reset_mock()
    requests_mock.post(token_endpoint, status_code=401, json={"error": "slow_down"})

    assert job() is None
    time.sleep.assert_called_once_with(interval)  # type: ignore[attr-defined]
    time.sleep.reset_mock()  # type: ignore[attr-defined]
    assert requests_mock.called_once
    assert job.interval == interval + job.slow_down_interval
    ciba_request_validator(requests_mock.last_request, auth_req_id=auth_req_id)

    freezer.tick(job.interval)
    requests_mock.reset_mock()
    requests_mock.post(token_endpoint, json={"access_token": access_token})

    token = job()
    time.sleep.assert_called_once_with(interval + job.slow_down_interval)  # type: ignore[attr-defined]
    time.sleep.reset_mock()  # type: ignore[attr-defined]
    assert requests_mock.called_once
    assert job.interval == interval + job.slow_down_interval
    ciba_request_validator(requests_mock.last_request, auth_req_id=auth_req_id)
    assert isinstance(token, BearerToken)
    assert token.access_token == access_token


def test_missing_backchannel_authentication_endpoint(token_endpoint: str, client_id: str, client_secret: str) -> None:
    client = OAuth2Client(token_endpoint, (client_id, client_secret))
    with pytest.raises(AttributeError):
        client.backchannel_authentication_request(login_hint="username@foo.bar")
