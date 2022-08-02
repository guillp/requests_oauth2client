from datetime import datetime
from typing import List, Union

import pytest
from jwskate import Jwk

from requests_oauth2client import (
    BackChannelAuthenticationPoolingJob,
    BackChannelAuthenticationResponse,
    BaseClientAuthenticationMethod,
    BearerToken,
    InvalidBackChannelAuthenticationResponse,
    OAuth2Client,
    UnauthorizedClient,
)
from tests.conftest import RequestsMocker, RequestValidatorType


def test_backchannel_authentication_response(auth_req_id: str) -> None:
    bca_resp = BackChannelAuthenticationResponse(
        auth_req_id=auth_req_id, expires_in=10, interval=10, foo="bar"
    )

    assert bca_resp.auth_req_id == auth_req_id
    assert bca_resp.interval == 10
    assert not bca_resp.is_expired()
    assert isinstance(bca_resp.expires_at, datetime)
    assert isinstance(bca_resp.expires_in, int)
    assert bca_resp.expires_in <= 10
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


@pytest.fixture()
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


def test_backchannel_authentication(
    requests_mock: RequestsMocker,
    backchannel_authentication_endpoint: str,
    bca_client: OAuth2Client,
    auth_req_id: str,
    scope: Union[None, str, List[str]],
    backchannel_auth_request_validator: RequestValidatorType,
) -> None:

    requests_mock.post(
        backchannel_authentication_endpoint,
        json={"auth_req_id": auth_req_id, "expires_in": 360, "interval": 3},
    )
    bca_resp = bca_client.backchannel_authentication_request(
        scope=scope, login_hint="user@example.com"
    )

    assert requests_mock.called_once
    backchannel_auth_request_validator(
        requests_mock.last_request, scope=scope, login_hint="user@example.com"
    )

    assert isinstance(bca_resp, BackChannelAuthenticationResponse)
    assert 355 <= bca_resp.expires_in <= 360


def test_backchannel_authentication_scope_list(
    requests_mock: RequestsMocker,
    backchannel_authentication_endpoint: str,
    bca_client: OAuth2Client,
    auth_req_id: str,
    backchannel_auth_request_validator: RequestValidatorType,
) -> None:
    scope = ["openid", "email", "profile"]
    requests_mock.post(
        backchannel_authentication_endpoint,
        json={"auth_req_id": auth_req_id, "expires_in": 360, "interval": 3},
    )
    bca_resp = bca_client.backchannel_authentication_request(
        scope=scope, login_hint="user@example.com"
    )

    assert requests_mock.called_once
    backchannel_auth_request_validator(
        requests_mock.last_request, scope=scope, login_hint="user@example.com"
    )

    assert isinstance(bca_resp, BackChannelAuthenticationResponse)
    assert 355 <= bca_resp.expires_in <= 360


def test_backchannel_authentication_invalid_response(
    requests_mock: RequestsMocker,
    backchannel_authentication_endpoint: str,
    bca_client: OAuth2Client,
    scope: Union[None, str, List[str]],
    backchannel_auth_request_validator: RequestValidatorType,
) -> None:

    requests_mock.post(
        backchannel_authentication_endpoint,
        json={"foo": "bar"},
    )
    with pytest.raises(InvalidBackChannelAuthenticationResponse):
        bca_client.backchannel_authentication_request(
            scope=scope, login_hint="user@example.com"
        )

    assert requests_mock.called_once
    backchannel_auth_request_validator(
        requests_mock.last_request, scope=scope, login_hint="user@example.com"
    )


def test_backchannel_authentication_jwt(
    requests_mock: RequestsMocker,
    backchannel_authentication_endpoint: str,
    bca_client: OAuth2Client,
    private_jwk: Jwk,
    public_jwk: Jwk,
    auth_req_id: str,
    scope: Union[None, str, List[str]],
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
    scope: Union[None, str, List[str]],
    backchannel_auth_request_validator: RequestValidatorType,
) -> None:

    requests_mock.post(
        backchannel_authentication_endpoint,
        status_code=400,
        json={"error": "unauthorized_client"},
    )
    with pytest.raises(UnauthorizedClient):
        bca_client.backchannel_authentication_request(
            scope=scope, login_hint="user@example.com"
        )

    assert requests_mock.called_once
    backchannel_auth_request_validator(
        requests_mock.last_request, scope=scope, login_hint="user@example.com"
    )


def test_backchannel_authentication_invalid_error(
    requests_mock: RequestsMocker,
    backchannel_authentication_endpoint: str,
    bca_client: OAuth2Client,
    scope: Union[None, str, List[str]],
    backchannel_auth_request_validator: RequestValidatorType,
) -> None:

    requests_mock.post(
        backchannel_authentication_endpoint,
        status_code=400,
        json={"foo": "bar"},
    )
    with pytest.raises(InvalidBackChannelAuthenticationResponse):
        bca_client.backchannel_authentication_request(
            scope=scope, login_hint="user@example.com"
        )

    assert requests_mock.called_once
    backchannel_auth_request_validator(
        requests_mock.last_request, scope=scope, login_hint="user@example.com"
    )


def test_backchannel_authentication_not_json_error(
    requests_mock: RequestsMocker,
    backchannel_authentication_endpoint: str,
    bca_client: OAuth2Client,
    scope: Union[None, str, List[str]],
    backchannel_auth_request_validator: RequestValidatorType,
) -> None:

    requests_mock.post(
        backchannel_authentication_endpoint,
        status_code=400,
        text="Error!",
    )
    with pytest.raises(InvalidBackChannelAuthenticationResponse):
        bca_client.backchannel_authentication_request(
            scope=scope, login_hint="user@example.com"
        )

    assert requests_mock.called_once
    backchannel_auth_request_validator(
        requests_mock.last_request, scope=scope, login_hint="user@example.com"
    )


def test_backchannel_authentication_missing_hint(
    bca_client: OAuth2Client,
    scope: Union[None, str, List[str]],
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
            scope=1.44, login_hint="user@example.net"  # type: ignore[arg-type]
        )


def test_pooling_job(
    requests_mock: RequestsMocker,
    bca_client: OAuth2Client,
    token_endpoint: str,
    auth_req_id: str,
    ciba_request_validator: RequestValidatorType,
    access_token: str,
) -> None:
    job = BackChannelAuthenticationPoolingJob(
        client=bca_client,
        auth_req_id=auth_req_id,
        interval=1,
    )

    requests_mock.post(token_endpoint, status_code=401, json={"error": "authorization_pending"})
    assert job() is None
    assert requests_mock.called_once
    assert job.interval == 1
    ciba_request_validator(requests_mock.last_request, auth_req_id=auth_req_id)

    requests_mock.reset_mock()
    requests_mock.post(token_endpoint, status_code=401, json={"error": "slow_down"})
    assert job() is None
    assert requests_mock.called_once
    assert job.interval == 1 + 5
    ciba_request_validator(requests_mock.last_request, auth_req_id=auth_req_id)

    requests_mock.reset_mock()
    job.interval = 1
    requests_mock.post(token_endpoint, json={"access_token": access_token})
    token = job()
    assert requests_mock.called_once
    ciba_request_validator(requests_mock.last_request, auth_req_id=auth_req_id)
    assert isinstance(token, BearerToken)
    assert token.access_token == access_token


def test_missing_backchannel_authentication_endpoint(
    token_endpoint: str, client_id: str, client_secret: str
) -> None:
    client = OAuth2Client(token_endpoint, (client_id, client_secret))
    with pytest.raises(AttributeError):
        client.backchannel_authentication_request("openid")
