"""An attempt to use old class names should generate DeprecationWarning."""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING

import pytest

from requests_oauth2client import (
    DeviceAuthorizationPoolingJob,  # old spelling
    OAuth2Client,
)
from tests.utils import join_url

if TYPE_CHECKING:
    from tests.utils import FixtureRequest, RequestsMocker


@pytest.fixture(params=["device", "oauth/device"])
def device_authorization_endpoint(request: FixtureRequest, issuer: str) -> str:
    return join_url(issuer, request.param)


def test_device_authorization_deprecated(
    requests_mock: RequestsMocker,
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
    requests_mock.post(
        token_endpoint,
        [
            {"json": {"error": "authorization_pending"}, "status_code": 400},
        ],
    )

    with pytest.deprecated_call():
        DeviceAuthorizationPoolingJob(
            client,
            device_auth_resp,
            interval=1,
            slow_down_interval=2,
        )
