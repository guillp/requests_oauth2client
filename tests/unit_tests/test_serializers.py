from datetime import datetime, timedelta, timezone

import pytest
from freezegun.api import FrozenDateTimeFactory

from requests_oauth2client import (
    AuthorizationRequest,
    AuthorizationRequestSerializer,
    BearerToken,
    BearerTokenSerializer,
    DPoPKey,
    DPoPToken,
)


@pytest.mark.parametrize(
    "token",
    [
        BearerToken("access_token"),
        # note that "expires_at" is calculated when the test is ran, so before `freezer` takes effect
        BearerToken("access_token", expires_in=60),
        BearerToken("access_token", expires_in=-60),
        DPoPToken("access_token", _dpop_key=DPoPKey.generate()),
        DPoPToken("access_token", expires_in=60, _dpop_key=DPoPKey.generate()),
        DPoPToken("access_token", expires_in=60, _dpop_key=DPoPKey.generate(alg="RS256")),
    ],
)
def test_token_serializer(token: BearerToken, freezer: FrozenDateTimeFactory) -> None:
    freezer.move_to("2024-08-01")
    serializer = BearerTokenSerializer()
    candidate = serializer.dumps(token)
    freezer.move_to(datetime.now(tz=timezone.utc) + timedelta(days=365))
    assert serializer.loads(candidate) == token


def test_authorization_request_serializer(authorization_request: AuthorizationRequest) -> None:
    serializer = AuthorizationRequestSerializer()
    serialized = serializer.dumps(authorization_request)
    assert serializer.loads(serialized) == authorization_request


def test_authorization_request_serializer_with_dpop_key() -> None:
    dpop_key = DPoPKey.generate()
    authorization_request = AuthorizationRequest(
        "https://as.local/authorize",
        client_id="foo",
        redirect_uri="http://localhost/local",
        scope="openid",
        dpop_key=dpop_key,
    )

    serializer = AuthorizationRequestSerializer()

    serialized = serializer.dumps(authorization_request)
    deserialized_request = serializer.loads(serialized)

    assert isinstance(deserialized_request.dpop_key, DPoPKey)
    assert deserialized_request.dpop_key.private_key == dpop_key.private_key
