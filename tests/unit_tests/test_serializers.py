from datetime import datetime, timedelta, timezone

import pytest
from freezegun.api import FrozenDateTimeFactory

from requests_oauth2client import (
    AuthorizationRequest,
    AuthorizationRequestSerializer,
    BearerToken,
    DPoPKey,
    DPoPToken,
    RequestParameterAuthorizationRequest,
    RequestUriParameterAuthorizationRequest,
    TokenSerializer,
)
from requests_oauth2client.exceptions import UnsupportedTokenTypeError


@pytest.mark.parametrize(
    "token",
    [
        BearerToken("access_token"),
        # note that "expires_at" is calculated when the test is run, so before `freezer` takes effect
        BearerToken("access_token", expires_in=60),
        BearerToken("access_token", expires_in=-60),
        DPoPToken("access_token", _dpop_key=DPoPKey.generate()),
        DPoPToken("access_token", expires_in=60, _dpop_key=DPoPKey.generate()),
        DPoPToken("access_token", expires_in=60, _dpop_key=DPoPKey.generate(alg="RS256")),
    ],
)
def test_token_serializer(token: BearerToken, freezer: FrozenDateTimeFactory) -> None:
    freezer.move_to("2024-08-01")
    serializer = TokenSerializer()
    candidate = serializer.dumps(token)
    freezer.move_to(datetime.now(tz=timezone.utc) + timedelta(days=365))
    assert serializer.loads(candidate) == token


def test_authorization_request_serializer(
    authorization_request: AuthorizationRequest,
    request_parameter_authorization_request: RequestParameterAuthorizationRequest,
) -> None:
    serializer = AuthorizationRequestSerializer()
    serialized = serializer.dumps(authorization_request)
    assert serializer.loads(serialized) == authorization_request

    request_parameter_serialized = serializer.dumps(request_parameter_authorization_request)
    assert serializer.loads(request_parameter_serialized) == request_parameter_authorization_request


@pytest.fixture(
    scope="module", params=["this_is_a_request_uri", "urn:this:is:a:request_uri", "https://foo.bar/request_uri"]
)
def request_uri_authorization_request(
    authorization_endpoint: str, client_id: str, request: pytest.FixtureRequest
) -> RequestUriParameterAuthorizationRequest:
    request_uri = request.param
    return RequestUriParameterAuthorizationRequest(
        authorization_endpoint=authorization_endpoint,
        client_id=client_id,
        request_uri=request_uri,
        custom_param="custom_value",
    )


def test_request_uri_authorization_request_serializer(
    request_uri_authorization_request: RequestUriParameterAuthorizationRequest,
) -> None:
    serializer = AuthorizationRequestSerializer()
    serialized = serializer.dumps(request_uri_authorization_request)
    deserialized = serializer.loads(serialized)
    assert isinstance(deserialized, RequestUriParameterAuthorizationRequest)
    assert deserialized == request_uri_authorization_request


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


def test_unsupported_token_type() -> None:
    class CustomToken(BearerToken):
        TOKEN_TYPE = "CustomToken"

    custom_token = CustomToken(access_token="my_access_token", token_type="CustomToken", custom_key="custom_value")
    serializer = TokenSerializer()
    serialized = serializer.dumps(custom_token)
    assert serializer.loader(serialized) == {
        "access_token": "my_access_token",
        "token_type": "CustomToken",
        "custom_key": "custom_value",
    }  # all attributes are preserved
    with pytest.raises(UnsupportedTokenTypeError):
        serializer.loads(serialized)  # but deserialization fails due to unsupported token type
