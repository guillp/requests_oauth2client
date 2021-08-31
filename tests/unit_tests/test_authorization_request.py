import base64
import hashlib

import pytest
from furl import furl

from requests_oauth2client import AuthorizationRequest, AuthorizationResponseError
from requests_oauth2client.exceptions import MismatchingState, MissingAuthCode
from requests_oauth2client.jwskate import Jwt, SignedJwt


@pytest.fixture(params=[None, {"foo": "bar"}])
def auth_request_kwargs(request):
    return request.param or {}


@pytest.fixture(
    params=[None, "state", True],
)
def state(request):
    return request.param


@pytest.fixture(
    params=[None, "nonce", False],
)
def nonce(request):
    return request.param


@pytest.fixture(
    params=[None, "openid", "openid profile email", ["openid", "profile", "email"], []],
    ids=["None", "unique", "space-separated", "list", "empty-list"],
)
def scope(request):
    return request.param


@pytest.fixture(
    params=[None, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"], ids=["None", "rfc7636"]
)
def code_verifier(request):
    return request.param


@pytest.fixture(params=[None, "plain", "S256"])
def code_challenge_method(request):
    return request.param


@pytest.fixture()
def authorization_request(
    authorization_endpoint,
    client_id,
    redirect_uri,
    scope,
    state,
    nonce,
    code_verifier,
    code_challenge_method,
    auth_request_kwargs,
    authorization_code,
):
    azr = AuthorizationRequest(
        authorization_endpoint=authorization_endpoint,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        state=state,
        nonce=nonce,
        code_verifier=code_verifier,
        code_challenge_method=code_challenge_method,
        **auth_request_kwargs,
    )

    url = furl(str(azr))
    assert url.origin + str(url.path) == authorization_endpoint
    args = dict(url.args)
    expected_args = dict(
        client_id=client_id,
        redirect_uri=redirect_uri,
        response_type="code",
        scope=scope,
        **auth_request_kwargs,
    )

    if nonce is None or nonce is True:
        generated_nonce = args.pop("nonce")
        assert isinstance(generated_nonce, str)
        assert len(generated_nonce) > 20
    elif nonce is False:
        assert "nonce" not in args
    elif isinstance(nonce, str):
        assert args.pop("nonce") == nonce
    else:
        pytest.warns("unexpected nonce type", nonce, type(nonce))

    if state is True:
        generated_state = args.pop("state")
        assert isinstance(generated_state, str)
        assert len(generated_state) > 20
    elif state is False:
        assert "state" not in args
    elif isinstance(state, str):
        assert args.pop("state") == state

    if scope is None:
        assert "scope" not in args
        del expected_args["scope"]
    elif isinstance(scope, list):
        expected_args["scope"] = "+".join(scope)

    if code_challenge_method is None:
        assert "code_challenge_method" not in args
        assert "code_challenge" not in args
    elif code_challenge_method == "S256":
        assert args.pop("code_challenge_method") == "S256"
        generated_code_challenge = args.pop("code_challenge")
        if code_verifier is None:
            assert isinstance(generated_code_challenge, str)
            assert len(generated_code_challenge) == 43
            assert base64.urlsafe_b64decode(
                generated_code_challenge.encode() + b"="
            ), f"Invalid B64U for generated code_challenge: {generated_code_challenge}"
        else:
            assert generated_code_challenge == base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode()).digest()
            ).decode().rstrip("=")
    elif code_challenge_method == "plain":
        assert args.pop("code_challenge_method") == "plain"
        generated_code_challenge = args.pop("code_challenge")
        if code_verifier is None:
            assert isinstance(generated_code_challenge, str)
            assert 43 <= len(generated_code_challenge) <= 128
        else:
            assert generated_code_challenge == code_verifier

    assert args == expected_args

    return azr


def test_validate(authorization_request, authorization_code):
    auth_response = furl(authorization_request.redirect_uri).add(
        args={"code": authorization_code, "state": authorization_request.state}
    )
    assert authorization_request.validate_callback(auth_response) == authorization_code


def test_authorization_url(authorization_request):
    url = furl(str(authorization_request))
    assert dict(url.args) == {
        key: val for key, val in authorization_request.args.items() if val is not None
    }


def test_authorization_signed_request(authorization_request, private_jwk, public_jwk):
    args = {
        key: value for key, value in authorization_request.args.items() if value is not None
    }
    url = furl(str(authorization_request.sign(private_jwk)))
    request = url.args.get("request")
    jwt = Jwt(request)
    assert isinstance(jwt, SignedJwt)
    assert jwt.verify_signature(public_jwk)
    assert jwt.claims == args


@pytest.fixture(params=["consent_required"])
def error(request):
    return request.param


def test_error_response(authorization_request, error):
    auth_response = furl(authorization_request.redirect_uri).add(
        args={"error": error, "state": authorization_request.state}
    )
    with pytest.raises(AuthorizationResponseError):
        authorization_request.validate_callback(auth_response)


def test_missing_code(authorization_request, authorization_code):
    auth_response = furl(authorization_request.redirect_uri).add(
        args={"state": authorization_request.state}
    )
    with pytest.raises(MissingAuthCode):
        assert authorization_request.validate_callback(auth_response) == authorization_code


def test_not_an_url(authorization_request, authorization_code):
    auth_response = "https://...$cz\\1.3ada////:@+++++z/"
    with pytest.raises(ValueError):
        assert authorization_request.validate_callback(auth_response) == authorization_code


def test_mismatching_state(authorization_request, authorization_code, state):
    auth_response = furl(authorization_request.redirect_uri).add(
        args={"code": authorization_code, "state": "foo"}
    )
    if state:
        with pytest.raises(MismatchingState):
            assert authorization_request.validate_callback(auth_response) == authorization_code


def test_missing_state(authorization_request, authorization_code, state):
    auth_response = furl(authorization_request.redirect_uri).add(
        args={"code": authorization_code}
    )
    if state:
        with pytest.raises(MismatchingState):
            assert authorization_request.validate_callback(auth_response) == authorization_code
