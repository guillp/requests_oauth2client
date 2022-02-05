import base64
import hashlib
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

import pytest
from furl import furl  # type: ignore

from requests_oauth2client import (
    AuthorizationRequest,
    AuthorizationResponse,
    AuthorizationResponseError,
    Jwk,
    Jwt,
    MismatchingIssuer,
    MismatchingState,
    MissingAuthCode,
    SignedJwt,
)
from tests.conftest import FixtureRequest


@pytest.fixture(scope="session", params=[None, {"foo": "bar"}])
def auth_request_kwargs(request: FixtureRequest) -> Dict[str, Any]:
    return request.param or {}  # type: ignore


@pytest.fixture(
    scope="session",
    params=[None, "state", True],
)
def state(request: FixtureRequest) -> Union[None, bool, str]:
    return request.param


@pytest.fixture(scope="session", params=[None, "https://myas.local", False])
def expected_issuer(request: FixtureRequest) -> Optional[str]:
    return request.param


@pytest.fixture(
    scope="session",
    params=[None, "nonce", False],
)
def nonce(request: FixtureRequest) -> Union[None, bool, str]:
    return request.param


@pytest.fixture(
    scope="session",
    params=[None, "openid", "openid profile email", ["openid", "profile", "email"], []],
    ids=["None", "unique", "space-separated", "list", "empty-list"],
)
def scope(request: FixtureRequest) -> Union[None, str, List[str]]:
    return request.param


@pytest.fixture(
    scope="session",
    params=[None, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"],
    ids=["None", "rfc7636"],
)
def code_verifier(request: FixtureRequest) -> Optional[str]:
    return request.param


@pytest.fixture(scope="session", params=[None, "plain", "S256"])
def code_challenge_method(request: FixtureRequest) -> Optional[str]:
    return request.param


@pytest.fixture(scope="session")
@pytest.mark.slow
def authorization_request(
    authorization_endpoint: str,
    client_id: str,
    redirect_uri: str,
    scope: Union[None, str, List[str]],
    state: Union[None, bool, str],
    nonce: Union[None, bool, str],
    code_verifier: str,
    code_challenge_method: str,
    expected_issuer: Union[str, bool, None],
    auth_request_kwargs: Dict[str, Any],
) -> AuthorizationRequest:
    azr = AuthorizationRequest(
        authorization_endpoint=authorization_endpoint,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        state=state,
        nonce=nonce,
        code_verifier=code_verifier,
        code_challenge_method=code_challenge_method,
        issuer=expected_issuer,
        **auth_request_kwargs,
    )

    url = furl(str(azr))
    assert url.origin + str(url.path) == authorization_endpoint

    assert azr.authorization_endpoint == authorization_endpoint
    assert azr.client_id == client_id
    assert azr.redirect_uri == redirect_uri
    assert azr.issuer == expected_issuer
    assert azr.kwargs == auth_request_kwargs

    args = dict(url.args)
    expected_args = dict(
        client_id=client_id,
        redirect_uri=redirect_uri,
        response_type="code",
        scope=scope,
        **auth_request_kwargs,
    )

    if nonce is True:
        generated_nonce = args.pop("nonce")
        assert isinstance(generated_nonce, str)
        assert len(generated_nonce) > 20
        assert azr.nonce == generated_nonce
    elif nonce is False or nonce is None:
        assert azr.nonce is None
        assert "nonce" not in args
    elif isinstance(nonce, str):
        assert azr.nonce == nonce
        assert args.pop("nonce") == nonce
    else:
        assert False

    if state is True:
        generated_state = args.pop("state")
        assert isinstance(generated_state, str)
        assert len(generated_state) > 20
        assert azr.state == generated_state
    elif state is False:
        assert "state" not in args
        assert azr.state is None
    elif isinstance(state, str):
        assert args.pop("state") == state
        assert azr.state == state

    if scope is None:
        assert azr.scope is None
        assert "scope" not in args
        del expected_args["scope"]
    elif isinstance(scope, list):
        joined_scope = " ".join(scope)
        expected_args["scope"] = joined_scope
        assert azr.scope == joined_scope
    if isinstance(scope, str):
        expected_args["scope"] = scope
        assert azr.scope == scope

    if code_challenge_method is None:
        assert "code_challenge_method" not in args
        assert "code_challenge" not in args
        assert azr.code_challenge_method is None
        assert azr.code_verifier is None
        assert azr.code_challenge is None
    elif code_challenge_method == "S256":
        assert azr.code_challenge_method == "S256"
        assert args.pop("code_challenge_method") == "S256"
        generated_code_challenge = args.pop("code_challenge")
        assert azr.code_challenge == generated_code_challenge
        if code_verifier is None:
            assert isinstance(generated_code_challenge, str)
            assert len(generated_code_challenge) == 43
            assert base64.urlsafe_b64decode(
                generated_code_challenge.encode() + b"="
            ), f"Invalid B64U for generated code_challenge: {generated_code_challenge}"
        else:
            assert azr.code_verifier == code_verifier
            assert generated_code_challenge == base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode()).digest()
            ).decode().rstrip("=")
    elif code_challenge_method == "plain":
        assert azr.code_challenge_method == "plain"
        assert args.pop("code_challenge_method") == "plain"
        generated_code_challenge = args.pop("code_challenge")
        assert azr.code_challenge == generated_code_challenge
        if code_verifier is None:
            assert isinstance(generated_code_challenge, str)
            assert 43 <= len(generated_code_challenge) <= 128
        else:
            assert generated_code_challenge == code_verifier
            assert azr.code_verifier == code_verifier

    assert args == expected_args

    return azr


@pytest.fixture()
def authorization_response_uri(
    authorization_request: AuthorizationRequest,
    redirect_uri: str,
    authorization_code: str,
    expected_issuer: Union[str, bool, None],
) -> furl:
    auth_url = furl(redirect_uri).add(args={"code": authorization_code})
    if state is not None:
        auth_url.add(args={"state": authorization_request.state})
    if expected_issuer:
        auth_url.add(args={"iss": expected_issuer})

    return auth_url


def test_validate_callback(
    authorization_request: AuthorizationRequest,
    authorization_response_uri: furl,
    redirect_uri: str,
    authorization_code: str,
) -> None:
    auth_response = authorization_request.validate_callback(authorization_response_uri)
    assert isinstance(auth_response, AuthorizationResponse)
    assert auth_response.code == authorization_code
    assert auth_response.state == authorization_request.state
    assert auth_response.redirect_uri == redirect_uri
    assert auth_response.code_verifier == authorization_request.code_verifier


def test_authorization_url(authorization_request: AuthorizationRequest) -> None:
    url = furl(str(authorization_request))
    assert dict(url.args) == {
        key: val for key, val in authorization_request.args.items() if val is not None
    }


def test_authorization_signed_request(
    authorization_request: AuthorizationRequest, private_jwk: Jwk, public_jwk: Jwk
) -> None:
    args = {
        key: value
        for key, value in authorization_request.args.items()
        if value is not None
    }
    url = furl(str(authorization_request.sign(private_jwk)))
    request = url.args.get("request")
    jwt = Jwt(request)
    assert isinstance(jwt, SignedJwt)
    assert jwt.verify_signature(public_jwk)
    assert jwt.claims == args


@pytest.fixture(params=["consent_required"])
def error(request: FixtureRequest) -> str:
    return request.param


def test_error_response(
    authorization_request: AuthorizationRequest,
    authorization_response_uri: furl,
    error: str,
) -> None:
    authorization_response_uri.args.pop("code")
    authorization_response_uri.args.add("error", error)
    with pytest.raises(AuthorizationResponseError):
        authorization_request.validate_callback(authorization_response_uri)


def test_missing_code(
    authorization_request: AuthorizationRequest, authorization_response_uri: furl
) -> None:
    authorization_response_uri.args.pop("code")
    with pytest.raises(MissingAuthCode):
        authorization_request.validate_callback(authorization_response_uri)


def test_not_an_url(authorization_request: AuthorizationRequest) -> None:
    auth_response = "https://...$cz\\1.3ada////:@+++++z/"
    with pytest.raises(ValueError):
        authorization_request.validate_callback(auth_response)


def test_mismatching_state(
    authorization_request: AuthorizationRequest,
    authorization_response_uri: furl,
    state: Union[None, bool, str],
) -> None:
    authorization_response_uri.args["state"] = "foo"
    if state:
        with pytest.raises(MismatchingState):
            authorization_request.validate_callback(authorization_response_uri)


def test_missing_state(
    authorization_request: AuthorizationRequest,
    authorization_response_uri: furl,
    state: Union[None, bool, str],
) -> None:
    authorization_response_uri.args.pop("state", None)
    if state:
        with pytest.raises(MismatchingState):
            authorization_request.validate_callback(authorization_response_uri)


def test_mismatching_iss(
    authorization_request: AuthorizationRequest,
    authorization_response_uri: furl,
    expected_issuer: Union[str, bool, None],
) -> None:
    authorization_response_uri.args["iss"] = "foo"
    if isinstance(expected_issuer, str) or expected_issuer is False:
        with pytest.raises(MismatchingIssuer):
            authorization_request.validate_callback(authorization_response_uri)


def test_missing_issuer(
    authorization_request: AuthorizationRequest,
    authorization_response_uri: furl,
    expected_issuer: Union[str, bool, None],
) -> None:
    authorization_response_uri.args.pop("iss", None)
    if expected_issuer:
        with pytest.raises(MismatchingIssuer):
            authorization_request.validate_callback(authorization_response_uri)
