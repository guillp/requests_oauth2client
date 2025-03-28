from __future__ import annotations

from typing import TYPE_CHECKING, Any

import jwskate
import pytest
from freezegun import freeze_time
from jwskate import JweCompact, Jwk, Jwt, SignedJwt

from requests_oauth2client import (
    AuthorizationRequest,
    AuthorizationRequestSerializer,
    AuthorizationResponse,
    AuthorizationResponseError,
    DPoPKey,
    InvalidMaxAgeParam,
    MismatchingIssuer,
    MismatchingState,
    MissingAuthCode,
    MissingIssuer,
    RequestParameterAuthorizationRequest,
    RequestUriParameterAuthorizationRequest,
    UnsupportedResponseTypeParam,
)

if TYPE_CHECKING:
    from furl import furl  # type: ignore[import-untyped]


def test_authorization_url(authorization_request: AuthorizationRequest) -> None:
    url = authorization_request.furl
    assert dict(url.args) == {key: val for key, val in authorization_request.args.items() if val is not None}


def test_authorization_signed_request(
    authorization_request: AuthorizationRequest, private_jwk: Jwk, public_jwk: Jwk, auth_request_kwargs: dict[str, Any]
) -> None:
    args = {key: value for key, value in authorization_request.args.items() if value is not None}
    signed_request = authorization_request.sign(private_jwk, custom_attr="custom_value")
    assert isinstance(signed_request, RequestParameterAuthorizationRequest)
    assert isinstance(signed_request.uri, str)
    assert signed_request.custom_attr == "custom_value"
    url = signed_request.furl
    request = url.args.get("request")
    jwt = Jwt(request)
    assert isinstance(jwt, SignedJwt)
    assert jwt.verify_signature(public_jwk)
    assert jwt.claims == args


@freeze_time("2022-10-10 13:37:00")
def test_authorization_signed_request_with_lifetime(
    authorization_request: AuthorizationRequest, private_jwk: Jwk, public_jwk: Jwk
) -> None:
    args = {key: value for key, value in authorization_request.args.items() if value is not None}
    args["iat"] = 1665409020
    args["exp"] = 1665409080
    signed_request = authorization_request.sign(private_jwk, lifetime=60)
    assert isinstance(signed_request.uri, str)

    url = signed_request.furl
    request = url.args.get("request")
    jwt = Jwt(request)
    assert isinstance(jwt, SignedJwt)
    assert jwt.verify_signature(public_jwk)
    assert jwt.claims == args


@pytest.fixture(scope="session")
def enc_jwk() -> Jwk:
    return Jwk.generate_for_alg(jwskate.KeyManagementAlgs.RSA_OAEP_256)


@freeze_time("2022-10-10 13:37:00")
def test_authorization_signed_and_encrypted_request(
    authorization_request: AuthorizationRequest, private_jwk: Jwk, public_jwk: Jwk, enc_jwk: Jwk
) -> None:
    args = {key: value for key, value in authorization_request.args.items() if value is not None}
    args["iat"] = 1665409020
    args["exp"] = 1665409080
    signed_and_encrypted_request = authorization_request.sign_and_encrypt(
        sign_jwk=private_jwk, enc_jwk=enc_jwk.public_jwk(), lifetime=60
    )
    assert isinstance(signed_and_encrypted_request.uri, str)
    url = signed_and_encrypted_request.furl
    request = url.args.get("request")
    jwt = Jwt(request)
    assert isinstance(jwt, JweCompact)
    assert Jwt.decrypt_and_verify(jwt, enc_jwk, public_jwk).claims == args


@pytest.mark.parametrize("request_uri", ["this_is_a_request_uri", "https://foo.bar/request_uri"])
def test_request_uri_authorization_request(authorization_endpoint: str, client_id: str, request_uri: str) -> None:
    request_uri_azr = RequestUriParameterAuthorizationRequest(
        authorization_endpoint=authorization_endpoint,
        client_id=client_id,
        request_uri=request_uri,
        custom_param="custom_value",
    )
    assert isinstance(request_uri_azr.uri, str)
    url = request_uri_azr.furl
    assert url.origin + str(url.path) == authorization_endpoint
    assert url.args == {"client_id": client_id, "request_uri": request_uri, "custom_param": "custom_value"}
    assert request_uri_azr.custom_param == "custom_value"


def test_request_uri_authorization_request_with_custom_param(authorization_endpoint: str) -> None:
    request_uri = "request_uri"
    custom_attr = "custom_attr"
    client_id = "client_id"
    request_uri_azr = RequestUriParameterAuthorizationRequest(
        authorization_endpoint=authorization_endpoint,
        client_id=client_id,
        request_uri=request_uri,
        custom_attr=custom_attr,
    )
    assert isinstance(request_uri_azr.uri, str)
    url = request_uri_azr.furl
    assert url.origin + str(url.path) == authorization_endpoint
    assert url.args == {"client_id": client_id, "request_uri": request_uri, "custom_attr": custom_attr}


@pytest.mark.parametrize("error", ["consent_required"])
def test_error_response(
    authorization_request: AuthorizationRequest,
    authorization_response_uri: furl,
    error: str,
) -> None:
    authorization_response_uri.args.pop("code")
    authorization_response_uri.args.add("error", error)
    with pytest.raises(AuthorizationResponseError):
        authorization_request.validate_callback(authorization_response_uri)


def test_missing_code(authorization_request: AuthorizationRequest, authorization_response_uri: furl) -> None:
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
    state: None | bool | str,
) -> None:
    authorization_response_uri.args["state"] = "foo"
    if state:
        with pytest.raises(MismatchingState):
            authorization_request.validate_callback(authorization_response_uri)


def test_missing_state(
    authorization_request: AuthorizationRequest,
    authorization_response_uri: furl,
    state: None | bool | str,
) -> None:
    authorization_response_uri.args.pop("state", None)
    if state:
        with pytest.raises(MismatchingState):
            authorization_request.validate_callback(authorization_response_uri)


def test_mismatching_iss(
    authorization_request: AuthorizationRequest,
    authorization_response_uri: furl,
    expected_issuer: str | bool | None,
) -> None:
    authorization_response_uri.args["iss"] = "foo"
    if expected_issuer:
        with pytest.raises(MismatchingIssuer):
            authorization_request.validate_callback(authorization_response_uri)


def test_missing_issuer(
    authorization_request: AuthorizationRequest,
    authorization_response_uri: furl,
    expected_issuer: str | bool | None,
) -> None:
    authorization_response_uri.args.pop("iss", None)
    if expected_issuer:
        with pytest.raises(MissingIssuer):
            authorization_request.validate_callback(authorization_response_uri)


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


def test_request_acr_values() -> None:
    # you may provide acr_values as a space separated list or as a real list
    assert AuthorizationRequest(
        "https://as.local/authorize",
        client_id="foo",
        redirect_uri="http://localhost/local",
        scope="openid",
        acr_values="1 2 3",
    ).acr_values == ("1", "2", "3")
    assert AuthorizationRequest(
        "https://as.local/authorize",
        client_id="foo",
        redirect_uri="http://localhost/local",
        scope="openid",
        acr_values=("1", "2", "3"),
    ).acr_values == ("1", "2", "3")


def test_code_challenge() -> None:
    # providing a code_challenge fails, you must provide the original code_verifier instead
    with pytest.raises(ValueError):
        AuthorizationRequest(
            "https://as.local/authorize",
            client_id="foo",
            redirect_uri="http://localhost/local",
            scope="openid",
            code_challenge="my_code_challenge",
        )


def test_issuer_parameter() -> None:
    with pytest.raises(ValueError, match="issuer"):
        AuthorizationRequest(
            "https://as.local/authorize",
            client_id="foo",
            redirect_uri="http://localhost/local",
            authorization_response_iss_parameter_supported=True,
            scope="openid",
        )


def test_invalid_max_age() -> None:
    with pytest.raises(ValueError, match="Invalid 'max_age' parameter") as exc:
        AuthorizationRequest(
            "https://as.local/authorize",
            client_id="foo",
            redirect_uri="http://localhost/local",
            scope="openid",
            max_age=-1,
        )
    assert exc.type is InvalidMaxAgeParam


def test_acr_values() -> None:
    acr_values = ("reinforced", "strong")
    assert (
        AuthorizationResponse(
            code="code",
            client_id="foo",
            redirect_uri="http://localhost/local",
            scope="openid",
            acr_values=list(acr_values),
        ).acr_values
        == acr_values
    )
    assert (
        AuthorizationResponse(
            code="code",
            client_id="foo",
            redirect_uri="http://localhost/local",
            scope="openid",
            acr_values=" ".join(acr_values),
        ).acr_values
        == acr_values
    )


def test_custom_attrs() -> None:
    custom = "foobar"
    azresp = AuthorizationResponse(
        code="code", client_id="foo", redirect_uri="http://localhost/local", scope="openid", custom=custom
    )
    assert azresp.custom == custom


def test_request_as_dict() -> None:
    assert AuthorizationRequest(
        "https://authorization.endpoint",
        client_id="foo",
        redirect_uri="http://localhost/local",
        scope="openid",
        acr_values="1 2 3",
        customattr="customvalue",
        code_verifier="Jdvs0V61iQz3TGoPP_wjwPUIUHPZ7KYDXnQVKJ3f63MvDFhKFMLusp2JOZKoHEUizGvC5xUWlr4m8FemSvo7gERO8b3G87hB-oOGogPiqmTh_c_ISiDpFENXiFNDaAH3",
        nonce="mynonce",
        state="mystate",
        issuer="https://my.issuer",
        authorization_response_iss_parameter_supported=True,
        max_age=0,
    ).as_dict() == {
        "authorization_endpoint": "https://authorization.endpoint",
        "client_id": "foo",
        "redirect_uri": "http://localhost/local",
        "response_type": "code",
        "scope": ("openid",),
        "acr_values": ("1", "2", "3"),
        "code_verifier": "Jdvs0V61iQz3TGoPP_wjwPUIUHPZ7KYDXnQVKJ3f63MvDFhKFMLusp2JOZKoHEUizGvC5xUWlr4m8FemSvo7gERO8b3G87hB-oOGogPiqmTh_c_ISiDpFENXiFNDaAH3",
        "code_challenge_method": "S256",
        "nonce": "mynonce",
        "state": "mystate",
        "issuer": "https://my.issuer",
        "authorization_response_iss_parameter_supported": True,
        "max_age": 0,
        "customattr": "customvalue",
        "dpop_key": None,
    }


def test_unsupported_response_type() -> None:
    with pytest.raises(UnsupportedResponseTypeParam):
        AuthorizationRequest("https://as.local/authorize", client_id="client_id", response_type="token")
