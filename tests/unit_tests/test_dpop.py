import secrets

import pytest
import requests
from binapy import BinaPy
from freezegun import freeze_time
from jwskate import Jwk, Jwt, SignatureAlgs, SignedJwt

from requests_oauth2client import (
    BearerToken,
    DPoPKey,
    DPoPToken,
    InvalidDPoPAccessToken,
    InvalidDPoPAlg,
    InvalidDPoPKey,
    OAuth2Client,
)
from tests.conftest import RequestsMocker


@pytest.mark.parametrize("alg", SignatureAlgs.ALL_ASYMMETRIC)
def test_dpop_key(alg: str) -> None:
    generated_dpopkey = DPoPKey.generate(alg=alg)
    assert generated_dpopkey.alg == alg

    private_key = Jwk.generate(alg=alg)
    choosen_dpop_key = DPoPKey(private_key=private_key)
    assert choosen_dpop_key.alg == alg
    assert choosen_dpop_key.private_key == private_key

    proof = choosen_dpop_key.proof(htm="POST", htu="https://myapi.local/")
    assert proof.alg == alg

    # you can also init a DPoPKey with any key material supported by `jwskate`
    choosen_dpop_key_cryptography = DPoPKey(private_key=private_key.cryptography_key, alg=alg)
    assert choosen_dpop_key_cryptography.alg == alg
    assert choosen_dpop_key_cryptography.private_key == private_key


@freeze_time()
def test_dpop_client_credentials_request(requests_mock: RequestsMocker) -> None:
    token_endpoint = "https://url.to.the/token_endpoint"
    client = OAuth2Client(
        token_endpoint=token_endpoint, client_id="foo", client_secret="bar", dpop_bound_access_tokens=True
    )

    access_token = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU"
    requests_mock.post(
        token_endpoint,
        json={
            "access_token": access_token,
            "token_type": "DPoP",
            "expires_in": 2677,
            "refresh_token": "Q..Zkm29lexi8VnWg2zPW1x-tgGad0Ibc3s3EwM_Ni4-g",
        },
    )

    dpop_token = client.client_credentials()
    assert isinstance(dpop_token, DPoPToken)
    assert dpop_token.token_type == "DPoP"
    dpop_key = dpop_token.dpop_key
    assert isinstance(dpop_key, DPoPKey)

    assert requests_mock.called_once
    token_request = requests_mock.last_request
    assert token_request is not None
    dpop = Jwt(token_request.headers["DPoP"])
    assert isinstance(dpop, SignedJwt)
    assert dpop.headers == {
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": dpop_key.private_key.public_jwk().minimize(),
    }
    assert dpop.claims["htm"] == "POST"
    assert dpop.claims["htu"] == token_endpoint
    assert dpop.claims["iat"] == Jwt.timestamp()
    assert len(dpop.claims["jti"]) > 16
    assert dpop.verify_signature(dpop_key.private_key)


@pytest.mark.parametrize("alg", SignatureAlgs.ALL_ASYMMETRIC)
def test_dpop_token_api_request(requests_mock: RequestsMocker, alg: str) -> None:
    private_key = Jwk.generate(alg=alg)
    dpop_key = DPoPKey(private_key=private_key)
    access_token = secrets.token_urlsafe(64)
    dpop_token = DPoPToken(access_token=access_token, _dpop_key=dpop_key)

    target_api = "https://my.api/resource"
    requests_mock.put(target_api)
    requests.put(target_api, params={"key": "value"}, auth=dpop_token)
    assert requests_mock.called_once
    api_request = requests_mock.last_request
    assert api_request is not None
    assert api_request.headers["Authorization"] == f"DPoP {access_token}"
    dpop = Jwt(api_request.headers["DPoP"])
    assert isinstance(dpop, SignedJwt)
    assert dpop.headers == {
        "typ": "dpop+jwt",
        "alg": alg,
        "jwk": dpop_token.dpop_key.private_key.public_jwk().minimize(),
    }
    assert dpop.claims["htm"] == "PUT"
    assert dpop.claims["htu"] == target_api  # must not include query parameters or fragment
    assert dpop.claims["iat"] == Jwt.timestamp()
    assert len(dpop.claims["jti"]) > 16
    assert dpop.claims["ath"] == BinaPy(access_token).to("sha256").to("b64u").ascii()
    assert dpop.verify_signature(private_key)


@freeze_time()
def test_dpop_access_token_request_with_choosen_key(requests_mock: RequestsMocker) -> None:
    dpop_alg = "ES512"
    private_key = Jwk.generate(alg=dpop_alg)
    dpop_key = DPoPKey(private_key=private_key)
    token_endpoint = "https://url.to.the/token_endpoint"
    client = OAuth2Client(
        token_endpoint=token_endpoint, client_id="foo", client_secret="bar", dpop_bound_access_tokens=True
    )

    requests_mock.post(
        token_endpoint,
        json={
            "access_token": "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU",
            "token_type": "DPoP",
            "expires_in": 2677,
            "refresh_token": "Q..Zkm29lexi8VnWg2zPW1x-tgGad0Ibc3s3EwM_Ni4-g",
        },
    )

    dpop_token = client.client_credentials(dpop_key=dpop_key)
    assert isinstance(dpop_token, DPoPToken)
    assert dpop_token.token_type == "DPoP"
    assert dpop_token.dpop_key == dpop_key

    assert requests_mock.called_once
    token_request = requests_mock.last_request
    assert token_request is not None
    dpop = Jwt(token_request.headers["DPoP"])
    assert isinstance(dpop, SignedJwt)
    assert dpop.headers == {"typ": "dpop+jwt", "alg": dpop_alg, "jwk": private_key.public_jwk().minimize()}
    assert dpop.claims["htm"] == "POST"
    assert dpop.claims["htu"] == token_endpoint
    assert dpop.claims["iat"] == Jwt.timestamp()
    assert len(dpop.claims["jti"]) > 16

    requests_mock.post(
        token_endpoint,
        json={
            "access_token": "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU",
            "token_type": "Bearer",
            "expires_in": 2677,
            "refresh_token": "Q..Zkm29lexi8VnWg2zPW1x-tgGad0Ibc3s3EwM_Ni4-g",
        },
    )

    with pytest.warns(match="DPoP is disabled for that request"):
        assert isinstance(client.client_credentials(dpop=False, dpop_key=dpop_key), BearerToken)


def test_dpop_proof() -> None:
    key = DPoPKey.generate(alg="ES256")
    htm = "GET"
    htu = "https://myapi.local"
    nonce = "this_is_a_nonce"
    ath = "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo"
    proof = key.proof(htm=htm, htu=htu, ath=ath, nonce=nonce)
    assert proof.claims["htm"] == htm
    assert proof.claims["htu"] == htu
    assert proof.claims["nonce"] == nonce
    assert proof.claims["ath"] == ath
    assert proof.verify_signature(key.private_key.public_jwk())


def test_dpop_errors() -> None:
    with pytest.raises(InvalidDPoPAccessToken, match="invalid characters"):
        DPoPToken(access_token="some_invalid_characters_follow: ?%", _dpop_key=DPoPKey.generate(alg="ES256"))

    with pytest.raises(InvalidDPoPAlg, match="DPoP proofing require an asymmetric signing alg."):
        DPoPToken(access_token="access_token", _dpop_key=DPoPKey.generate(alg="HS256"))

    with pytest.raises(InvalidDPoPKey, match="not an asymmetric private key"):
        DPoPKey(private_key=Jwk.generate(alg="HS256"))
