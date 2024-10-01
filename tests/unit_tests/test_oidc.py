from __future__ import annotations

import jwskate
import pytest
from freezegun import freeze_time
from jwskate import EncryptionAlgs, InvalidSignature, Jwk, Jwt, KeyManagementAlgs, SignatureAlgs

from requests_oauth2client import (
    AuthorizationResponse,
    BearerToken,
    ExpiredIdToken,
    IdToken,
    InvalidIdToken,
    MismatchingIdTokenAcr,
    MismatchingIdTokenAlg,
    MismatchingIdTokenAudience,
    MismatchingIdTokenAzp,
    MismatchingIdTokenIssuer,
    MismatchingIdTokenNonce,
    MissingIdToken,
    OAuth2Client,
)
from requests_oauth2client.tokens import UnsupportedIdTokenAlg


@freeze_time("2011-07-21 20:42:55")
@pytest.mark.parametrize(
    ("kwargs", "at_hash", "c_hash", "s_hash"),
    [
        (
            {"alg": "PS256"},
            "xsZZrUssMXjL3FBlzoSh2g",
            "LDktKdoQak3Pk0cnXxCltA",
            "GAsHrlqowzjqTW8xW7lyMw",
        ),
        (
            {"alg": "PS384"},
            "adt46pcdiB-l6eTNifgoVM-5AIJAxq84",
            "Mq-knyaEMtWGfnBi2POEZb1kiLx10_DF",
            "IIXrx5-tK3fM7Q80_DbXTWRb6ty48rOd",
        ),
        (
            {"alg": "PS512"},
            "p2LHG4H-8pYDc0hyVOo3iIHvZJUqe9tbj3jESOuXbkY",
            "E9z1C-c0Az4eTEzE0Nm3OQ3BS2BhMgxuP7x5JAQj1_4",
            "aVrO6_zIGuPg0pvBhlmB9jnpmFoY6MXEt1nJeHp1pmI",
        ),
        (
            {"alg": "EdDSA", "crv": "Ed448"},
            "sB_U72jyb0WgtX8TsVoqJnm6CD295W9gfSDRxkilB3LAL7REi9JYutRW_s1yE4lD8cOfMZf83gi4",
            "07UgYISe6yaAzmTIBr_f2vchFCIs6bAGk1-36iEH00fq4B3eBih5g0r_kEPHpuYLqbXOq7gDBVpr",
            "ZPaPdOYbQ2dUGsQZHaSIcIveQMwWh4yG8lMT9Cfa_cSKSO8KGjx4rqI4zwmAfYJ6bPIxZWeUwvUn",
        ),
        (
            {"alg": "EdDSA", "crv": "Ed25519"},
            "p2LHG4H-8pYDc0hyVOo3iIHvZJUqe9tbj3jESOuXbkY",
            "E9z1C-c0Az4eTEzE0Nm3OQ3BS2BhMgxuP7x5JAQj1_4",
            "aVrO6_zIGuPg0pvBhlmB9jnpmFoY6MXEt1nJeHp1pmI",
        ),
    ],
)
def test_validate_id_token(kwargs: dict[str, str], at_hash: str, c_hash: str, s_hash: str) -> None:
    signing_key = jwskate.Jwk.generate(**kwargs).with_kid_thumbprint()
    jwks = signing_key.public_jwk().minimize().as_jwks()
    client_id = "s6BhdRkqt3"
    access_token = "YmJiZTAwYmYtMzgyOC00NzhkLTkyOTItNjJjNDM3MGYzOWIy9sFhvH8K_x8UIHj1osisS57f5DduL"
    code = "Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk"
    state = "qu2pNLwFWBjakH2x4OxivEVtjKiM27SHrPdY3McJN4g"

    nonce = "n-0S6_WzA2Mj"
    id_token = IdToken.sign(
        {
            "iss": "http://server.example.com",
            "sub": "248289761001",
            "aud": client_id,
            "nonce": nonce,
            "exp": 1311281970,
            "iat": 1311280970,
            "c_hash": c_hash,
            "at_hash": at_hash,
            "s_hash": s_hash,
            "auth_time": 1311280970,
        },
        signing_key,
    )
    assert (
        BearerToken(
            access_token=access_token,
            expires_in=60,
            id_token=str(id_token),
        )
        .validate_id_token(
            client=OAuth2Client(
                "https://myas.local/token",
                client_id=client_id,
                authorization_server_jwks=jwks,
                id_token_signed_response_alg=kwargs["alg"],
            ),
            azr=AuthorizationResponse(code=code, nonce=nonce, max_age=0, state=state),
        )
        .id_token
        == id_token
    )

    with pytest.raises(AttributeError, match="auth_time"):
        IdToken.sign(
            {
                "iss": "http://server.example.com",
                "sub": "248289761001",
                "aud": client_id,
                "exp": 1311281970,
                "iat": 1311280970,
            },
            signing_key,
        ).auth_time


def test_invalid_id_token(token_endpoint: str) -> None:
    with pytest.raises(MissingIdToken):
        BearerToken(access_token="an_access_token").validate_id_token(
            client=OAuth2Client(token_endpoint, client_id="client_id"),
            azr=AuthorizationResponse(code="code"),
        )

    with pytest.raises(InvalidIdToken, match="token is neither a JWT or a JWE"):
        BearerToken(access_token="an_access_token", expires_in=60, id_token="foo")

    sig_jwk = Jwk.generate(alg=SignatureAlgs.RS256).with_kid_thumbprint()
    enc_jwk = Jwk.generate(alg=KeyManagementAlgs.ECDH_ES_A256KW, crv="P-256").with_kid_thumbprint()
    as_jwks = sig_jwk.public_jwk().as_jwks()

    issuer = "http://issuer.local"
    client_id = "my_client_id"
    claims = {
        "iss": issuer,
        "sub": "mysub",
        "iat": Jwt.timestamp(),
        "exp": Jwt.timestamp(60),
        "auth_time": Jwt.timestamp(),
    }

    with pytest.raises(InvalidIdToken, match="should be encrypted"):
        BearerToken(access_token="an_access_token", id_token=Jwt.sign(claims, sig_jwk).value).validate_id_token(
            client=OAuth2Client(
                token_endpoint,
                client_id=client_id,
                id_token_encrypted_response_alg=EncryptionAlgs.A256GCM,
            ),
            azr=AuthorizationResponse(code="code"),
        )

    with pytest.raises(InvalidIdToken, match="should be clear-text"):
        BearerToken(
            access_token="an_access_token",
            id_token=Jwt.sign_and_encrypt(
                claims=claims,
                sign_key=sig_jwk,
                enc_key=enc_jwk.public_jwk(),
                enc=EncryptionAlgs.A256GCM,
            ).value,
        ).validate_id_token(
            client=OAuth2Client(token_endpoint, client_id=client_id),
            azr=AuthorizationResponse(code="code"),
        )

    with pytest.raises(InvalidIdToken, match="client does not have a decryption key"):
        BearerToken(
            access_token="an_access_token",
            id_token=Jwt.sign_and_encrypt(
                claims,
                sign_key=sig_jwk,
                enc_key=enc_jwk.public_jwk(),
                enc=EncryptionAlgs.A256GCM,
            ).value,
        ).validate_id_token(
            client=OAuth2Client(
                token_endpoint,
                client_id=client_id,
                id_token_encrypted_response_alg=EncryptionAlgs.A256GCM,
                id_token_decryption_key=None,
            ),
            azr=AuthorizationResponse(code="code"),
        )

    with pytest.raises(InvalidSignature):
        BearerToken(
            access_token="an_access_token",
            id_token=Jwt.sign(
                {
                    "iss": issuer,
                    "aud": client_id,
                    "iat": Jwt.timestamp(),
                    "exp": Jwt.timestamp(60),
                    "azp": client_id,
                },
                sig_jwk,
            ).value[:-8]
            + b"altered-",
        ).validate_id_token(
            client=OAuth2Client(token_endpoint, client_id=client_id, authorization_server_jwks=as_jwks),
            azr=AuthorizationResponse(code="code", issuer=issuer),
        )

    with pytest.raises(InvalidIdToken, match="does not contain an `alg` parameter"):
        BearerToken(
            access_token="an_access_token",
            id_token=Jwt.sign_arbitrary(
                {
                    "iss": issuer,
                    "aud": client_id,
                    "iat": Jwt.timestamp(),
                    "exp": Jwt.timestamp(60),
                    "azp": client_id,
                },
                headers={"kid": sig_jwk.kid},
                key=sig_jwk,
            ).value,
        ).validate_id_token(
            client=OAuth2Client(
                token_endpoint,
                client_id=client_id,
                authorization_server_jwks=as_jwks,
                id_token_signed_response_alg=None,
            ),
            azr=AuthorizationResponse(code="code", issuer=issuer),
        )

    with pytest.raises(UnsupportedIdTokenAlg):
        BearerToken(
            access_token="an_access_token",
            id_token=Jwt.sign_arbitrary(
                {
                    "iss": issuer,
                    "aud": client_id,
                    "iat": Jwt.timestamp(),
                    "exp": Jwt.timestamp(60),
                    "azp": client_id,
                },
                headers={"kid": sig_jwk.kid, "alg": "foobar"},
                key=sig_jwk,
            ).value,
        ).validate_id_token(
            client=OAuth2Client(
                token_endpoint,
                client_id=client_id,
                authorization_server_jwks=as_jwks,
                id_token_signed_response_alg=None,
            ),
            azr=AuthorizationResponse(code="code", issuer=issuer),
        )

    with pytest.raises(MismatchingIdTokenIssuer):
        BearerToken(access_token="an_access_token", id_token=Jwt.sign(claims, sig_jwk).value).validate_id_token(
            client=OAuth2Client(token_endpoint, client_id=client_id, authorization_server_jwks=as_jwks),
            azr=AuthorizationResponse(code="code", issuer="https://a.different.issuer"),
        )

    with pytest.raises(MismatchingIdTokenAudience):
        BearerToken(
            access_token="an_access_token",
            id_token=Jwt.sign(
                {
                    "iss": issuer,
                    "aud": "another_client_id",
                    "iat": Jwt.timestamp(),
                    "exp": Jwt.timestamp(60),
                },
                sig_jwk,
            ).value,
        ).validate_id_token(
            client=OAuth2Client(token_endpoint, client_id=client_id, authorization_server_jwks=as_jwks),
            azr=AuthorizationResponse(code="code", issuer=issuer),
        )

    with pytest.raises(MismatchingIdTokenAzp):
        BearerToken(
            access_token="an_access_token",
            id_token=Jwt.sign(
                {
                    "iss": issuer,
                    "aud": client_id,
                    "iat": Jwt.timestamp(),
                    "exp": Jwt.timestamp(60),
                    "azp": "another_client_id",
                },
                sig_jwk,
            ).value,
        ).validate_id_token(
            client=OAuth2Client(token_endpoint, client_id=client_id, authorization_server_jwks=as_jwks),
            azr=AuthorizationResponse(code="code", issuer=issuer),
        )

    with pytest.raises(ExpiredIdToken):
        BearerToken(
            access_token="an_access_token",
            id_token=Jwt.sign(
                {
                    "iss": issuer,
                    "aud": client_id,
                    "iat": Jwt.timestamp(-120),
                    "exp": Jwt.timestamp(-60),
                    "azp": client_id,
                },
                sig_jwk,
            ).value,
        ).validate_id_token(
            client=OAuth2Client(token_endpoint, client_id=client_id, authorization_server_jwks=as_jwks),
            azr=AuthorizationResponse(code="code", issuer=issuer),
        )

    with pytest.raises(MismatchingIdTokenNonce):
        BearerToken(
            access_token="an_access_token",
            id_token=Jwt.sign(
                {
                    "iss": issuer,
                    "aud": client_id,
                    "iat": Jwt.timestamp(),
                    "exp": Jwt.timestamp(60),
                    "nonce": "another_nonce",
                },
                sig_jwk,
            ).value,
        ).validate_id_token(
            client=OAuth2Client(token_endpoint, client_id=client_id, authorization_server_jwks=as_jwks),
            azr=AuthorizationResponse(code="code", issuer=issuer, nonce="nonce"),
        )

    with pytest.raises(MismatchingIdTokenAcr):
        BearerToken(
            access_token="an_access_token",
            id_token=Jwt.sign(
                {
                    "iss": issuer,
                    "aud": client_id,
                    "iat": Jwt.timestamp(),
                    "exp": Jwt.timestamp(60),
                    "azp": client_id,
                    "acr": "1",
                },
                sig_jwk,
            ).value,
        ).validate_id_token(
            client=OAuth2Client(token_endpoint, client_id=client_id, authorization_server_jwks=as_jwks),
            azr=AuthorizationResponse(code="code", issuer=issuer, acr_values="2 3"),
        )

    with pytest.raises(MismatchingIdTokenAlg):
        BearerToken(
            access_token="an_access_token",
            id_token=Jwt.sign(
                {
                    "iss": issuer,
                    "aud": client_id,
                    "iat": Jwt.timestamp(),
                    "exp": Jwt.timestamp(60),
                    "azp": client_id,
                },
                Jwk.generate(alg=SignatureAlgs.HS256),
            ).value,
        ).validate_id_token(
            client=OAuth2Client(
                token_endpoint,
                client_id=client_id,
                id_token_signed_response_alg=SignatureAlgs.RS256,
                authorization_server_jwks=as_jwks,
            ),
            azr=AuthorizationResponse(code="code", issuer=issuer),
        )

    with pytest.raises(InvalidIdToken, match="does not have a Client Secret"):
        BearerToken(
            access_token="an_access_token",
            id_token=Jwt.sign(
                {
                    "iss": issuer,
                    "aud": client_id,
                    "iat": Jwt.timestamp(),
                    "exp": Jwt.timestamp(60),
                    "azp": client_id,
                },
                Jwk.generate(alg=SignatureAlgs.HS256),
            ).value,
        ).validate_id_token(
            client=OAuth2Client(
                token_endpoint,
                client_id=client_id,
                id_token_signed_response_alg=SignatureAlgs.HS256,
            ),
            azr=AuthorizationResponse(code="code", issuer=issuer),
        )

    with pytest.raises(InvalidIdToken, match="Authorization Server JWKS is not available"):
        BearerToken(
            access_token="an_access_token",
            id_token=Jwt.sign(
                {
                    "iss": issuer,
                    "aud": client_id,
                    "iat": Jwt.timestamp(),
                    "exp": Jwt.timestamp(60),
                    "azp": client_id,
                },
                sig_jwk,
            ).value,
        ).validate_id_token(
            client=OAuth2Client(token_endpoint, client_id=client_id, authorization_server_jwks=None),
            azr=AuthorizationResponse(code="code", issuer=issuer),
        )

    with pytest.raises(InvalidIdToken, match="does not contain a Key ID"):
        BearerToken(
            access_token="an_access_token",
            id_token=Jwt.sign_arbitrary(
                claims={
                    "iss": issuer,
                    "aud": client_id,
                    "iat": Jwt.timestamp(),
                    "exp": Jwt.timestamp(60),
                    "azp": client_id,
                },
                headers={"alg": "RS256"},
                key=sig_jwk,
            ).value,
        ).validate_id_token(
            client=OAuth2Client(
                token_endpoint,
                client_id=client_id,
                authorization_server_jwks=sig_jwk.public_jwk().as_jwks(),
            ),
            azr=AuthorizationResponse(code="code", issuer=issuer),
        )

    with pytest.raises(
        InvalidIdToken,
        match=f"no key\nwith kid='{sig_jwk.kid}' in the Authorization Server JWKS",
    ):
        BearerToken(
            access_token="an_access_token",
            id_token=Jwt.sign(
                {
                    "iss": issuer,
                    "aud": client_id,
                    "iat": Jwt.timestamp(),
                    "exp": Jwt.timestamp(60),
                    "azp": client_id,
                },
                sig_jwk,
            ).value,
        ).validate_id_token(
            client=OAuth2Client(
                token_endpoint,
                client_id=client_id,
                authorization_server_jwks=Jwk.generate(alg=SignatureAlgs.ES256)
                .with_kid_thumbprint()
                .public_jwk()
                .as_jwks(),
            ),
            azr=AuthorizationResponse(code="code", issuer=issuer),
        )

    with pytest.raises(InvalidIdToken, match="mismatching 'at_hash' value"):
        BearerToken(
            access_token="an_access_token",
            id_token=Jwt.sign(
                {
                    "iss": issuer,
                    "aud": client_id,
                    "iat": Jwt.timestamp(),
                    "exp": Jwt.timestamp(60),
                    "azp": client_id,
                    "at_hash": "foo",
                },
                sig_jwk,
            ).value,
        ).validate_id_token(
            client=OAuth2Client(
                token_endpoint,
                client_id=client_id,
                authorization_server_jwks=sig_jwk.public_jwk().as_jwks(),
            ),
            azr=AuthorizationResponse(code="code", issuer=issuer),
        )

    with pytest.raises(InvalidIdToken, match="mismatching 'c_hash' value"):
        BearerToken(
            access_token="an_access_token",
            id_token=Jwt.sign(
                {
                    "iss": issuer,
                    "aud": client_id,
                    "iat": Jwt.timestamp(),
                    "exp": Jwt.timestamp(60),
                    "azp": client_id,
                    "c_hash": "foo",
                },
                sig_jwk,
            ).value,
        ).validate_id_token(
            client=OAuth2Client(
                token_endpoint,
                client_id=client_id,
                authorization_server_jwks=sig_jwk.public_jwk().as_jwks(),
            ),
            azr=AuthorizationResponse(code="code", issuer=issuer),
        )

    with pytest.raises(InvalidIdToken, match="no state was included in the request"):
        BearerToken(
            access_token="an_access_token",
            id_token=Jwt.sign(
                {
                    "iss": issuer,
                    "aud": client_id,
                    "iat": Jwt.timestamp(),
                    "exp": Jwt.timestamp(60),
                    "azp": client_id,
                    "s_hash": "foo",
                },
                sig_jwk,
            ).value,
        ).validate_id_token(
            client=OAuth2Client(
                token_endpoint,
                client_id=client_id,
                authorization_server_jwks=sig_jwk.public_jwk().as_jwks(),
            ),
            azr=AuthorizationResponse(code="code", issuer=issuer),
        )

    with pytest.raises(InvalidIdToken, match="mismatching 's_hash' value"):
        BearerToken(
            access_token="an_access_token",
            id_token=Jwt.sign(
                {
                    "iss": issuer,
                    "aud": client_id,
                    "iat": Jwt.timestamp(),
                    "exp": Jwt.timestamp(60),
                    "azp": client_id,
                    "s_hash": "foo",
                },
                sig_jwk,
            ).value,
        ).validate_id_token(
            client=OAuth2Client(
                token_endpoint,
                client_id=client_id,
                authorization_server_jwks=sig_jwk.public_jwk().as_jwks(),
            ),
            azr=AuthorizationResponse(code="code", issuer=issuer, state="state"),
        )

    with pytest.raises(InvalidIdToken, match="does not contain an `alg` parameter"):
        BearerToken(
            access_token="an_access_token",
            id_token=Jwt.sign_arbitrary(
                claims={
                    "iss": issuer,
                    "aud": client_id,
                    "iat": Jwt.timestamp(),
                    "exp": Jwt.timestamp(60),
                    "azp": client_id,
                    "s_hash": "foo",
                },
                headers={"kid": sig_jwk.kid},
                key=sig_jwk,
            ).value,
        ).validate_id_token(
            client=OAuth2Client(
                token_endpoint,
                client_id=client_id,
                authorization_server_jwks=sig_jwk.public_jwk().as_jwks(),
                id_token_signed_response_alg=None,
            ),
            azr=AuthorizationResponse(code="code", issuer=issuer, state="state"),
        )

    # ID Token signed with alg not supported by verification key
    with pytest.raises(InvalidIdToken, match="algorithm is not supported by the verification key"):
        BearerToken(
            access_token="an_access_token",
            id_token=Jwt.sign_arbitrary(
                headers={"alg": "ES512", "kid": sig_jwk.kid},
                claims={
                    "iss": issuer,
                    "aud": client_id,
                    "iat": Jwt.timestamp(),
                    "exp": Jwt.timestamp(60),
                    "azp": client_id,
                    "s_hash": "foo",
                },
                key=sig_jwk,
            ).value,
        ).validate_id_token(
            client=OAuth2Client(
                token_endpoint,
                client_id=client_id,
                authorization_server_jwks=sig_jwk.public_jwk().as_jwks(),
                id_token_signed_response_alg="ES512",
            ),
            azr=AuthorizationResponse(code="code", issuer=issuer, state="state"),
        )

    # auth_time too old for "max_age" parameter
    with pytest.raises(InvalidIdToken, match="auth_time"):
        BearerToken(
            access_token="an_access_token",
            id_token=Jwt.sign(
                claims={
                    "iss": issuer,
                    "aud": client_id,
                    "iat": Jwt.timestamp(),
                    "exp": Jwt.timestamp(60),
                    "azp": client_id,
                    "auth_time": Jwt.timestamp(-120),
                },
                key=sig_jwk,
            ).value,
        ).validate_id_token(
            client=OAuth2Client(
                token_endpoint,
                client_id=client_id,
                authorization_server_jwks=sig_jwk.public_jwk().as_jwks(),
                id_token_signed_response_alg="RS256",
            ),
            azr=AuthorizationResponse(code="code", issuer=issuer, state="state", max_age=0),
        )

    # missing auth_time in ID Token
    with pytest.raises(InvalidIdToken, match="auth_time"):
        BearerToken(
            access_token="an_access_token",
            id_token=Jwt.sign(
                claims={
                    "iss": issuer,
                    "aud": client_id,
                    "iat": Jwt.timestamp(),
                    "exp": Jwt.timestamp(60),
                    "azp": client_id,
                },
                key=sig_jwk,
            ).value,
        ).validate_id_token(
            client=OAuth2Client(
                token_endpoint,
                client_id=client_id,
                authorization_server_jwks=sig_jwk.public_jwk().as_jwks(),
                id_token_signed_response_alg="RS256",
            ),
            azr=AuthorizationResponse(code="code", issuer=issuer, state="state", max_age=0),
        )


def test_id_token_signed_with_client_secret(token_endpoint: str) -> None:
    client_id = "my_client_id"
    client_secret = "Th1sIs5eCr3t"

    issuer = "http://issuer.local"
    claims = {
        "iss": issuer,
        "sub": "mysub",
        "iat": Jwt.timestamp(),
        "exp": Jwt.timestamp(60),
        "auth_time": Jwt.timestamp(),
        "azr": client_id,
    }

    alg = "HS256"

    BearerToken(
        access_token="access_token",
        id_token=Jwt.sign(claims, key=Jwk.from_cryptography_key(client_secret.encode()), alg=alg).value,
    ).validate_id_token(
        client=OAuth2Client(
            token_endpoint,
            client_id=client_id,
            client_secret=client_secret,
            id_token_signed_response_alg=alg,
        ),
        azr=AuthorizationResponse(code="code", issuer=issuer, state="state"),
    )
