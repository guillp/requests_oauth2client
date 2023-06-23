from typing import Dict

import jwskate
import pytest
from freezegun import freeze_time
from jwskate import EncryptionAlgs, Jwk, Jwt, KeyManagementAlgs, SignatureAlgs

from requests_oauth2client import (
    AuthorizationResponse,
    BearerToken,
    IdToken,
    InvalidIdToken,
    MismatchingIssuer,
    OAuth2Client,
)
from requests_oauth2client.exceptions import (
    ExpiredIdToken,
    MismatchingAcr,
    MismatchingAudience,
    MismatchingAzp,
    MismatchingIdTokenAlg,
    MismatchingNonce,
    MissingIdToken,
)

ID_TOKEN = (
    "eyJraWQiOiIxZTlnZGs3IiwiYWxnIjoiUlMyNTYifQ.ewogIml"
    "zcyI6ICJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwKICJzdWIiOiAiMjQ"
    "4Mjg5NzYxMDAxIiwKICJhdWQiOiAiczZCaGRSa3F0MyIsCiAibm9uY2UiOiA"
    "ibi0wUzZfV3pBMk1qIiwKICJleHAiOiAxMzExMjgxOTcwLAogImlhdCI6IDE"
    "zMTEyODA5NzAsCiAiY19oYXNoIjogIkxEa3RLZG9RYWszUGswY25YeENsdEE"
    "iCn0.XW6uhdrkBgcGx6zVIrCiROpWURs-4goO1sKA4m9jhJIImiGg5muPUcN"
    "egx6sSv43c5DSn37sxCRrDZZm4ZPBKKgtYASMcE20SDgvYJdJS0cyuFw7Ijp"
    "_7WnIjcrl6B5cmoM6ylCvsLMwkoQAxVublMwH10oAxjzD6NEFsu9nipkszWh"
    "sPePf_rM4eMpkmCbTzume-fzZIi5VjdWGGEmzTg32h3jiex-r5WTHbj-u5HL"
    "7u_KP3rmbdYNzlzd1xWRYTUs4E8nOTgzAUwvwXkIQhOh5TPcSMBYy6X3E7-_"
    "gr9Ue6n4ND7hTFhtjYs3cjNKIA08qm5cpVYFMFMG6PkhzLQ"
)


@freeze_time("2011-07-21 20:42:55")
@pytest.mark.parametrize(
    "kwargs, at_hash",
    (
        ({"alg": "PS256"}, "xsZZrUssMXjL3FBlzoSh2g"),
        ({"alg": "PS384"}, "adt46pcdiB-l6eTNifgoVM-5AIJAxq84"),
        ({"alg": "PS512"}, "p2LHG4H-8pYDc0hyVOo3iIHvZJUqe9tbj3jESOuXbkY"),
        (
            {"alg": "EdDSA", "crv": "Ed448"},
            "sB_U72jyb0WgtX8TsVoqJnm6CD295W9gfSDRxkilB3LAL7REi9JYutRW_s1yE4lD8cOfMZf83gi4",
        ),
    ),
)
def test_validate_id_token(kwargs: Dict[str, str], at_hash: str) -> None:
    signing_key = jwskate.Jwk.generate(**kwargs).with_kid_thumbprint()
    client_id = "s6BhdRkqt3"
    access_token = (
        "YmJiZTAwYmYtMzgyOC00NzhkLTkyOTItNjJjNDM3MGYzOWIy9sFhvH8K_x8UIHj1osisS57f5DduL"
    )
    code = "Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk"
    nonce = "n-0S6_WzA2Mj"
    id_token = IdToken.sign(
        {
            "iss": "http://server.example.com",
            "sub": "248289761001",
            "aud": client_id,
            "nonce": nonce,
            "exp": 1311281970,
            "iat": 1311280970,
            # "c_hash": BinaPy(code).to("sha256")[:16].to("b64u").ascii(),
            "at_hash": at_hash,
        },
        signing_key,
    )
    assert id_token == BearerToken(
        access_token=access_token,
        expires_in=60,
        id_token=str(id_token),
    ).validate_id_token(
        client=OAuth2Client(
            "https://myas.local/token",
            client_id=client_id,
            authorization_server_jwks=signing_key.public_jwk().as_jwks(),
            id_token_signed_response_alg=kwargs["alg"],
        ),
        azr=AuthorizationResponse(
            code=code,
            nonce=nonce,
        ),
    )


def test_invalid_id_token(token_endpoint: str) -> None:
    with pytest.raises(MissingIdToken):
        BearerToken(access_token="an_access_token").validate_id_token(
            client=OAuth2Client(token_endpoint, client_id="client_id"),
            azr=AuthorizationResponse(code="code"),
        )

    with pytest.raises(InvalidIdToken):
        BearerToken(
            access_token="an_access_token", expires_in=60, id_token="foo"
        ).validate_id_token(
            client=OAuth2Client(token_endpoint, client_id="client_id"),
            azr=AuthorizationResponse(code="code"),
        )

    sig_jwk = Jwk.generate(alg=SignatureAlgs.RS256).with_kid_thumbprint()
    enc_jwk = Jwk.generate(alg=KeyManagementAlgs.ECDH_ES_A256KW).with_kid_thumbprint()

    issuer = "http://issuer.local"
    client_id = "my_client_id"
    claims = {
        "iss": issuer,
        "sub": "mysub",
        "iat": Jwt.timestamp(),
        "exp": Jwt.timestamp(60),
    }

    with pytest.raises(InvalidIdToken, match="should be encrypted"):
        BearerToken(
            access_token="an_access_token", id_token=Jwt.sign(claims, sig_jwk).value
        ).validate_id_token(
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

    with pytest.raises(MismatchingIssuer):
        BearerToken(
            access_token="an_access_token", id_token=Jwt.sign(claims, sig_jwk).value
        ).validate_id_token(
            client=OAuth2Client(token_endpoint, client_id=client_id),
            azr=AuthorizationResponse(code="code", issuer="https://a.different.issuer"),
        )

    with pytest.raises(MismatchingAudience):
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
            client=OAuth2Client(token_endpoint, client_id=client_id),
            azr=AuthorizationResponse(code="code", issuer=issuer),
        )

    with pytest.raises(MismatchingAzp):
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
            client=OAuth2Client(token_endpoint, client_id=client_id),
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
            client=OAuth2Client(token_endpoint, client_id=client_id),
            azr=AuthorizationResponse(code="code", issuer=issuer),
        )

    with pytest.raises(MismatchingNonce):
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
            client=OAuth2Client(token_endpoint, client_id=client_id),
            azr=AuthorizationResponse(code="code", issuer=issuer, nonce="nonce"),
        )

    with pytest.raises(MismatchingAcr):
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
            client=OAuth2Client(token_endpoint, client_id=client_id),
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
            client=OAuth2Client(
                token_endpoint, client_id=client_id, authorization_server_jwks=None
            ),
            azr=AuthorizationResponse(code="code", issuer=issuer),
        )

    with pytest.raises(InvalidIdToken, match="does not contain a Key ID"):
        sig_jwk_no_kid = Jwk.generate(alg=SignatureAlgs.RS256)
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
                sig_jwk_no_kid,
            ).value,
        ).validate_id_token(
            client=OAuth2Client(
                token_endpoint,
                client_id=client_id,
                authorization_server_jwks=sig_jwk_no_kid.public_jwk().as_jwks(),
            ),
            azr=AuthorizationResponse(code="code", issuer=issuer),
        )

    with pytest.raises(
        InvalidIdToken, match="Key ID is not part of the Authorization Server JWKS"
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
                authorization_server_jwks=Jwk.generate(alg=SignatureAlgs.RS256)
                .with_kid_thumbprint()
                .public_jwk()
                .as_jwks(),
            ),
            azr=AuthorizationResponse(code="code", issuer=issuer),
        )

    with pytest.raises(InvalidIdToken, match="Mismatching 'at_hash' value"):
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

    with pytest.raises(InvalidIdToken, match="Mismatching 'c_hash' value"):
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

    with pytest.raises(InvalidIdToken, match="Mismatching 's_hash' value"):
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

    with pytest.raises(InvalidIdToken, match="ID Token does not contain an `alg` parameter"):
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

    with pytest.raises(
        InvalidIdToken, match="algorithm is not supported by the verification key"
    ):
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
