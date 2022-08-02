from datetime import datetime, timezone

import pytest
from jwskate import (
    ExpiredJwt,
    InvalidClaim,
    InvalidJwt,
    InvalidSignature,
    Jwk,
    Jwt,
    SignedJwt,
)

from requests_oauth2client import BearerToken, BearerTokenSerializer, IdToken

ID_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsImtpZCI6Im15X2tleSJ9.eyJhY3IiOiIyIiwiYW1yIjpbInB3ZCIsIm90cCJdLCJhdWQiOiJjbGllbnRfaWQiL"
    "CJhdXRoX3RpbWUiOjE2MjkyMDQ1NjAsImV4cCI6MTYyOTIwNDYyMCwiaWF0IjoxNjI5MjA0NTYwLCJpc3MiOiJodHRwczovL215YXMubG9"
    "jYWwiLCJub25jZSI6Im5vbmNlIiwic3ViIjoiMTIzNDU2In0.wUfjMyjlOSdvbFGFP8O8wGcNBK7akeyOUBMvYcNZclFUtokOyxhLUPxmo"
    "1THo1DV1BHUVd6AWfeKUnyTxl_8-G3E_a9u5wJfDyfghPDhCmfkYARvqQnnV_3aIbfTfUBC4f0bHr08d_q0fED88RLu77wESIPCVqQYy2b"
    "k4FLucc63yGBvaCskqzthZ85DbBJYWLlR8qBUk_NA8bWATYEtjwTrxoZe-uA-vB6NwUv1h8DKRsDF-9HSVHeWXXAeoG9UW7zgxoY3KbDIV"
    "zemvGzs2R9OgDBRRafBBVeAkDV6CdbdMNJDmHzcjase5jX6LE-3YCy7c7AMM1uWRCnK3f-azA"
)


def test_bearer_token_simple() -> None:
    token = BearerToken(access_token="foo")
    assert "access_token" in token
    assert "refresh_token" not in token
    assert "scope" not in token
    assert "token_type" in token
    assert "expires_in" not in token
    assert "foo" not in token
    assert token.expires_in is None
    assert token.expires_at is None
    assert token.token_type == "Bearer"

    assert token.as_dict() == {
        "access_token": "foo",
        "token_type": "Bearer",
    }

    assert str(token) == "foo"
    assert repr(token)


def test_bearer_token_complete() -> None:
    token = BearerToken(
        access_token="foo",
        expires_in=180,
        scope="myscope1 myscope2",
        refresh_token="refresh_token",
        custom_attr="custom_value",
    )
    assert "access_token" in token
    assert "refresh_token" in token
    assert "scope" in token
    assert "token_type" in token
    assert "expires_in" in token
    assert "foo" not in token
    assert "custom_attr" in token
    assert token.expires_in is not None
    assert token.expires_at is not None
    assert token.token_type == "Bearer"

    assert token.as_dict() == {
        "access_token": "foo",
        "token_type": "Bearer",
        "refresh_token": "refresh_token",
        "expires_in": token.expires_in,  # TODO: enhance
        "scope": "myscope1 myscope2",
        "custom_attr": "custom_value",
    }

    assert token.expires_in <= 180
    assert token.custom_attr == "custom_value"

    with pytest.raises(AttributeError):
        token.foo

    assert str(token) == "foo"
    assert repr(token)


def test_invalid_token_type() -> None:
    with pytest.raises(ValueError):
        BearerToken(access_token="foo", token_type="bar")


def test_empty_jwt() -> None:
    jwt = SignedJwt(
        "eyJhbGciOiJSUzI1NiIsImtpZCI6Im15X2tleSJ9.e30.qoopspKRRo0LvRHcBVAjGNOVAnGkfgOmcSTwhRv46RUuEPvoDoodtLq5hINC3TvRm8GidshIU2e-lHZ033Ja4KE5DQSL8pPItjwUxFIQ9qUYhF625bOisufNoE9YK0qDup_jcawRaBWoxkJB9oPSFaV9sCXLBX_szrUI87PPs7GDxXfgpgnztazFizizIdNf29f_FKTKRwldiQz1zaB9D_svOOThQm3ECk0PFbjqlfn7uYxe5l_GDmdgvV479rkySHhgNEC-HrGYD18Kc7Zsl1avvuLV8X-qzj-I8N06Wst8kEVnrGcCm0S4K3HfG4xHzohPQFoIuwdVzDIjSVEfCQ"
    )
    public_jwk = {
        "kty": "RSA",
        "alg": "RS256",
        "kid": "my_key",
        "n": "2m4QVSHdUo2DFSbGY24cJbxE10KbgdkSCtm0YZ1q0Zmna8pJg8YhaWCJHV7D5AxQ_L1b1PK0jsdpGYWc5-Pys0FB2hyABGPxXIdg1mjxn6geHLpWzsA3MHD29oqfl0Rt7g6AFc5St3lBgJCyWtci6QYBmBkX9oIMOx9pgv4BaT6y1DdrNh27-oSMXZ0a58KwnC6jbCpdA3V3Eume-Be1Tx9lJN3j6S8ydT7CGY1Xd-sc3oB8pXfkr1_EYf0Sgb9EwOJfqlNK_kVjT3GZ-1JJMKJ6zkU7H0yXe2SKXAzfayvJaIcYrk-sYwmf-u7yioOLLvjlGjysN7SOSM8socACcw",
        "e": "AQAB",
    }

    assert jwt.verify_signature(jwk=public_jwk)
    assert jwt.expires_at is None
    assert jwt.issued_at is None
    assert jwt.not_before is None
    assert jwt.issuer is None
    assert jwt.alg == "RS256"

    with pytest.raises(InvalidClaim):
        jwt.validate(jwk=public_jwk, issuer="foo")

    with pytest.raises(InvalidClaim):
        jwt.validate(jwk=public_jwk, audience="foo")


def test_jwt_iat_exp_nbf() -> None:
    jwt = SignedJwt(
        "eyJhbGciOiJSUzI1NiIsImtpZCI6Im15X2tleSJ9.eyJleHAiOjE2MjkzODQ5ODgsImlhdCI6MTYyOTM4NDkyOCwibmJmIjoxNjI5Mzg0ODY4fQ.k_0abUntpK5yVOvalZGnhEhUuq1lmtoRQfKmEJuQpYiHCb3x9buYWclQCMNGzHikiyGtrRqN0RcyUPeGI9QN7hasvj1ItzrhsdXJDO968y3VXjfPnOz2lDPUKJjsTdWXbCGDZD82d4OX8E9WFaOwwutMb_5ismEBvttNAmwHJG433TzEO2rFhno9X3RPo8IqOJg_HSw8Q0BLsub7Ak9I0eGDsb8x5J8_fp6zqGkZaqL35DkLPZSHdLzYalmH4ksH69SVWu-7rD-W1brGxVpJg8unV9fy_1AmiQu-8tIedo68br2Tg0oNekwT-lXMTjmiJkYv8hpnECbtFXMRQSGcvQ"
    )
    public_jwk = {
        "kty": "RSA",
        "alg": "RS256",
        "kid": "my_key",
        "n": "2m4QVSHdUo2DFSbGY24cJbxE10KbgdkSCtm0YZ1q0Zmna8pJg8YhaWCJHV7D5AxQ_L1b1PK0jsdpGYWc5-Pys0FB2hyABGPxXIdg1mjxn6geHLpWzsA3MHD29oqfl0Rt7g6AFc5St3lBgJCyWtci6QYBmBkX9oIMOx9pgv4BaT6y1DdrNh27-oSMXZ0a58KwnC6jbCpdA3V3Eume-Be1Tx9lJN3j6S8ydT7CGY1Xd-sc3oB8pXfkr1_EYf0Sgb9EwOJfqlNK_kVjT3GZ-1JJMKJ6zkU7H0yXe2SKXAzfayvJaIcYrk-sYwmf-u7yioOLLvjlGjysN7SOSM8socACcw",
        "e": "AQAB",
    }

    assert jwt.verify_signature(public_jwk, alg="RS256")
    assert jwt.issued_at == datetime(
        year=2021, month=8, day=19, hour=14, minute=55, second=28, tzinfo=timezone.utc
    )
    assert jwt.expires_at == datetime(
        year=2021, month=8, day=19, hour=14, minute=56, second=28, tzinfo=timezone.utc
    )
    assert jwt.not_before == datetime(
        year=2021, month=8, day=19, hour=14, minute=54, second=28, tzinfo=timezone.utc
    )

    assert jwt.iat == 1629384928
    assert jwt.exp == 1629384988
    assert jwt.nbf == 1629384868


def test_id_token() -> None:
    public_jwk = Jwk(
        {
            "kty": "RSA",
            "alg": "RS256",
            "kid": "my_key",
            "n": "2m4QVSHdUo2DFSbGY24cJbxE10KbgdkSCtm0YZ1q0Zmna8pJg8YhaWCJHV7D5AxQ_L1b1PK0jsdpGYWc5-Pys0FB2hyABGPxXIdg1mjxn6geHLpWzsA3MHD29oqfl0Rt7g6AFc5St3lBgJCyWtci6QYBmBkX9oIMOx9pgv4BaT6y1DdrNh27-oSMXZ0a58KwnC6jbCpdA3V3Eume-Be1Tx9lJN3j6S8ydT7CGY1Xd-sc3oB8pXfkr1_EYf0Sgb9EwOJfqlNK_kVjT3GZ-1JJMKJ6zkU7H0yXe2SKXAzfayvJaIcYrk-sYwmf-u7yioOLLvjlGjysN7SOSM8socACcw",
            "e": "AQAB",
        }
    )
    issuer = "https://myas.local"
    audience = "client_id"
    nonce = "nonce"
    acr = "2"
    id_token = IdToken(
        "eyJhbGciOiJSUzI1NiIsImtpZCI6Im15X2tleSJ9.eyJhY3IiOiIyIiwiYW1yIjpbInB3ZCIsIm90cCJdLCJhdWQiOiJjbGllbnRfaWQiLCJhdXRoX3RpbWUiOjE2MjkyMDQ1NjAsImV4cCI6MTYyOTIwNDYyMCwiaWF0IjoxNjI5MjA0NTYwLCJpc3MiOiJodHRwczovL215YXMubG9jYWwiLCJub25jZSI6Im5vbmNlIiwic3ViIjoiMTIzNDU2In0.wUfjMyjlOSdvbFGFP8O8wGcNBK7akeyOUBMvYcNZclFUtokOyxhLUPxmo1THo1DV1BHUVd6AWfeKUnyTxl_8-G3E_a9u5wJfDyfghPDhCmfkYARvqQnnV_3aIbfTfUBC4f0bHr08d_q0fED88RLu77wESIPCVqQYy2bk4FLucc63yGBvaCskqzthZ85DbBJYWLlR8qBUk_NA8bWATYEtjwTrxoZe-uA-vB6NwUv1h8DKRsDF-9HSVHeWXXAeoG9UW7zgxoY3KbDIVzemvGzs2R9OgDBRRafBBVeAkDV6CdbdMNJDmHzcjase5jX6LE-3YCy7c7AMM1uWRCnK3f-azA"
    )

    with pytest.raises(AttributeError):
        id_token.not_found

    id_token.validate(
        public_jwk,
        issuer=issuer,
        audience=audience,
        nonce=nonce,
        check_exp=False,
        acr=acr,
    )

    with pytest.raises(ExpiredJwt):
        id_token.validate(
            public_jwk, issuer=issuer, audience=audience, nonce=nonce, check_exp=True
        )

    assert id_token.alg == "RS256"
    assert id_token.kid == "my_key"
    assert id_token == id_token
    assert id_token.aud == audience
    assert id_token.is_expired()
    assert id_token.expires_at == datetime(2021, 8, 17, 12, 50, 20, tzinfo=timezone.utc)
    assert id_token.issued_at == datetime(2021, 8, 17, 12, 49, 20, tzinfo=timezone.utc)


def test_invalid_jwt() -> None:
    public_jwk = Jwk(
        {
            "kty": "RSA",
            "alg": "RS256",
            "kid": "my_key",
            "n": "2m4QVSHdUo2DFSbGY24cJbxE10KbgdkSCtm0YZ1q0Zmna8pJg8YhaWCJHV7D5AxQ_L1b1PK0jsdpGYWc5-Pys0FB2hyABGPxXIdg1mjxn6geHLpWzsA3MHD29oqfl0Rt7g6AFc5St3lBgJCyWtci6QYBmBkX9oIMOx9pgv4BaT6y1DdrNh27-oSMXZ0a58KwnC6jbCpdA3V3Eume-Be1Tx9lJN3j6S8ydT7CGY1Xd-sc3oB8pXfkr1_EYf0Sgb9EwOJfqlNK_kVjT3GZ-1JJMKJ6zkU7H0yXe2SKXAzfayvJaIcYrk-sYwmf-u7yioOLLvjlGjysN7SOSM8socACcw",
            "e": "AQAB",
        }
    )
    issuer = "https://myas.local"
    audience = "client_id"
    nonce = "nonce"

    id_token = IdToken(ID_TOKEN)
    modified_id_token = IdToken(
        ID_TOKEN[:-4]  # strips a few chars from the signature
        + "abcd"  # replace them with arbitrary data
    )

    # invalid signature
    with pytest.raises(InvalidSignature):
        modified_id_token.validate(
            public_jwk, issuer=issuer, audience=audience, nonce=nonce, check_exp=False
        )

    # invalid issuer
    with pytest.raises(InvalidClaim):
        id_token.validate(
            public_jwk, issuer="foo", audience=audience, nonce=nonce, check_exp=False
        )

    # invalid audience
    with pytest.raises(InvalidClaim):
        id_token.validate(
            public_jwk, issuer=issuer, audience="foo", nonce=nonce, check_exp=False
        )

    # invalid nonce
    with pytest.raises(InvalidClaim):
        id_token.validate(
            public_jwk, issuer=issuer, audience=audience, nonce="foo", check_exp=False
        )

    # invalid claim
    with pytest.raises(InvalidClaim):
        id_token.validate(
            public_jwk,
            issuer=issuer,
            audience=audience,
            nonce=nonce,
            check_exp=False,
            acr="4",
        )

    # missing claim
    with pytest.raises(InvalidClaim):
        id_token.validate(
            public_jwk,
            issuer=issuer,
            audience=audience,
            nonce=nonce,
            check_exp=False,
            foo="bar",
        )


def test_invalid_token() -> None:
    with pytest.raises(InvalidJwt):
        IdToken("foo.bar")


def test_id_token_eq() -> None:
    id_token = IdToken(ID_TOKEN)

    assert id_token == ID_TOKEN
    assert id_token != "foo"
    assert id_token != 13.37


def test_token_serializer() -> None:
    serializer = BearerTokenSerializer()
    assert (
        serializer.dumps(BearerToken("access_token"))
        == "q1ZKTE5OLS6OL8nPTs1TskLl6iiB6fiSyoJUoJxTamJRapFSLQA"
    )
    assert serializer.loads(
        "q1ZKTE5OLS6OL8nPTs1TskLl6iiB6fiSyoJUoJxTamJRapFSLQA"
    ) == BearerToken("access_token")
