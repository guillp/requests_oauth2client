from datetime import datetime, timedelta, timezone

import jwskate
import pytest
from freezegun import freeze_time
from freezegun.api import FrozenDateTimeFactory
from jwskate import (
    ExpiredJwt,
    InvalidClaim,
    InvalidJwt,
    InvalidSignature,
    Jwk,
    Jwt,
    SignatureAlgs,
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
PUBLIC_JWK = Jwk(
    {
        "kty": "RSA",
        "alg": "RS256",
        "kid": "my_key",
        "n": "2m4QVSHdUo2DFSbGY24cJbxE10KbgdkSCtm0YZ1q0Zmna8pJg8YhaWCJHV7D5AxQ_L1b1PK0jsdpGYWc5-Pys0FB2hyABGPxXIdg1mjxn6geHLpWzsA3MHD29oqfl0Rt7g6AFc5St3lBgJCyWtci6QYBmBkX9oIMOx9pgv4BaT6y1DdrNh27-oSMXZ0a58KwnC6jbCpdA3V3Eume-Be1Tx9lJN3j6S8ydT7CGY1Xd-sc3oB8pXfkr1_EYf0Sgb9EwOJfqlNK_kVjT3GZ-1JJMKJ6zkU7H0yXe2SKXAzfayvJaIcYrk-sYwmf-u7yioOLLvjlGjysN7SOSM8socACcw",
        "e": "AQAB",
    }
)


def test_bearer_token_simple() -> None:
    token = BearerToken(access_token="foo")
    assert token.access_token == "foo"
    assert token.refresh_token is None
    assert token.scope is None
    assert token.token_type == "Bearer"
    assert token.expires_at is None
    assert token.expires_in is None
    with pytest.raises(AttributeError):
        token.foo

    assert token.as_dict() == {
        "access_token": "foo",
        "token_type": "Bearer",
    }

    assert str(token) == "foo"
    assert repr(token)

    assert str(token) == "foo"
    assert token != 1.2  # type: ignore[comparison-overlap]


@freeze_time("2021-08-17 12:50:18")
def test_bearer_token_complete() -> None:
    id_token = IdToken.sign(
        {
            "iss": "https://issuer.local",
            "iat": IdToken.timestamp(),
            "exp": IdToken.timestamp(60),
            "sub": "myuserid",
        },
        Jwk.generate_for_alg(SignatureAlgs.RS256),
    )
    token = BearerToken(
        access_token="foo",
        expires_in=180,
        scope="myscope1 myscope2",
        refresh_token="refresh_token",
        custom_attr="custom_value",
        id_token=str(id_token),
    )
    assert token.access_token == "foo"
    assert token.refresh_token == "refresh_token"
    assert token.scope == "myscope1 myscope2"
    assert token.token_type == "Bearer"
    assert token.expires_in == 180
    assert token.custom_attr == "custom_value"
    assert token.id_token == id_token
    assert token.expires_at == datetime(year=2021, month=8, day=17, hour=12, minute=53, second=18, tzinfo=timezone.utc)
    with pytest.raises(AttributeError):
        token.foo

    assert token.as_dict() == {
        "access_token": "foo",
        "token_type": "Bearer",
        "refresh_token": "refresh_token",
        "expires_in": 180,
        "scope": "myscope1 myscope2",
        "custom_attr": "custom_value",
        "id_token": str(id_token),
    }

    assert str(token) == "foo"
    assert repr(token)


@freeze_time("2021-08-17 12:50:18")
def test_nearly_expired_token() -> None:
    token = BearerToken(
        access_token="foo",
        expires_at=datetime(year=2021, month=8, day=17, hour=12, minute=50, second=20, tzinfo=timezone.utc),
    )
    assert not token.is_expired()
    assert token.is_expired(3)


@freeze_time("2021-08-17 12:50:21")
def test_recently_expired_token() -> None:
    token = BearerToken(
        access_token="foo",
        expires_at=datetime(year=2021, month=8, day=17, hour=12, minute=50, second=20, tzinfo=timezone.utc),
    )
    assert token.is_expired()
    assert token.is_expired(3)
    assert not token.is_expired(-3)


def test_invalid_token_type() -> None:
    with pytest.raises(ValueError):
        BearerToken(access_token="foo", token_type="bar")


def test_empty_jwt() -> None:
    jwt = SignedJwt(
        "eyJhbGciOiJSUzI1NiIsImtpZCI6Im15X2tleSJ9.e30.qoopspKRRo0LvRHcBVAjGNOVAnGkfgOmcSTwhRv46RUuEPvoDoodtLq5hINC3TvRm8GidshIU2e-lHZ033Ja4KE5DQSL8pPItjwUxFIQ9qUYhF625bOisufNoE9YK0qDup_jcawRaBWoxkJB9oPSFaV9sCXLBX_szrUI87PPs7GDxXfgpgnztazFizizIdNf29f_FKTKRwldiQz1zaB9D_svOOThQm3ECk0PFbjqlfn7uYxe5l_GDmdgvV479rkySHhgNEC-HrGYD18Kc7Zsl1avvuLV8X-qzj-I8N06Wst8kEVnrGcCm0S4K3HfG4xHzohPQFoIuwdVzDIjSVEfCQ"
    )

    assert jwt.verify_signature(PUBLIC_JWK)
    assert jwt.expires_at is None
    assert jwt.issued_at is None
    assert jwt.not_before is None
    assert jwt.issuer is None
    assert jwt.alg == "RS256"

    with pytest.raises(InvalidClaim):
        jwt.validate(key=PUBLIC_JWK, issuer="foo")

    with pytest.raises(InvalidClaim):
        jwt.validate(key=PUBLIC_JWK, audience="foo")


def test_jwt_iat_exp_nbf() -> None:
    jwt = SignedJwt(
        "eyJhbGciOiJSUzI1NiIsImtpZCI6Im15X2tleSJ9.eyJleHAiOjE2MjkzODQ5ODgsImlhdCI6MTYyOTM4NDkyOCwibmJmIjoxNjI5Mzg0ODY4fQ.k_0abUntpK5yVOvalZGnhEhUuq1lmtoRQfKmEJuQpYiHCb3x9buYWclQCMNGzHikiyGtrRqN0RcyUPeGI9QN7hasvj1ItzrhsdXJDO968y3VXjfPnOz2lDPUKJjsTdWXbCGDZD82d4OX8E9WFaOwwutMb_5ismEBvttNAmwHJG433TzEO2rFhno9X3RPo8IqOJg_HSw8Q0BLsub7Ak9I0eGDsb8x5J8_fp6zqGkZaqL35DkLPZSHdLzYalmH4ksH69SVWu-7rD-W1brGxVpJg8unV9fy_1AmiQu-8tIedo68br2Tg0oNekwT-lXMTjmiJkYv8hpnECbtFXMRQSGcvQ"
    )

    assert jwt.verify_signature(PUBLIC_JWK, alg="RS256")
    assert jwt.issued_at == datetime(year=2021, month=8, day=19, hour=14, minute=55, second=28, tzinfo=timezone.utc)
    assert jwt.expires_at == datetime(year=2021, month=8, day=19, hour=14, minute=56, second=28, tzinfo=timezone.utc)
    assert jwt.not_before == datetime(year=2021, month=8, day=19, hour=14, minute=54, second=28, tzinfo=timezone.utc)

    assert jwt.iat == 1629384928
    assert jwt.exp == 1629384988
    assert jwt.nbf == 1629384868


def test_id_token() -> None:
    issuer = "https://myas.local"
    audience = "client_id"
    nonce = "nonce"
    acr = "2"
    id_token = IdToken(
        "eyJhbGciOiJSUzI1NiIsImtpZCI6Im15X2tleSJ9.eyJhY3IiOiIyIiwiYW1yIjpbInB3ZCIsIm90cCJdLCJhdWQiOiJjbGllbnRfaWQiLCJhdXRoX3RpbWUiOjE2MjkyMDQ1NjAsImV4cCI6MTYyOTIwNDYyMCwiaWF0IjoxNjI5MjA0NTYwLCJpc3MiOiJodHRwczovL215YXMubG9jYWwiLCJub25jZSI6Im5vbmNlIiwic3ViIjoiMTIzNDU2In0.wUfjMyjlOSdvbFGFP8O8wGcNBK7akeyOUBMvYcNZclFUtokOyxhLUPxmo1THo1DV1BHUVd6AWfeKUnyTxl_8-G3E_a9u5wJfDyfghPDhCmfkYARvqQnnV_3aIbfTfUBC4f0bHr08d_q0fED88RLu77wESIPCVqQYy2bk4FLucc63yGBvaCskqzthZ85DbBJYWLlR8qBUk_NA8bWATYEtjwTrxoZe-uA-vB6NwUv1h8DKRsDF-9HSVHeWXXAeoG9UW7zgxoY3KbDIVzemvGzs2R9OgDBRRafBBVeAkDV6CdbdMNJDmHzcjase5jX6LE-3YCy7c7AMM1uWRCnK3f-azA"
    )

    with pytest.raises(AttributeError):
        id_token.attr_not_found

    id_token.validate(
        PUBLIC_JWK,
        issuer=issuer,
        audience=audience,
        nonce=nonce,
        check_exp=False,
        acr=acr,
    )

    with pytest.raises(ExpiredJwt):
        id_token.validate(PUBLIC_JWK, issuer=issuer, audience=audience, nonce=nonce, check_exp=True)

    assert id_token.alg == "RS256"
    assert id_token.kid == "my_key"
    assert id_token.aud == audience
    assert id_token.is_expired()
    assert id_token.is_expired(1000)
    assert id_token.expires_at == datetime(2021, 8, 17, 12, 50, 20, tzinfo=timezone.utc)
    assert id_token.issued_at == datetime(2021, 8, 17, 12, 49, 20, tzinfo=timezone.utc)


def test_invalid_jwt() -> None:
    issuer = "https://myas.local"
    audience = "client_id"
    nonce = "nonce"

    id_token = IdToken(ID_TOKEN)
    modified_id_token = IdToken(
        ID_TOKEN[:-4] + "abcd"  # strips a few chars from the signature  # replace them with arbitrary data
    )

    # invalid signature
    with pytest.raises(InvalidSignature):
        modified_id_token.validate(PUBLIC_JWK, issuer=issuer, audience=audience, nonce=nonce, check_exp=False)

    # invalid issuer
    with pytest.raises(InvalidClaim):
        id_token.validate(PUBLIC_JWK, issuer="foo", audience=audience, nonce=nonce, check_exp=False)

    # invalid audience
    with pytest.raises(InvalidClaim):
        id_token.validate(PUBLIC_JWK, issuer=issuer, audience="foo", nonce=nonce, check_exp=False)

    # invalid nonce
    with pytest.raises(InvalidClaim):
        id_token.validate(PUBLIC_JWK, issuer=issuer, audience=audience, nonce="foo", check_exp=False)

    # invalid claim
    with pytest.raises(InvalidClaim):
        id_token.validate(
            PUBLIC_JWK,
            issuer=issuer,
            audience=audience,
            nonce=nonce,
            check_exp=False,
            acr="4",
        )

    # missing claim
    with pytest.raises(InvalidClaim):
        id_token.validate(
            PUBLIC_JWK,
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


def test_id_token_attributes() -> None:
    bad_id_token = IdToken(Jwt.sign({"azp": 1234, "auth_time": -3000}, Jwk.generate(alg="HS256")).value)
    with pytest.raises(AttributeError):
        bad_id_token.authorized_party

    with pytest.raises(AttributeError):
        bad_id_token.auth_datetime

    good_id_token = IdToken(Jwt.sign({"azp": "valid", "auth_time": 1725529281}, Jwk.generate(alg="HS256")).value)
    assert good_id_token.authorized_party == "valid"
    assert good_id_token.auth_datetime == datetime(2024, 9, 5, 9, 41, 21, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    "token",
    [
        BearerToken("access_token"),
        # note that "expires_at" is calculated when the test is ran, so before `freezer` takes effect
        BearerToken("access_token", expires_in=60),
        BearerToken("access_token", expires_in=-60),
    ],
)
def test_token_serializer(token: BearerToken, freezer: FrozenDateTimeFactory) -> None:
    freezer.move_to("2024-08-01")
    serializer = BearerTokenSerializer()
    candidate = serializer.dumps(token)
    freezer.move_to(datetime.now(tz=timezone.utc) + timedelta(days=365))
    assert serializer.loads(candidate) == token


@freeze_time()
def test_expires_in_as_str() -> None:
    assert BearerToken("access_token", expires_in=60) == BearerToken("access_token", expires_in="60")
    assert BearerToken("access_token", expires_in=-60) == BearerToken("access_token", expires_in="-60")
    assert BearerToken("access_token", expires_in="foo") == BearerToken("access_token")


def test_access_token_jwt() -> None:
    assert isinstance(
        BearerToken(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        ).access_token_jwt,
        jwskate.SignedJwt,
    )

    with pytest.raises(jwskate.InvalidJwt):
        BearerToken("not.a.jwt").access_token_jwt
