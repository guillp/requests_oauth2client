from datetime import datetime

import pytest

from requests_oauth2client import BearerToken, ExpiredToken, IdToken, InvalidIdToken

ID_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsImtpZCI6Im15X2tleSJ9"
    ".eyJhY3IiOiIyIiwiYW1yIjpbInB3ZCIsIm90cCJdLCJhdWQiOiJjbGllbnRfaWQiLCJhdXRoX3RpbWUiOjE2MjkyMDQ1NjAsImV"
    "4cCI6MTYyOTIwNDYyMCwiaWF0IjoxNjI5MjA0NTYwLCJpc3MiOiJodHRwczovL215YXMubG9jYWwiLCJub25jZSI6Im5vbmNlIiw"
    "ic3ViIjoiMTIzNDU2In0.wUfjMyjlOSdvbFGFP8O8wGcNBK7akeyOUBMvYcNZclFUtokOyxhLUPxmo1THo1DV1BHUVd6AWfeKUny"
    "Txl_8-G3E_a9u5wJfDyfghPDhCmfkYARvqQnnV_3aIbfTfUBC4f0bHr08d_q0fED88RLu77wESIPCVqQYy2bk4FLucc63yGBvaCs"
    "kqzthZ85DbBJYWLlR8qBUk_NA8bWATYEtjwTrxoZe-uA-vB6NwUv1h8DKRsDF-9HSVHeWXXAeoG9UW7zgxoY3KbDIVzemvGzs2R9"
    "OgDBRRafBBVeAkDV6CdbdMNJDmHzcjase5jX6LE-3YCy7c7AMM1uWRCnK3f"
)


def test_bearer_token_simple():
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


def test_bearer_token_complete():
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


def test_invalid_token_type():
    with pytest.raises(ValueError):
        BearerToken(access_token="foo", token_type="bar")


def test_id_token():
    # private_jwk = {'kty': 'RSA', 'alg': 'RS256', 'kid': 'my_key', 'n': '2m4QVSHdUo2DFSbGY24cJbxE10KbgdkSCtm0YZ1q0Zmna8pJg8YhaWCJHV7D5AxQ_L1b1PK0jsdpGYWc5-Pys0FB2hyABGPxXIdg1mjxn6geHLpWzsA3MHD29oqfl0Rt7g6AFc5St3lBgJCyWtci6QYBmBkX9oIMOx9pgv4BaT6y1DdrNh27-oSMXZ0a58KwnC6jbCpdA3V3Eume-Be1Tx9lJN3j6S8ydT7CGY1Xd-sc3oB8pXfkr1_EYf0Sgb9EwOJfqlNK_kVjT3GZ-1JJMKJ6zkU7H0yXe2SKXAzfayvJaIcYrk-sYwmf-u7yioOLLvjlGjysN7SOSM8socACcw', 'e': 'AQAB', 'd': 'RldleRTzwi8CRKB9CO4fsGNFxBCWJaWy8r2TIlBgYulZihPVwtLeVaIZ5dRrvxfcSNfuJ9CVJtm-1dI6ak71DJb6TvQYodFRm9uY6tNW5HRuZg_3_pLV8wqd7V1M8Zi-0gfnZZ5Q8vbgijeOyEQ54NLnVoTWO7M7nxqJjv6fk7Vd1vd6Gy8jI_soA6AMFCSAF-Vab07jGklBaLyow_TdczYufQ1737RNsFra2l43esAKeavxxkr7Js6OpgUkrXPEOc19GAwJLDdfkZ6yJLR8poWwX_OD-Opmvqmq6BT0s0mAyjBKZUxTGJuD3hm6mKOxXrbJOKY_UXRN7EAuH6U0gQ', 'p': '9WQs9id-xB2AhrpHgyt4nfljXFXjaDqRHzUydw15HAOoSZzYMZJW-GT8g2hB3oH3EsSCuMh70eiE1ohTLeipYdJ-s7Gy5qTH5-CblT_OfLXxi2hIumdTx53w-AtDEWl2PRt_qGHZ0B83NjVU2fo96kp9bgJWYh_iWWtSJyabXbM', 'q': '499_fCUhh5zL-3a4WGENy_yrsAa5C1sylZUtokyJNYBz68kWRFHFsArXnwZifBD_GWBgJQtldsouqvvPxzAlHQB9kfhxaRbaugwVePSjgHYmhd-NhAySq7rBURvRquAxJmoBmN2lS54YyN_X-VAKgfHDNsN7f7LIw9ISrLeR6EE', 'dp': 'Cfxwo_fJfduhfloYTOs49lzOwVQxc-1mOHnmuteOhShU8eHzHllRNryNVh-pBpANaPMcSr7F4y3uMfjMQcMFGZkCVPe3SxGLnRET48f79DFHSiANTaCk1SvFQaLbsNq02BnFYSnSPlj22zriYBiB6oXrgs2PjGC1ymPGrRcyHWc', 'dq': 'hL-4AfeTn_AtORJBdGMd6X8J-eMAu-fmARRF4G3b5Qou_eZIjYZhtxup31-V0hcItZzahdoswtYn9734nl6i0FFv1bC5SPJie838WFmUQosSCB1i0NGORHLombquG3C90VYiFg7Rc8rnP2Z_6CLD7E2OXwHkmVDq-oEQFgRfAME', 'qi': 'riPJlv9XNjdheryQWGr7Rhlvp9rxeNyWfVzj3y_IGh3tpe--Cd6-1GUrF00HLTTc-5iKVIa-FWOeMPTYc2_Uldi_0qWlrKjM5teIpUlDJbz7Ha-bfed9-eTbG8cI5F57KdDjbjB8YgqWYKz4YPMwqZFbWxZi4W_X79Bs3htXcXA'}
    public_jwk = {
        "kty": "RSA",
        "alg": "RS256",
        "kid": "my_key",
        "n": "2m4QVSHdUo2DFSbGY24cJbxE10KbgdkSCtm0YZ1q0Zmna8pJg8YhaWCJHV7D5AxQ_L1b1PK0jsdpGYWc5-Pys0FB2hyABGPxXIdg1mjxn6geHLpWzsA3MHD29oqfl0Rt7g6AFc5St3lBgJCyWtci6QYBmBkX9oIMOx9pgv4BaT6y1DdrNh27-oSMXZ0a58KwnC6jbCpdA3V3Eume-Be1Tx9lJN3j6S8ydT7CGY1Xd-sc3oB8pXfkr1_EYf0Sgb9EwOJfqlNK_kVjT3GZ-1JJMKJ6zkU7H0yXe2SKXAzfayvJaIcYrk-sYwmf-u7yioOLLvjlGjysN7SOSM8socACcw",
        "e": "AQAB",
    }
    issuer = "https://myas.local"
    audience = "client_id"
    nonce = "nonce"
    id_token = IdToken(
        "eyJhbGciOiJSUzI1NiIsImtpZCI6Im15X2tleSJ9.eyJhY3IiOiIyIiwiYW1yIjpbInB3ZCIsIm90cCJdLCJhdWQiOiJjbGllbnRfaWQiLCJhdXRoX3RpbWUiOjE2MjkyMDQ1NjAsImV4cCI6MTYyOTIwNDYyMCwiaWF0IjoxNjI5MjA0NTYwLCJpc3MiOiJodHRwczovL215YXMubG9jYWwiLCJub25jZSI6Im5vbmNlIiwic3ViIjoiMTIzNDU2In0.wUfjMyjlOSdvbFGFP8O8wGcNBK7akeyOUBMvYcNZclFUtokOyxhLUPxmo1THo1DV1BHUVd6AWfeKUnyTxl_8-G3E_a9u5wJfDyfghPDhCmfkYARvqQnnV_3aIbfTfUBC4f0bHr08d_q0fED88RLu77wESIPCVqQYy2bk4FLucc63yGBvaCskqzthZ85DbBJYWLlR8qBUk_NA8bWATYEtjwTrxoZe-uA-vB6NwUv1h8DKRsDF-9HSVHeWXXAeoG9UW7zgxoY3KbDIVzemvGzs2R9OgDBRRafBBVeAkDV6CdbdMNJDmHzcjase5jX6LE-3YCy7c7AMM1uWRCnK3f-azA"
    )

    with pytest.raises(RuntimeError):
        id_token.get_claim("sub")

    assert id_token.validate(
        public_jwk, issuer=issuer, audience=audience, nonce=nonce, check_exp=False
    )

    with pytest.raises(ExpiredToken):
        assert id_token.validate(
            public_jwk, issuer=issuer, audience=audience, nonce=nonce, check_exp=True
        )

    assert id_token.alg == "RS256"
    assert id_token.kid == "my_key"
    assert id_token == id_token
    assert id_token.aud == audience
    assert id_token.is_expired()
    assert id_token.expires_at == datetime(2021, 8, 17, 14, 50, 20)
    assert id_token.issued_at == datetime(2021, 8, 17, 14, 49, 20)

    assert id_token.validate(
        {"keys": [public_jwk]}, issuer=issuer, audience=audience, nonce=nonce, check_exp=False
    )


def test_invalid_signature():
    public_jwk = {
        "kty": "RSA",
        "alg": "RS256",
        "kid": "my_key",
        "n": "2m4QVSHdUo2DFSbGY24cJbxE10KbgdkSCtm0YZ1q0Zmna8pJg8YhaWCJHV7D5AxQ_L1b1PK0jsdpGYWc5-Pys0FB2hyABGPxXIdg1mjxn6geHLpWzsA3MHD29oqfl0Rt7g6AFc5St3lBgJCyWtci6QYBmBkX9oIMOx9pgv4BaT6y1DdrNh27-oSMXZ0a58KwnC6jbCpdA3V3Eume-Be1Tx9lJN3j6S8ydT7CGY1Xd-sc3oB8pXfkr1_EYf0Sgb9EwOJfqlNK_kVjT3GZ-1JJMKJ6zkU7H0yXe2SKXAzfayvJaIcYrk-sYwmf-u7yioOLLvjlGjysN7SOSM8socACcw",
        "e": "AQAB",
    }
    issuer = "https://myas.local"
    audience = "client_id"
    nonce = "nonce"

    id_token = IdToken(ID_TOKEN)
    modified_id_token = IdToken(
        ID_TOKEN[:-4]  # strips a few chars from the signature
        + "abcd"  # replace them with arbitrary data
    )

    # invalid signature
    with pytest.raises(ValueError):
        assert modified_id_token.validate(
            public_jwk, issuer=issuer, audience=audience, nonce=nonce, check_exp=True
        )

    # invalid issuer
    with pytest.raises(ValueError):
        assert id_token.validate(
            public_jwk, issuer="foo", audience=audience, nonce=nonce, check_exp=True
        )

    # invalid audience
    with pytest.raises(ValueError):
        assert id_token.validate(
            public_jwk, issuer=issuer, audience="foo", nonce=nonce, check_exp=True
        )

    # invalid nonce
    with pytest.raises(ValueError):
        assert id_token.validate(
            public_jwk, issuer=issuer, audience=audience, nonce="foo", check_exp=True
        )


def test_invalid_token():
    with pytest.raises(InvalidIdToken):
        IdToken("foo.bar")


def test_id_token_eq():
    id_token = IdToken(ID_TOKEN)

    assert id_token == ID_TOKEN
    assert id_token != "foo"
