import base64
from datetime import datetime

from requests_oauth2client.jwskate import (ECJwk, Jwk, JwkSet, JwsCompact, Jwt,
                                           OKPJwk, RSAJwk, SignedJwt, SymetricJwk)

RSA_PRIVATE_JWK = {
    "kty": "RSA",
    "n": "oRHn4oGv23ylRL3RSsL4p_e6Ywinnj2N2tT5OLe5pEZTg-LFBhjFxcJaB-p1dh6XX47EtSfa-JHffU0o5ZRK2ySyNDtlrFAkOpAHH6U83ayE2QPYGzrFrrvHDa8wIMUWymzxpPwGgKBwZZqtTT6d-iy4Ux3AWV-bUv6Z7WijHnOy7aVzZ4dFERLVf2FaaYXDET7GO4v-oQ5ss_guYdmewN039jxkjz_KrA-0Fyhalf9hL8IHfpdpSlHosrmjORG5y9LkYK0J6zxSBF5ZvLIBK33BTzPPiCMwKLyAcV6qdcAcvV4kthKO0iUKBK4eE8D0N8HcSPvA9F_PpLS_k5F2lw",
    "e": "AQAB",
    "d": "U-uiZ8-uMquU6GYF_-_p4ooeIK9HthjYKiZA255OKRtDNDoY8X5CvTDv-6PbI3n44J7gOorTeiN20DA9mLBU-Cz8dF5mMQtodOLJ82ECf3T9mpx4ImfSy6GmqqiWaNyHbVyp4o41TRtKtIWMuexgHxLhztx3dZlssidZR-r24kwON7_2JUeY-N6hwmKh3DlsmO9KyOAoTwNjyKxCIqbf7WnZ9gnavG_mLUeXeiHhSgASYMTUCCFm0KOhDWgvaddDKDMqcQUYPonaI19fW1eNtXfXRjFWwlGbqOnOo930yl1LG1CawI0rbxmkDoyjTHLDJlY7Go_gpHlP2maQRPiMcQ",
    "p": "0mzP9sbFxU5YxNNLgUEdRQSO-ojqWrzbI02PfQLGyzXumvOh_Qr73OpHStU8CAAcUBaQdRGidsVdb5cq6JG2zvbEEYiX-dCHqTJs8wfktGCL7eV-ZVh7fhJ1sYVBN20yv8aSH63uUPZnJXR1AUyrvRumuerdPxp8X951PESrJd0",
    "q": "w_SPRMeEtbEvsRcNfpmbRbpO368hcaLjB9Bb_IvxvoiI3aMTMZgwLSyx5hpuv6A86R3wFdRkh2JBKCzG4ItirUyTfVRUY9ItSNyMNplHxELA6I4JG0m6Rh-IO3wG8-h-U-NKllG4SCR8mS9Wvhg7eBZh_LXvKSgKLgalZSSUSQM",
    "dp": "ogg6B3u-VJVk04Mk1A3w3PGKq678Twy37bJOuGOH8njAGD9c0D5B_TXF2gDirgJvytflOtBueui1bzVHTDjQPQRVrG6zICGMJSR4Mpg0axUhCvo53w5IYacTS7QhqO2EM5pTcON87Ikgmf3YDz0bzY3aT7Vj0rCxbx0cx2DVLV0",
    "dq": "TwdPzJ5m4FwgbtxsPdW3cIyuCLp503ms9FbM8nKCQaSRBkohkIvfSijPaozYg4Idbqr7S-KH1K4Ety4v2xl754aNqSscidGXH96K0e5JqlZ9tIysEYxPir5m1A62QyJN6IkvaKZ2munUMneMFUhym4Dzbdb2KHQUfvGBPORexX8",
    "qi": "rymn9AZV0TshtAM32YLo2HNzOOXRVLbwMZUjOeViuUVSyPqtkKNYFHKBpg7QxuzGbl6w32xKLKoW7xmlQKsSCMtFyVFYtv5muRNlQMG79xxX2M65MhUesPoe7YMJR0fHSBQ6yDvOOdP35CEnABh7AiIIW_rs3ngyfIOyAm0XuiE",
}


def test_jwk():
    jwk = Jwk(RSA_PRIVATE_JWK)
    assert jwk.is_private
    assert jwk.kty == "RSA"
    assert type(jwk) == RSAJwk
    assert jwk.n == RSA_PRIVATE_JWK["n"]
    assert jwk.e == RSA_PRIVATE_JWK["e"]
    assert jwk.d == RSA_PRIVATE_JWK["d"]
    assert jwk.p == RSA_PRIVATE_JWK["p"]
    assert jwk.q == RSA_PRIVATE_JWK["q"]
    assert jwk.dp == RSA_PRIVATE_JWK["dp"]
    assert jwk.dq == RSA_PRIVATE_JWK["dq"]
    assert jwk.qi == RSA_PRIVATE_JWK["qi"]

    assert (
        jwk.thumbprint() == "Qfq9DOLKNRyptzTJBhCFlzccbA0ac7Ag9GVFL11GAfM"
    )  # TODO: check this value

    signature = jwk.sign(b"Hello World!")
    assert (
        signature.hex()
        == "2eb2d1f5ef9a55403b7d09cca52955feea3ced6b948d311819ec976e4f40cb3cdf9718de38ecc53fd060e2994fab378cb64ebcecf1a6da1d5983af8b6d53c2830e0a4815863345ac72f9a6e7b6328f5678c1a3ed89074fa1e0526f261c5d969c0d059db94fedd51a705ae1870ef4c00cf89b5702c62f20fd1c3f13b94b15e529a9f6d86810788cf7d6d9e1e296d094af934931d6b845d2c93239943ca678b715310c2019ac1eca39dc1e8e67153342ab5d8d500ee07e438b316a1e6e2cd11191fb2ddf98ae2d9f62a6d50f74890d429af57946e744dda52f8341014a9bbc1b82bcaeae8d5458d3433140b88d6fc2c46af011c2189fdf6adc27b53e2ae90b6207"  # TODO: check this value
    )

    public_jwk = jwk.public_jwk()
    assert not public_jwk.is_private
    assert public_jwk.d is None
    assert public_jwk.p is None
    assert public_jwk.q is None
    assert public_jwk.dp is None
    assert public_jwk.dq is None
    assert public_jwk.qi is None

    assert public_jwk.thumbprint() == jwk.thumbprint()
    assert public_jwk.verify(b"Hello World!", signature, alg="RS256")


def test_jwk_symetric():
    jwk = SymetricJwk.generate(24, kid="myoctkey")
    assert jwk.kty == "oct"
    assert jwk.kid == "myoctkey"
    assert isinstance(jwk.k, str)
    assert len(base64.urlsafe_b64decode(jwk.k + "=")) == 24
    assert jwk.is_private


def test_jwk_rsa():
    jwk = RSAJwk.generate(kid="myrsakey")
    assert jwk.kty == "RSA"
    assert jwk.kid == "myrsakey"
    assert jwk.n
    assert jwk.d
    assert jwk.p
    assert jwk.q
    assert jwk.dp
    assert jwk.dq
    assert jwk.qi


def test_jwk_ec():
    jwk = ECJwk.generate(kid="myeckey")
    assert jwk.kty == "EC"
    assert jwk.kid == "myeckey"
    assert jwk.crv == "P-256"
    assert jwk.x
    assert jwk.y
    assert jwk.d


def test_jwk_okp():
    jwk = OKPJwk.generate(crv="Ed25519", kid="myokpkey")
    assert jwk.kty == "OKP"
    assert jwk.kid == "myokpkey"


def test_jwks():
    jwks = JwkSet()
    assert len(jwks) == 0
    kid = jwks.add_jwk(RSA_PRIVATE_JWK)
    assert jwks[kid]["kty"] == RSA_PRIVATE_JWK["kty"]
    assert jwks[kid]["kid"] == kid
    assert jwks[kid]["n"] == RSA_PRIVATE_JWK["n"]
    assert jwks[kid]["e"] == RSA_PRIVATE_JWK["e"]

    private_key = jwks.private_jwks[kid]
    assert kid == private_key.pop("kid")
    assert private_key == RSA_PRIVATE_JWK


def test_jws_compact():
    jwk = Jwk(RSA_PRIVATE_JWK)
    jws = JwsCompact.sign(payload=b"Hello World!", jwk=jwk, alg="RS256")
    assert (
        str(jws)
        == "eyJhbGciOiJSUzI1NiIsImtpZCI6IlFmcTlET0xLTlJ5cHR6VEpCaENGbHpjY2JBMGFjN0FnOUdWRkwxMUdBZk0ifQ.SGVsbG8gV29ybGQh.Wkne7AHUe6_yoAE-qjW139dTTSLrcxImDCB3WalovNUdgjhQxTxdZJBWA6GCkwXQvLmANyo51oAyiWSMEpmaPuuhxf4i47_1CuX2a33kuJh_HefJr3aCENRBdJQfCLcPqnkRhikFvJfbDMEFJpmdoEJfsxs4SNlP4eED--5y1odATb40Ikw8_H2O-OtLvSwGKiSUazJnzMa29GyQeAWXqxgsknnUBDQXSHVwPsUz-aiTPk9anzPWaV-pmjksfXsutzO9bXhs_8hKsby1QgEB-9GQRdRjY-ywWszc1MVIjjxx0TOKXCufk8xr3iN3lCrnd7Burz2YlCv47JzZczAxYA"
    )
    assert jws.verify_signature(jwk, alg="RS256")


def test_jwt():
    jwt = Jwt(
        "eyJhbGciOiJSUzI1NiIsImtpZCI6Im15X2tleSJ9.eyJhY3IiOiIyIiwiYW1yIjpbInB3ZCIsIm90cCJdLCJhdWQiOiJjbGllbnRfaWQiLCJhdXRoX3RpbWUiOjE2MjkyMDQ1NjAsImV4cCI6MTYyOTIwNDYyMCwiaWF0IjoxNjI5MjA0NTYwLCJpc3MiOiJodHRwczovL215YXMubG9jYWwiLCJub25jZSI6Im5vbmNlIiwic3ViIjoiMTIzNDU2In0.wUfjMyjlOSdvbFGFP8O8wGcNBK7akeyOUBMvYcNZclFUtokOyxhLUPxmo1THo1DV1BHUVd6AWfeKUnyTxl_8-G3E_a9u5wJfDyfghPDhCmfkYARvqQnnV_3aIbfTfUBC4f0bHr08d_q0fED88RLu77wESIPCVqQYy2bk4FLucc63yGBvaCskqzthZ85DbBJYWLlR8qBUk_NA8bWATYEtjwTrxoZe-uA-vB6NwUv1h8DKRsDF-9HSVHeWXXAeoG9UW7zgxoY3KbDIVzemvGzs2R9OgDBRRafBBVeAkDV6CdbdMNJDmHzcjase5jX6LE-3YCy7c7AMM1uWRCnK3f-azA"
    )

    assert isinstance(jwt, SignedJwt)
    assert jwt.headers == {"alg": "RS256", "kid": "my_key"}
    assert jwt.claims == {
        "acr": "2",
        "amr": ["pwd", "otp"],
        "aud": "client_id",
        "auth_time": 1629204560,
        "exp": 1629204620,
        "iat": 1629204560,
        "iss": "https://myas.local",
        "nonce": "nonce",
        "sub": "123456",
    }
    assert jwt.is_expired()
    assert jwt.sub == "123456"
    assert jwt.nonce == "nonce"
    assert jwt.amr == ["pwd", "otp"]
    assert jwt.exp == 1629204620
    assert jwt.expires_at == datetime.fromtimestamp(1629204620)
    assert jwt.issued_at == datetime.fromtimestamp(1629204560)
    assert jwt.verify_signature(Jwk({
        "kty": "RSA",
        "alg": "RS256",
        "kid": "my_key",
        "n": "2m4QVSHdUo2DFSbGY24cJbxE10KbgdkSCtm0YZ1q0Zmna8pJg8YhaWCJHV7D5AxQ_L1b1PK0jsdpGYWc5-Pys0FB2hyABGPxXIdg1mjxn6geHLpWzsA3MHD29oqfl0Rt7g6AFc5St3lBgJCyWtci6QYBmBkX9oIMOx9pgv4BaT6y1DdrNh27-oSMXZ0a58KwnC6jbCpdA3V3Eume-Be1Tx9lJN3j6S8ydT7CGY1Xd-sc3oB8pXfkr1_EYf0Sgb9EwOJfqlNK_kVjT3GZ-1JJMKJ6zkU7H0yXe2SKXAzfayvJaIcYrk-sYwmf-u7yioOLLvjlGjysN7SOSM8socACcw",
        "e": "AQAB",
        "d": "RldleRTzwi8CRKB9CO4fsGNFxBCWJaWy8r2TIlBgYulZihPVwtLeVaIZ5dRrvxfcSNfuJ9CVJtm-1dI6ak71DJb6TvQYodFRm9uY6tNW5HRuZg_3_pLV8wqd7V1M8Zi-0gfnZZ5Q8vbgijeOyEQ54NLnVoTWO7M7nxqJjv6fk7Vd1vd6Gy8jI_soA6AMFCSAF-Vab07jGklBaLyow_TdczYufQ1737RNsFra2l43esAKeavxxkr7Js6OpgUkrXPEOc19GAwJLDdfkZ6yJLR8poWwX_OD-Opmvqmq6BT0s0mAyjBKZUxTGJuD3hm6mKOxXrbJOKY_UXRN7EAuH6U0gQ",
        "p": "9WQs9id-xB2AhrpHgyt4nfljXFXjaDqRHzUydw15HAOoSZzYMZJW-GT8g2hB3oH3EsSCuMh70eiE1ohTLeipYdJ-s7Gy5qTH5-CblT_OfLXxi2hIumdTx53w-AtDEWl2PRt_qGHZ0B83NjVU2fo96kp9bgJWYh_iWWtSJyabXbM",
        "q": "499_fCUhh5zL-3a4WGENy_yrsAa5C1sylZUtokyJNYBz68kWRFHFsArXnwZifBD_GWBgJQtldsouqvvPxzAlHQB9kfhxaRbaugwVePSjgHYmhd-NhAySq7rBURvRquAxJmoBmN2lS54YyN_X-VAKgfHDNsN7f7LIw9ISrLeR6EE",
        "dp": "Cfxwo_fJfduhfloYTOs49lzOwVQxc-1mOHnmuteOhShU8eHzHllRNryNVh-pBpANaPMcSr7F4y3uMfjMQcMFGZkCVPe3SxGLnRET48f79DFHSiANTaCk1SvFQaLbsNq02BnFYSnSPlj22zriYBiB6oXrgs2PjGC1ymPGrRcyHWc",
        "dq": "hL-4AfeTn_AtORJBdGMd6X8J-eMAu-fmARRF4G3b5Qou_eZIjYZhtxup31-V0hcItZzahdoswtYn9734nl6i0FFv1bC5SPJie838WFmUQosSCB1i0NGORHLombquG3C90VYiFg7Rc8rnP2Z_6CLD7E2OXwHkmVDq-oEQFgRfAME",
        "qi": "riPJlv9XNjdheryQWGr7Rhlvp9rxeNyWfVzj3y_IGh3tpe--Cd6-1GUrF00HLTTc-5iKVIa-FWOeMPTYc2_Uldi_0qWlrKjM5teIpUlDJbz7Ha-bfed9-eTbG8cI5F57KdDjbjB8YgqWYKz4YPMwqZFbWxZi4W_X79Bs3htXcXA",
    }))
