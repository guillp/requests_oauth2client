from requests_oauth2client.jwskate import Jwk, JwkSet

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
    assert jwk.n == RSA_PRIVATE_JWK["n"]
    assert jwk.e == RSA_PRIVATE_JWK["e"]
    assert jwk.d == RSA_PRIVATE_JWK["d"]
    assert jwk.p == RSA_PRIVATE_JWK["p"]
    assert jwk.q == RSA_PRIVATE_JWK["q"]
    assert jwk.dp == RSA_PRIVATE_JWK["dp"]
    assert jwk.dq == RSA_PRIVATE_JWK["dq"]
    assert jwk.qi == RSA_PRIVATE_JWK["qi"]

    assert jwk.thumbprint() == 'Qfq9DOLKNRyptzTJBhCFlzccbA0ac7Ag9GVFL11GAfM'

    public_jwk = jwk.public_jwk()
    assert not public_jwk.is_private
    assert public_jwk.d is None
    assert public_jwk.p is None
    assert public_jwk.q is None
    assert public_jwk.dp is None
    assert public_jwk.dq is None
    assert public_jwk.qi is None

    assert public_jwk.thumbprint() == jwk.thumbprint()


def test_jwk_generator():
    jwk = Jwk.generate_RSA(kid="mykey")
    assert jwk.kty == "RSA"
    assert jwk.kid == "mykey"


def test_jwks():
    jwks = JwkSet()
    assert len(jwks) == 0
    kid = jwks.add(RSA_PRIVATE_JWK)
    assert jwks[kid]["kty"] == RSA_PRIVATE_JWK["kty"]
    assert jwks[kid]["kid"] == kid
    assert jwks[kid]["n"] == RSA_PRIVATE_JWK["n"]
    assert jwks[kid]["e"] == RSA_PRIVATE_JWK["e"]

    private_key = jwks.private[kid]
    assert kid == private_key.pop("kid")
    assert private_key == RSA_PRIVATE_JWK
