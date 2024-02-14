from freezegun import freeze_time
from furl import furl  # type: ignore[import-untyped]
from jwskate import EncryptionAlgs, Jwk, Jwt

from requests_oauth2client import IdToken, OAuth2Client
from tests.conftest import RequestsMocker


@freeze_time("2024-01-01 00:00:00")
def test_encrypted_id_token(requests_mock: RequestsMocker) -> None:
    id_token_decryption_key = Jwk(
        {
            "kty": "EC",
            "crv": "P-256",
            "x": "GNWWCtwaKIdNjsz_ypPKEX1If_yL5w_mJeAepqEDNdk",
            "y": "qjfk0Og-Ov9cWxtuR3-Oxcr4MqW9LB4FLkQuo-ryUWE",
            "d": "y-ndvYzmafoeY9AlnUkoXIiNe5xf_h_23NEEATYKoY4",
            "alg": "ECDH-ES+A256KW",
            "kid": "RvIJrxavhz4CLxA9woSdt4szQkvBIxJtR_s8huPIfIQ",
        }
    )
    id_token_encryption_key = id_token_decryption_key.public_jwk()

    id_token_signature_key = Jwk(
        {
            "kty": "EC",
            "crv": "P-256",
            "x": "Q9nRvw5sxTnl93FWc3oHvvbfREUt_1on0WVucVqSPvw",
            "y": "2dNrVWA0LHTwC8vOChVR29HbesoLCwbvaHwHcqKQSG4",
            "d": "pfpik5SEnMh6NcegGPrI0XOlf2YIx4wB7hws6-kO1fE",
            "alg": "ES256",
            "kid": "uiSjaT2_mswJWSBQ6Oj78RjpPnAQVz0iDkyLZHEkFvc",
        }
    )
    id_token_verification_key = id_token_signature_key.public_jwk()

    subject = "user1"
    nonce = "mynonce"

    client_id = "myclientid"
    private_key = Jwk(
        {
            "kty": "EC",
            "crv": "P-256",
            "x": "mKV-T7IbQJwt6sakGn9kN3dCyMWIa3XqA_EyIUs_jzc",
            "y": "8sy4p5BzWwDjAULMokrgkCJwaPWNICTozriOUUA_KQ8",
            "d": "xitL_m0Y1lxjoOQINYcynNTJU-EopW4NiBeiMWE-3O8",
            "alg": "ES256",
            "kid": "Vs6sw5LGsEYfeiAs3rwiOwXKJpw4S926IaOpefvm-Ec",
        }
    )
    token_endpoint = "https://as.local/token"
    authorization_endpoint = "https://as.local/authorize"
    issuer = "https://issuer"

    claims = {"iss": issuer, "iat": Jwt.timestamp(), "exp": Jwt.timestamp(60), "sub": subject, "nonce": nonce}
    id_token = Jwt.sign_and_encrypt(
        claims, sign_key=id_token_signature_key, enc_key=id_token_encryption_key, enc=EncryptionAlgs.A256CBC_HS512
    )

    redirect_uri = "http://localhost:12345/callback"
    client = OAuth2Client(
        client_id=client_id,
        private_key=private_key,
        issuer=issuer,
        token_endpoint=token_endpoint,
        authorization_endpoint=authorization_endpoint,
        redirect_uri=redirect_uri,
        id_token_signed_response_alg="ES256",
        id_token_decryption_key=id_token_decryption_key,
        authorization_server_jwks=id_token_verification_key.as_jwks(),
    )

    state = "mystate"

    authorization_code = "authorization_code"
    authorization_request = client.authorization_request(scope="openid", state=state, nonce=nonce)

    authorization_response = authorization_request.validate_callback(
        furl(redirect_uri).add(args={"code": authorization_code, "state": state, "iss": issuer})
    )

    access_token = "my_access_token"

    requests_mock.post(
        token_endpoint,
        json={"access_token": access_token, "token_type": "Bearer", "expires_in": 3600, "id_token": str(id_token)},
    )
    token_resp = client.authorization_code(authorization_response, validate=True)
    assert isinstance(token_resp.id_token, IdToken)
    assert token_resp.id_token.claims == claims
