import base64
import hashlib
import secrets
from datetime import datetime, timedelta
from urllib.parse import parse_qs

import pytest
import requests
from furl import furl

from requests_oauth2client import AuthorizationRequest, ClientSecretPost, PkceUtils
from requests_oauth2client.discovery import oidc_discovery_document_url
from requests_oauth2client.oidc import IdToken, OpenIdConnectClient, OpenIdConnectTokenResponse

CLIENT_ID = "TEST_CLIENT_ID"
CLIENT_SECRET = "TEST_CLIENT_SECRET"
ISSUER = "https://test.com"
REDIRECT_URI = "TEST_REDIRECT_URI"
RESOURCE_PARAMS = {"audience": "TEST_AUDIENCE", "scope": "openid TEST_SCOPE"}
NONCE = "Dn6w52ziDGDHUQr4rBvdwP7B5G8LNk3kVF8fqmLrvK8"
NAME = "John Doe"
SUB = "1234567890"
ID_TOKEN = "eyJhbGciOiJSUzI1NiIsImtpZCI6IklELVRva2VuLVNpZ25pbmcifQ.eyJpYXQiOjE1MTYyMzkwMjIsImlzcyI6Imh0dHBzOi8vdGVzdC5jb20iLCJuYW1lIjoiSm9obiBEb2UiLCJub25jZSI6IkRuNnc1MnppREdESFVRcjRyQnZkd1A3QjVHOExOazNrVkY4ZnFtTHJ2SzgiLCJzdWIiOiIxMjM0NTY3ODkwIn0.MuDliHl6czGyIvwTDMGj4NMRtKtoqotDkUaAGxh9vGOC1DOT43iSYaYxjsWOScujuUsY3hjai_Ezbz6B9pp0OrKI1VGl9pVPs3TKPRswvCUTH__2bWW70QpkVgoahBvycHGa2DrL5-tPmPsTju8noCFE5EzEv_ymCrb416QpQgAWzOQKVsYtdt2yZiYA8yA6X9tO8SypdFmidqlRju3DPJbz70u_OODZ1nlca8khR4u63vpcUeEfUbsgSpOkWcaptQKfR4t2tMbC7aSmALadcNAmVb7DCtu_zkHf_LqkFOj2W2DsXQqLjnbktfIPynYsJYyBqVzqWihNlL-vtQRrjg"

AUTHORIZATION_ENDPOINT = furl(ISSUER, path="/authorize").url
TOKEN_ENDPOINT = furl(ISSUER, path="/token").url
USERINFO_ENDPOINT = furl(ISSUER, path="/userinfo").url
JWKS_URI = furl(ISSUER, path="/jwks").url
KID = "ID-Token-Signing"
ALG = "RS256"
JWK = {
    "kty": "RSA",
    "kid": KID,
    "n": "vKAyVSIXUCmuXhTu5hSKbvnDkiM0IfhpOYnLzSInak3ASFwa61Jl2i73twyjP_I_5qW0pRp6XnpOyJx9q4XIcyEc0WaZVqP6MLxoD6xzyh-PCZR37smOWm0PKD9-7isF_c6LezK8K_Prf3zVhEgGl8eIdqL8u-5NVn5tAV54AfpYBNaLgCcC0emUJNviR8HWlu_OR1TiDuVGl7VKVyWjvFYoiG-6_5c6rfP7Pt3arbUpBG6yhEE2XGd24eqR6DlSQUlJ7xGq2SSCn8_hLiXG0Ap8yYbhwYLw0npWM5-n1IVkP7HpMclb4h9pjOW_oJC4maGJKqZGLEgyi0EXu33Pkw",
    "e": "AQAB",
}
JWKS = {"keys": [JWK]}

PRIVATE_JWK = {
    "kty": "RSA",
    "n": "vKAyVSIXUCmuXhTu5hSKbvnDkiM0IfhpOYnLzSInak3ASFwa61Jl2i73twyjP_I_5qW0pRp6XnpOyJx9q4XIcyEc0WaZVqP6MLxoD6xzyh-PCZR37smOWm0PKD9-7isF_c6LezK8K_Prf3zVhEgGl8eIdqL8u-5NVn5tAV54AfpYBNaLgCcC0emUJNviR8HWlu_OR1TiDuVGl7VKVyWjvFYoiG-6_5c6rfP7Pt3arbUpBG6yhEE2XGd24eqR6DlSQUlJ7xGq2SSCn8_hLiXG0Ap8yYbhwYLw0npWM5-n1IVkP7HpMclb4h9pjOW_oJC4maGJKqZGLEgyi0EXu33Pkw",
    "e": "AQAB",
    "d": "GrNejJiHzkwoJ5809hLASddHLN-Y2JouYvuzgrUr-StKZbPMB7WhP1JYtGuwjDPBgefA-4IVAlyz3Efyrh4A8vMj_ixU1mPd3Zo97MIPnfP7rnJ6y61yXjCD7cGXOSWT8oqTSfwzkNE1a9WC7_e2HzQaiBioR_4CqpS433G88SJ9cJ-W4gbdHtkOO8z3uTRCFyI2ZaJx_1xluSPJ_Kh8ydSSnyeS_j4IcE1u8ejrSsXPefDlsM5swOH12ADHZyuTjuRj438hOqMF2mHduudSpMazoQl1nnrolLKmrODanCGcpd2geVUULodk_ob9nf_JQdXK_KzEfUTX-GM4nxchqQ",
    "p": "8Aflm05sBIvYj0fKWPxKfRg1w6k_DIyCMW1rjayVGDINk_yLGQEmOpsnnOrt4mpeQgschGEhUO66tDICKcm479ysGllzElEwlqbY0ZAQRju9jAnM1KPEGx5jRlzruluI9wPBWA9YD1LlJdSdtB8Klsclv2ikQ0pZnFJQtGhZ5c8",
    "q": "ySzKUZaK3QB-irQxzuKMz3shiUF6-vYVH8ZE54JYbo53z4ZXUGZyXHryI63DZegwnvUdwngdSWy3h7elF0tfKtTDFH05k9-52R0maUC6bFluPI9ZnaIwAC7o23nixUtkjJi8C0WOUKB1af8XR8YkU_IF_Urp_7xWlhP73ggdrv0",
    "dp": "r0B0ykIl5-PbSDHYccQy9sb4alVmLVlhrYkAoD5D1ZimBUi8npMSQHQMJiv5Z_jVvU6zkYwBcT_8nZhtr-kS2D68gbiRpewVl8lWQRv4Ze80Y8y7-v1fL5WuUi-CBVzT0dayEgOR_g4-NLLaOir35kKdMvXKCT990f7f4fjWuk0",
    "dq": "nBENW8IoNE8f3EbypQcIKiXh3HNaDrs9pArSha-PHyWTOQGFVzBC5A_VLWyuO66nmYma7rT0M3QN5VHI14t3Zujr9kc3lcpoiVCd7eVzOn8ekAi9gxbBmkLKDwo9rMVSWehbaXsqbs4siHCHBP1oTV9i2h917RmVKpSSPquZK5k",
    "qi": "XFbdDTDuNw9IvjjFbtqrJuR4vb6MRCrl0HY13rdx9s-CN8X2Ituvy5zUb2II0Zk2vJNXYH1Y5O_j7jye5Cd9xKbaxxj-rIpmCtxpbEjePK39p7ZIG26IdRs0-QQ0_-_Re6oEqKxnd7PiaIM8vLrb6O9rweJb2rjPaHrewophG24",
}


discovery_document = {
    "authorization_endpoint": AUTHORIZATION_ENDPOINT,
    "token_endpoint": TOKEN_ENDPOINT,
    "userinfo_endpoint": USERINFO_ENDPOINT,
    "jwks_uri": JWKS_URI,
}


def test_oidc(requests_mock):
    discovery_url = oidc_discovery_document_url(ISSUER)
    requests_mock.get(url=discovery_url, json=discovery_document)
    client = OpenIdConnectClient.from_discovery_endpoint(
        discovery_url, ClientSecretPost(CLIENT_ID, CLIENT_SECRET)
    )
    assert client.token_endpoint == TOKEN_ENDPOINT
    assert client.userinfo_endpoint == USERINFO_ENDPOINT

    code_verifier = PkceUtils.generate_code_verifier()
    authorization_request = AuthorizationRequest(
        AUTHORIZATION_ENDPOINT,
        CLIENT_ID,
        redirect_uri=REDIRECT_URI,
        code_verifier=code_verifier,
        nonce=NONCE,
        **RESOURCE_PARAMS,
    )

    authorization_code = secrets.token_urlsafe()
    state = authorization_request.state
    nonce = authorization_request.nonce
    auth_response = furl(REDIRECT_URI, query={"code": authorization_code, "state": state}).url

    requests_mock.get(
        url=authorization_request.request.url,
        status_code=302,
        headers={"Location": auth_response},
    )
    resp = requests.get(authorization_request.request.url, allow_redirects=False)

    params = dict(requests_mock.last_request.qs)
    assert params.pop("client_id") == [CLIENT_ID]
    assert params.pop("response_type") == ["code"]
    assert params.pop("redirect_uri") == [REDIRECT_URI]
    assert params.pop("state") == [state]
    assert params.pop("nonce") == [nonce]

    assert params.pop("code_challenge_method") == ["S256"]
    code_challenge = params.pop("code_challenge")[0]

    assert (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(b"=")
        == code_challenge.encode()
    )

    for attr, value in RESOURCE_PARAMS.items():
        assert params.pop(attr) == [value]

    assert not params, "extra parameters passed in authorization request"

    location = resp.headers.get("Location")
    code = authorization_request.validate_callback(location)

    access_token = secrets.token_urlsafe()

    requests_mock.post(
        url=TOKEN_ENDPOINT,
        json={
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": ID_TOKEN,
        },
    )
    token_resp = client.authorization_code(code=code, code_verifier=code_verifier)

    form = parse_qs(requests_mock.last_request.text)
    assert form.pop("client_id")[0] == CLIENT_ID
    assert form.pop("client_secret")[0] == CLIENT_SECRET
    assert form.pop("grant_type")[0] == "authorization_code"
    assert form.pop("code")[0] == authorization_code
    assert form.pop("code_verifier")[0] == code_verifier
    assert not form, "extra parameters in form data"

    assert isinstance(token_resp, OpenIdConnectTokenResponse)
    assert token_resp.access_token == access_token
    assert not token_resp.is_expired()

    now = datetime.now()
    assert 3598 <= token_resp.expires_in <= 3600
    assert (
        now + timedelta(seconds=3598) <= token_resp.expires_at <= now + timedelta(seconds=3600)
    )

    assert token_resp.id_token == ID_TOKEN
    assert token_resp.id_token == IdToken(ID_TOKEN)
    assert not token_resp.id_token == 6.5

    assert token_resp.id_token.validate(ISSUER, JWK, nonce=authorization_request.nonce)
    assert token_resp.id_token.validate(ISSUER, JWKS, nonce=authorization_request.nonce)

    assert token_resp.id_token.alg == ALG
    assert token_resp.id_token.kid == KID
    assert token_resp.id_token.name == NAME

    requests_mock.post(USERINFO_ENDPOINT, json={"sub": SUB, "name": NAME})
    userinfo_resp = client.userinfo(token_resp.access_token)

    assert userinfo_resp["sub"] == SUB
    assert userinfo_resp["name"] == NAME


def test_invalid_id_token():
    id_token = IdToken(ID_TOKEN)
    with pytest.raises(ValueError):
        id_token.validate("https://wrong.issuer", JWK, NONCE)
    wrong_jwk = JWK.copy()
    wrong_jwk["n"] = JWK["n"][4:]
    with pytest.raises(ValueError):
        id_token.validate(ISSUER, wrong_jwk, NONCE)
    with pytest.raises(ValueError):
        id_token.validate(ISSUER, JWK, "wrong_nonce")
