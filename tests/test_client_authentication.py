import base64
import json
import secrets
from datetime import datetime
from urllib.parse import parse_qs
from uuid import uuid4

import pytest
import requests
from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT
from requests_mock import ANY

from requests_oauth2client import (ClientSecretBasic, ClientSecretJWT, ClientSecretPost,
                                   OAuth2Client, OAuth2ClientCredentialsAuth, PrivateKeyJWT)

client_id = "TEST_CLIENT_ID"
kid = "JWK-ABCD"
client_secret = "TEST_CLIENT_SECRET"
private_jwk = {
    "kty": "RSA",
    "n": "2jgK-5aws3_fjllgnAacPkwjbz3RCeAHni1pcHvReuTgk9qEiTmXWJiSS_F20VeI1zEwFM36e836ROCyOQ8cjjaPWpdzCajWC0koY7X8MPhZbdoSptOmDBseRCyYqmeMCp8mTTOD6Cs43SiIYSMNlPuio89qjf_4u32eVF_5YqOGtwfzC4p2NUPPCxpljYpAcf2BBG1tRX1mY4WP_8zwmx3ZH7Sy0V_fXI46tzDqfRXdMhHW7ARJAnEr_EJhlMgUaM7FUQKUNpi1ZdeeLxYv44eRx9-Roy5zTG1b0yRuaKaAG3559572quOcxISZzK5Iy7BhE7zxVa9jabEl-Y1Daw",
    "e": "AQAB",
    "d": "XCtpsCRQ1DBBm51yqdQ88C82lEjW30Xp0cy6iVEzBKZhmPGmI1PY8gnXWQ5PMlK3sLTM6yypDNvORoNlo6YXWJYA7LGlXEIczj2DOsJmF8T9-OEwGZixvNFDcmYnwWnlA6N_CQKmR0ziQr9ZAzZMCU5Tvr7f8cRZKdAALQEwk5FYpLnEbXOBduJtY9x2kddJSCJwRaEJhx0fG_pJAO3yLUZBY20dZK8UrxDoCgB9eiZV3N4uWGt367r1MDdaxGY6l6bC1HZCHkttBuTxfSUMCgooZevdU6ThQNpFrwZNY3KoP-OksEdqMs-neecfk_AQREkubDW2VPNFnaVEa38BKQ",
    "p": "8QNZGwUINpkuZi8l2ZfQzKVeOeNe3aQ7UW0wperM-63DFEJDRO1UyNC1n6yeo8_RxPZKSTlr6xZDoilQq23mopeF6O0ZmYz6E2VWJuma65V-A7tB-6xjqUXPlSkCNA6Ia8kMeCmNpKs0r0ijTBf_2y2GSsNH4EcP7XzcDEeJIh0",
    "q": "58nWgg-qRorRddwKM7qhLxJnEDsnCiYhbKJrP78OfBZ-839bNRvL5D5sfjJqxcKMQidgpYZVvVNL8oDEywcC5T7kKW0HK1JUdYiX9DuI40Mv9WzXQ8B8FBjp5wV4IX6_0KgyIiyoUiKpVHBvO0YFPUYuk0Ns4H9yEws93RWwhSc",
    "dp": "zFsLZcaphSnzVr9pd4urhqo9MBZjbMmBZnSQCE8ECe729ymMQlh-SFv3dHF4feuLsVcn-9iNceMJ6-jeNs1T_s89wxevWixYKrQFDa-MJW83T1CrDQvJ4VCJR69i5-Let43cXdLWACcO4AVWOQIsdpquQJw-SKPYlIUHS_4n_90",
    "dq": "fP79rNnhy3TlDBgDcG3-qjHUXo5nuTNi5wCXsaLInuZKw-k0OGmrBIUdYNizd744gRxXJCxTZGvdEwOaHJrFVvcZd7WSHiyh21g0CcNpSJVc8Y8mbyUIRJZC3RC3_egqbM2na4KFqvWCN0UC1wYloSuNxmCgAFj6HYb8b5NYxBU",
    "qi": "hxXfLYgwrfZBvZ27nrPsm6mLuoO-V2rKdOj3-YDJzf0gnVGBLl0DZbgydZ8WZmSLn2290mO_J8XY-Ss8PjLYbz3JXPDNLMJ-da3iEPKTvh6OfliM_dBxhaW8sq5afLMUR0H8NeabbWkfPz5h0W11CCBYxsyPC6CzniFYCYXfByU",
}
public_jwk = {
    "kty": "RSA",
    "n": "2jgK-5aws3_fjllgnAacPkwjbz3RCeAHni1pcHvReuTgk9qEiTmXWJiSS_F20VeI1zEwFM36e836ROCyOQ8cjjaPWpdzCajWC0koY7X8MPhZbdoSptOmDBseRCyYqmeMCp8mTTOD6Cs43SiIYSMNlPuio89qjf_4u32eVF_5YqOGtwfzC4p2NUPPCxpljYpAcf2BBG1tRX1mY4WP_8zwmx3ZH7Sy0V_fXI46tzDqfRXdMhHW7ARJAnEr_EJhlMgUaM7FUQKUNpi1ZdeeLxYv44eRx9-Roy5zTG1b0yRuaKaAG3559572quOcxISZzK5Iy7BhE7zxVa9jabEl-Y1Daw",
    "e": "AQAB",
}
token_endpoint = "https://test.com/token"
api = "https://test.com/api"


def test_client_secret_post(requests_mock):
    access_token = secrets.token_urlsafe()

    requests_mock.post(
        token_endpoint,
        json={"access_token": access_token, "token_type": "Bearer", "expires_in": 3600},
    )
    client = OAuth2Client(token_endpoint, ClientSecretPost(client_id, client_secret))
    auth = OAuth2ClientCredentialsAuth(client)

    requests_mock.get(api, request_headers={"Authorization": f"Bearer {access_token}"})
    response = requests.get(api, auth=auth)
    assert response.ok
    assert len(requests_mock.request_history) == 2
    token_request = requests_mock.request_history[0]
    api_request = requests_mock.request_history[1]
    params = parse_qs(token_request.text)
    assert params.get("client_id") == [client_id]
    assert params.get("client_secret") == [client_secret]
    assert params.get("grant_type") == ["client_credentials"]

    assert api_request.headers.get("Authorization") == f"Bearer {access_token}"


def test_client_secret_basic(requests_mock):
    access_token = secrets.token_urlsafe()

    requests_mock.post(
        token_endpoint,
        json={"access_token": access_token, "token_type": "Bearer", "expires_in": 3600},
    )
    client = OAuth2Client(token_endpoint, ClientSecretBasic(client_id, client_secret))
    auth = OAuth2ClientCredentialsAuth(client)

    requests_mock.get(api, request_headers={"Authorization": f"Bearer {access_token}"})
    response = requests.get(api, auth=auth)
    assert response.ok
    assert len(requests_mock.request_history) == 2
    token_request = requests_mock.request_history[0]
    api_request = requests_mock.request_history[1]
    params = parse_qs(token_request.text)
    encoded_username_password = base64.b64encode(
        f"{client_id}:{client_secret}".encode("ascii")
    ).decode()
    assert token_request.headers.get("Authorization") == f"Basic {encoded_username_password}"
    assert params.get("grant_type") == ["client_credentials"]

    assert api_request.headers.get("Authorization") == f"Bearer {access_token}"


def test_private_key_jwt(requests_mock):
    access_token = secrets.token_urlsafe()

    requests_mock.post(
        token_endpoint,
        json={"access_token": access_token, "token_type": "Bearer", "expires_in": 3600},
    )
    client = OAuth2Client(
        token_endpoint, PrivateKeyJWT(client_id, private_jwk=private_jwk, kid=kid)
    )
    token_response = client.client_credentials()
    assert token_response.access_token == access_token

    params = parse_qs(requests_mock.last_request.text)
    assert params.get("client_id") == [client_id], "invalid client_id"
    client_assertion = params.get("client_assertion")[0]
    assert client_assertion, "missing client_assertion"
    jwt = JWT(jwt=client_assertion, key=JWK(**public_jwk))
    claims = json.loads(jwt.claims)
    now = int(datetime.now().timestamp())
    assert now - 10 <= claims["iat"] <= now, "Unexpected iat"
    assert now + 10 < claims["exp"] < now + 180, "unexpected exp"
    assert claims["iss"] == client_id
    assert claims["aud"] == token_endpoint
    assert "jti" in claims
    assert claims["sub"] == client_id

    assert params.get("grant_type")[0] == "client_credentials", "invalid grant_type"


def test_private_key_jwt_with_kid(requests_mock):
    private_jwk_with_kid = dict(private_jwk, kid=kid)
    client = OAuth2Client(
        token_endpoint, PrivateKeyJWT(client_id, private_jwk=private_jwk_with_kid)
    )

    access_token = secrets.token_urlsafe()
    requests_mock.post(
        token_endpoint,
        json={"access_token": access_token, "token_type": "Bearer", "expires_in": 3600},
    )
    token_response = client.client_credentials()
    assert token_response.access_token == access_token

    params = parse_qs(requests_mock.last_request.text)
    assert params.get("client_id")[0] == client_id, "invalid client_id"
    client_assertion = params.get("client_assertion")[0]
    assert client_assertion, "missing client_assertion"
    jwt = JWT(jwt=client_assertion, key=JWK(**public_jwk))
    claims = json.loads(jwt.claims)
    now = int(datetime.now().timestamp())
    assert now - 10 <= claims["iat"] <= now, "Unexpected iat"
    assert now + 10 < claims["exp"] < now + 180, "unexpected exp"
    assert claims["iss"] == client_id
    assert claims["aud"] == token_endpoint
    assert "jti" in claims
    assert claims["sub"] == client_id

    assert params.get("grant_type")[0] == "client_credentials", "invalid grant_type"


def test_client_secret_jwt(requests_mock):
    access_token = secrets.token_urlsafe()

    requests_mock.post(
        token_endpoint,
        json={"access_token": access_token, "token_type": "Bearer", "expires_in": 3600},
    )
    client = OAuth2Client(token_endpoint, ClientSecretJWT(client_id, client_secret))
    token_response = client.client_credentials()
    assert token_response.access_token == access_token

    params = parse_qs(requests_mock.last_request.text)
    assert params.get("client_id")[0] == client_id, "invalid client_id"
    client_assertion = params.get("client_assertion")[0]
    assert client_assertion, "missing client_assertion"
    jwk = JWK(
        kty="oct",
        alg="HS256",
        k=base64.urlsafe_b64encode(client_secret.encode()).decode().rstrip("="),
    )
    jwt = JWT(jwt=client_assertion, key=jwk)
    claims = json.loads(jwt.claims)
    now = int(datetime.now().timestamp())
    assert now - 10 <= claims["iat"] <= now, "unexpected iat"
    assert now + 10 < claims["exp"] < now + 180, "unexpected exp"
    assert claims["iss"] == client_id
    assert claims["aud"] == token_endpoint
    assert "jti" in claims
    assert claims["sub"] == client_id

    assert params.get("grant_type")[0] == "client_credentials", "invalid grant_type"


def test_public_client(requests_mock):
    access_token = secrets.token_urlsafe()

    requests_mock.post(
        token_endpoint,
        json={"access_token": access_token, "token_type": "Bearer", "expires_in": 3600},
    )
    client = OAuth2Client(token_endpoint, client_id)
    auth = OAuth2ClientCredentialsAuth(client)

    requests_mock.get(api, request_headers={"Authorization": f"Bearer {access_token}"})
    response = requests.get(api, auth=auth)
    assert response.ok
    assert len(requests_mock.request_history) == 2
    token_request = requests_mock.request_history[0]
    api_request = requests_mock.request_history[1]
    params = parse_qs(token_request.text)
    assert params.get("client_id") == [client_id]
    assert params.get("grant_type") == ["client_credentials"]

    assert api_request.headers.get("Authorization") == f"Bearer {access_token}"


def test_invalid_request(requests_mock):
    requests_mock.get(ANY)
    with pytest.raises(RuntimeError):
        requests.get("http://localhost", auth=ClientSecretBasic(client_id, client_secret))


def test_private_key_jwt_missing_alg():
    private_jwk_no_alg = private_jwk.copy()
    with pytest.raises(ValueError):
        PrivateKeyJWT(client_id=client_id, private_jwk=private_jwk_no_alg, alg=None)


def test_private_key_jwt_missing_kid():
    private_jwk_no_kid = private_jwk.copy()
    with pytest.raises(ValueError):
        PrivateKeyJWT(client_id=client_id, private_jwk=private_jwk_no_kid)


def test_jti():
    auth = PrivateKeyJWT(client_id=client_id, private_jwk=private_jwk, kid=kid)
    jti = uuid4()
    audience = "audience"
    auth.client_assertion(jti=jti, audience=audience)
    auth.client_assertion(jti=lambda: jti, audience=audience)
