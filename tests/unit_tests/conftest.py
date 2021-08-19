import base64
import json
from datetime import datetime
from urllib.parse import parse_qs

import pytest
import requests
from furl import furl
from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT

from requests_oauth2client import (ApiClient, BearerAuth, ClientSecretBasic, ClientSecretJWT,
                                   ClientSecretPost, OAuth2Client, PrivateKeyJWT, PublicApp)


@pytest.fixture()
def session():
    return requests.Session()


@pytest.fixture(scope="session")
def join_url():
    def _join_url(root, path):
        if path:
            f = furl(root).add(path=path)
            f.path.normalize()
            return f.url
        else:
            return root

    return _join_url


@pytest.fixture()
def access_token():
    return "access_token"


@pytest.fixture()
def bearer_auth(access_token):
    return BearerAuth(access_token)


@pytest.fixture()
def target_api():
    return "https://myapi.local/root/"


@pytest.fixture()
def api(target_api, bearer_auth):
    return ApiClient(target_api, auth=bearer_auth)


@pytest.fixture()
def issuer():
    return "https://test.com"


@pytest.fixture()
def token_endpoint(issuer, join_url):
    return join_url(issuer, "oauth/token")


@pytest.fixture()
def authorization_endpoint(issuer, join_url):
    return join_url(issuer, "login/authorize")


@pytest.fixture()
def revocation_endpoint(issuer, join_url):
    return join_url(issuer, "oauth/revoke")


@pytest.fixture()
def introspection_endpoint(issuer, join_url):
    return join_url(issuer, "oauth/introspect")


@pytest.fixture()
def userinfo_endpoint(issuer, join_url):
    return join_url(issuer, "oidc/userinfo")


@pytest.fixture()
def jwks_uri(issuer, join_url):
    return join_url(issuer, "jwks")


@pytest.fixture()
def device_authorization_endpoint(issuer, join_url):
    return join_url(issuer, "device")


@pytest.fixture()
def client_id():
    return "client_id"


@pytest.fixture(params=[PublicApp, ClientSecretPost, ClientSecretBasic, ClientSecretJWT])
def client_auth_method_handler(request):
    return request.param


@pytest.fixture()
def kid():
    return "JWK-ABCD"


@pytest.fixture()
def private_jwk(kid):
    return {
        "kty": "RSA",
        "kid": kid,
        "n": "2jgK-5aws3_fjllgnAacPkwjbz3RCeAHni1pcHvReuTgk9qEiTmXWJiSS_F20VeI1zEwFM36e836ROCyOQ8cjjaPWpdzCajWC0koY7X8MPhZbdoSptOmDBseRCyYqmeMCp8mTTOD6Cs43SiIYSMNlPuio89qjf_4u32eVF_5YqOGtwfzC4p2NUPPCxpljYpAcf2BBG1tRX1mY4WP_8zwmx3ZH7Sy0V_fXI46tzDqfRXdMhHW7ARJAnEr_EJhlMgUaM7FUQKUNpi1ZdeeLxYv44eRx9-Roy5zTG1b0yRuaKaAG3559572quOcxISZzK5Iy7BhE7zxVa9jabEl-Y1Daw",
        "e": "AQAB",
        "d": "XCtpsCRQ1DBBm51yqdQ88C82lEjW30Xp0cy6iVEzBKZhmPGmI1PY8gnXWQ5PMlK3sLTM6yypDNvORoNlo6YXWJYA7LGlXEIczj2DOsJmF8T9-OEwGZixvNFDcmYnwWnlA6N_CQKmR0ziQr9ZAzZMCU5Tvr7f8cRZKdAALQEwk5FYpLnEbXOBduJtY9x2kddJSCJwRaEJhx0fG_pJAO3yLUZBY20dZK8UrxDoCgB9eiZV3N4uWGt367r1MDdaxGY6l6bC1HZCHkttBuTxfSUMCgooZevdU6ThQNpFrwZNY3KoP-OksEdqMs-neecfk_AQREkubDW2VPNFnaVEa38BKQ",
        "p": "8QNZGwUINpkuZi8l2ZfQzKVeOeNe3aQ7UW0wperM-63DFEJDRO1UyNC1n6yeo8_RxPZKSTlr6xZDoilQq23mopeF6O0ZmYz6E2VWJuma65V-A7tB-6xjqUXPlSkCNA6Ia8kMeCmNpKs0r0ijTBf_2y2GSsNH4EcP7XzcDEeJIh0",
        "q": "58nWgg-qRorRddwKM7qhLxJnEDsnCiYhbKJrP78OfBZ-839bNRvL5D5sfjJqxcKMQidgpYZVvVNL8oDEywcC5T7kKW0HK1JUdYiX9DuI40Mv9WzXQ8B8FBjp5wV4IX6_0KgyIiyoUiKpVHBvO0YFPUYuk0Ns4H9yEws93RWwhSc",
        "dp": "zFsLZcaphSnzVr9pd4urhqo9MBZjbMmBZnSQCE8ECe729ymMQlh-SFv3dHF4feuLsVcn-9iNceMJ6-jeNs1T_s89wxevWixYKrQFDa-MJW83T1CrDQvJ4VCJR69i5-Let43cXdLWACcO4AVWOQIsdpquQJw-SKPYlIUHS_4n_90",
        "dq": "fP79rNnhy3TlDBgDcG3-qjHUXo5nuTNi5wCXsaLInuZKw-k0OGmrBIUdYNizd744gRxXJCxTZGvdEwOaHJrFVvcZd7WSHiyh21g0CcNpSJVc8Y8mbyUIRJZC3RC3_egqbM2na4KFqvWCN0UC1wYloSuNxmCgAFj6HYb8b5NYxBU",
        "qi": "hxXfLYgwrfZBvZ27nrPsm6mLuoO-V2rKdOj3-YDJzf0gnVGBLl0DZbgydZ8WZmSLn2290mO_J8XY-Ss8PjLYbz3JXPDNLMJ-da3iEPKTvh6OfliM_dBxhaW8sq5afLMUR0H8NeabbWkfPz5h0W11CCBYxsyPC6CzniFYCYXfByU",
    }


@pytest.fixture()
def private_jwk_no_kid(private_jwk):
    return {key: val for key, val in private_jwk.items() if key != "kid"}


@pytest.fixture()
def private_jwk_no_alg(private_jwk):
    return {key: val for key, val in private_jwk.items() if key != "alg"}


@pytest.fixture()
def public_jwk(private_jwk):
    return {key: val for key, val in private_jwk.items() if key in ("kty", "kid", "n", "e")}


@pytest.fixture()
def client_secret():
    return "client_secret"


@pytest.fixture()
def client_credential(client_auth_method_handler, client_secret, private_jwk):
    if client_auth_method_handler == PublicApp:
        return None
    elif client_auth_method_handler in (ClientSecretPost, ClientSecretBasic, ClientSecretJWT):
        return client_secret
    elif client_auth_method_handler == PrivateKeyJWT:
        return private_jwk


@pytest.fixture()
def client_auth_method(client_auth_method_handler, client_id, client_credential):
    if client_auth_method_handler == PublicApp:
        return client_auth_method_handler(client_id)
    return client_auth_method_handler(client_id, client_credential)


@pytest.fixture()
def client_auth_validator(client_auth_method_handler, client_id, client_credential, public_jwk):
    if client_auth_method_handler == PublicApp:

        def validator(req):
            params = parse_qs(req.text)
            assert params.get("client_id") == [client_id]
            assert "client_secret" not in params

    elif client_auth_method_handler == ClientSecretBasic:

        def validator(req):
            encoded_username_password = base64.b64encode(
                f"{client_id}:{client_secret}".encode("ascii")
            ).decode()
            assert req.headers.get("Authorization") == f"Basic {encoded_username_password}"
            assert "client_secret" not in req.text

    elif client_auth_method_handler == ClientSecretPost:

        def validator(req):
            params = parse_qs(req.text)
            assert params.get("client_id") == [client_id]
            assert params.get("client_secret") == [client_secret]
            assert "Authorization" not in req.headers

    elif client_auth_method_handler == ClientSecretJWT:

        def validator(req):
            params = parse_qs(req.text)
            assert params.get("client_id") == [client_id]
            client_assertion = params.get("client_assertion")[0]
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

    elif client_auth_method_handler == PrivateKeyJWT:

        def validator(req):
            params = parse_qs(req.text)
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

    return validator


@pytest.fixture()
def target_path():
    return "/resource"


@pytest.fixture()
def target_uri(target_api, target_path, join_url):
    return join_url(target_api, target_path)


@pytest.fixture()
def refresh_token():
    return "refresh_token"


@pytest.fixture()
def authorization_code():
    return "authorization_code"


@pytest.fixture()
def device_code():
    return "device_code"


@pytest.fixture()
def user_code():
    return "user_code"


@pytest.fixture()
def redirect_uri():
    return "http://localhost:12345/callback"


@pytest.fixture()
def verification_uri(issuer, join_url):
    return join_url(issuer, "verification")


@pytest.fixture()
def verification_uri_complete(verification_uri, user_code):
    return verification_uri + "?user_code=" + user_code


@pytest.fixture()
def audience():
    return "https://myapi.com/path"


@pytest.fixture()
def scope():
    return "openid profile email"


@pytest.fixture
def discovery_document(
    issuer,
    token_endpoint,
    authorization_endpoint,
    revocation_endpoint,
    introspection_endpoint,
    userinfo_endpoint,
    jwks_uri,
):
    return {
        "issuer": issuer,
        "authorization_endpoint": authorization_endpoint,
        "token_endpoint": token_endpoint,
        "userinfo_endpoint": userinfo_endpoint,
        "revocation_endpoint": revocation_endpoint,
        "introspection_endpoint": introspection_endpoint,
        "jwks_uri": jwks_uri,
    }


@pytest.fixture()
def oauth2client(
    token_endpoint,
    revocation_endpoint,
    introspection_endpoint,
    userinfo_endpoint,
    jwks_uri,
    client_auth_method,
):
    return OAuth2Client(
        token_endpoint,
        revocation_endpoint=revocation_endpoint,
        introspection_endpoint=introspection_endpoint,
        userinfo_endpoint=userinfo_endpoint,
        jwks_uri=jwks_uri,
        auth=client_auth_method,
    )


@pytest.fixture()
def bearer_auth_validator():
    def validator(req, access_token):
        assert req.headers.get("Authorization") == f"Bearer {access_token}"

    return validator


@pytest.fixture()
def sub():
    return "abcdefghijklmnopqrstuvwxyz"


@pytest.fixture()
def code_verifier():
    return "code_verifier"
