import base64
import hashlib
import secrets
from datetime import datetime, timedelta
from urllib.parse import parse_qs

import requests
from furl import furl

from requests_oauth2client import AuthorizationRequest, ClientSecretPost, PkceUtils
from requests_oauth2client.discovery import oidc_discovery_document_url
from requests_oauth2client.oidc import OpenIdConnectClient, OpenIdConnectTokenResponse

CLIENT_ID = "TEST_CLIENT_ID"
CLIENT_SECRET = "TEST_CLIENT_SECRET"
ISSUER = "https://test.com"
REDIRECT_URI = "TEST_REDIRECT_URI"
RESOURCE_PARAMS = {"audience": "TEST_AUDIENCE", "scope": "openid TEST_SCOPE"}
ID_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

AUTHORIZATION_ENDPOINT = furl(ISSUER, path="/authorize").url
TOKEN_ENDPOINT = furl(ISSUER, path="/token").url
USERINFO_ENDPOINT = furl(ISSUER, path="/userinfo").url
JWKS_URI = furl(ISSUER, path="/jwks").url

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
        **RESOURCE_PARAMS,
    )

    authorization_code = secrets.token_urlsafe()
    state = authorization_request.state
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
    token = client.authorization_code(code=code, code_verifier=code_verifier)

    form = parse_qs(requests_mock.last_request.text)
    assert form.pop("client_id")[0] == CLIENT_ID
    assert form.pop("client_secret")[0] == CLIENT_SECRET
    assert form.pop("grant_type")[0] == "authorization_code"
    assert form.pop("code")[0] == authorization_code
    assert form.pop("code_verifier")[0] == code_verifier
    assert not form, "extra parameters in form data"

    assert isinstance(token, OpenIdConnectTokenResponse)
    assert token.access_token == access_token
    assert not token.is_expired()
    assert token.expires_at == datetime.now() + timedelta(seconds=3600)
    assert token.id_token == ID_TOKEN
