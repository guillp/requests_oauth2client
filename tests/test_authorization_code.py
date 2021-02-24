import base64
import hashlib
import secrets
from datetime import datetime, timedelta
from urllib.parse import parse_qs

import requests
from furl import furl

from requests_oauth2client import BearerToken, ClientSecretPost, OAuth2Client
from requests_oauth2client.authorization_code import AuthorizationCodeHandler, PkceHelper
from requests_oauth2client.discovery import oidc_discovery_document_url

client_id = "TEST_CLIENT_ID"
client_secret = "TEST_CLIENT_SECRET"
issuer = "https://test.com"
redirect_uri = "TEST_REDIRECT_URI"
audience = "TEST_AUDIENCE"
scope = "TEST_SCOPE"

discovery_document = {
    "authorization_endpoint": furl(issuer, path="/authorize").url,
    "token_endpoint": furl(issuer, path="/token").url,
}


def test_authorization_code(session, requests_mock):

    discovery_url = oidc_discovery_document_url(issuer)
    requests_mock.get(discovery_url, json=discovery_document)
    discovery = session.get(discovery_url).json()
    authorization_endpoint = discovery.get("authorization_endpoint")
    assert authorization_endpoint
    token_endpoint = discovery.get("token_endpoint")
    assert token_endpoint

    authorization_request = AuthorizationCodeHandler(
        authorization_endpoint,
        client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        audience=audience,
    )

    authorization_code = secrets.token_urlsafe()

    def authorization_response_callback(request, context):
        assert request.qs.get("client_id")[0] == client_id
        assert request.qs.get("response_type")[0] == "code"
        assert request.qs.get("redirect_uri")[0] == redirect_uri
        state = request.qs.get("state")
        context.status_code = 302
        query = {"code": authorization_code}
        if state:
            query["state"] = state
        context.headers = {"Location": furl(redirect_uri, query=query).url}
        return "redirection"

    requests_mock.get(authorization_request.request.url, text=authorization_response_callback)
    resp = requests.get(authorization_request.request.url, allow_redirects=False)
    location = resp.headers.get("Location")
    code = authorization_request.validate_callback(location)

    client = OAuth2Client(token_endpoint, ClientSecretPost(client_id, client_secret))

    access_token = secrets.token_urlsafe()

    def token_response_callback(request, context):
        params = parse_qs(request.text)
        assert params.get("client_id")[0] == client_id
        assert params.get("client_secret")[0] == client_secret
        assert params.get("grant_type")[0] == "authorization_code"
        assert params.get("code")[0] == authorization_code

        return {"access_token": access_token, "token_type": "Bearer", "expires_in": 3600}

    requests_mock.post(
        token_endpoint, json=token_response_callback,
    )
    token = client.authorization_code(code=code, redirect_uri=redirect_uri)
    assert isinstance(token, BearerToken)
    assert token.access_token == access_token
    assert not token.is_expired()
    assert (
        datetime.now() + timedelta(seconds=3598)
        <= token.expires_at
        <= datetime.now() + timedelta(seconds=3600)
    )


def test_authorization_code_pkce(session, requests_mock):
    discovery_url = oidc_discovery_document_url(issuer)
    requests_mock.get(discovery_url, json=discovery_document)
    discovery = session.get(discovery_url).json()
    authorization_endpoint = discovery.get("authorization_endpoint")
    assert authorization_endpoint
    token_endpoint = discovery.get("token_endpoint")
    assert token_endpoint

    code_verifier = PkceHelper.generate_code_verifier()
    authorization_request = AuthorizationCodeHandler(
        authorization_endpoint,
        client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        audience=audience,
        code_verifier=code_verifier,
    )

    authorization_code = secrets.token_urlsafe()

    def authorization_response_callback(request, context):
        assert request.qs.get("client_id")[0] == client_id
        assert request.qs.get("response_type")[0] == "code"
        assert request.qs.get("redirect_uri")[0] == redirect_uri

        code_challenge = request.qs.get("code_challenge")
        code_challenge_method = request.qs.get("code_challenge_method")

        assert len(code_challenge) == 1
        code_challenge = code_challenge[0]
        assert code_challenge_method == ["S256"]
        assert (
            base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(
                b"="
            )
            == code_challenge.encode()
        )

        state = request.qs.get("state")
        context.status_code = 302
        query = {"code": authorization_code}
        if state:
            query["state"] = state
        context.headers = {"Location": furl(redirect_uri, query=query).url}
        return "redirection"

    requests_mock.get(authorization_request.request.url, text=authorization_response_callback)
    resp = requests.get(authorization_request.request.url, allow_redirects=False)
    location = resp.headers.get("Location")
    code = authorization_request.validate_callback(location)

    client = OAuth2Client(token_endpoint, ClientSecretPost(client_id, client_secret))

    access_token = secrets.token_urlsafe()

    def token_response(request, context):
        params = parse_qs(request.text)
        assert params.get("client_id")[0] == client_id
        assert params.get("client_secret")[0] == client_secret
        assert params.get("grant_type")[0] == "authorization_code"
        assert params.get("code")[0] == authorization_code
        assert params.get("code_verifier")[0] == code_verifier

        return {"access_token": access_token, "token_type": "Bearer", "expires_in": 3600}

    requests_mock.post(
        token_endpoint, json=token_response,
    )
    token = client.authorization_code(
        code=code, redirect_uri=redirect_uri, code_verifier=code_verifier
    )
    assert isinstance(token, BearerToken)
    assert token.access_token == access_token
    assert not token.is_expired()
    now = datetime.now()
    assert 3598 <= token.expires_in <= 3600
    assert now + timedelta(seconds=3598) <= token.expires_at <= now + timedelta(seconds=3600)
