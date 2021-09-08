import base64
import hashlib
import secrets
from datetime import datetime, timedelta
from urllib.parse import parse_qs

import requests
from furl import furl

from requests_oauth2client import BearerToken, ClientSecretPost, OAuth2Client
from requests_oauth2client.authorization_request import AuthorizationRequest, PkceUtils
from requests_oauth2client.discovery import oidc_discovery_document_url


def test_authorization_code(
    session,
    requests_mock,
    issuer,
    discovery_document,
    client_id,
    client_secret,
    redirect_uri,
    scope,
    audience,
):
    discovery_url = oidc_discovery_document_url(issuer)
    requests_mock.get(discovery_url, json=discovery_document)
    discovery = session.get(discovery_url).json()
    authorization_endpoint = discovery.get("authorization_endpoint")
    assert authorization_endpoint
    token_endpoint = discovery.get("token_endpoint")
    assert token_endpoint

    authorization_request = AuthorizationRequest(
        authorization_endpoint,
        client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        audience=audience,
    )

    authorization_code = secrets.token_urlsafe()

    state = authorization_request.state

    authorization_response = furl(
        redirect_uri, query={"code": authorization_code, "state": state}
    ).url
    requests_mock.get(
        authorization_request.uri,
        status_code=302,
        headers={"Location": authorization_response},
    )
    resp = requests.get(authorization_request.uri, allow_redirects=False)
    assert resp.status_code == 302
    location = resp.headers.get("Location")
    assert location == authorization_response
    assert requests_mock.last_request.qs.get("client_id") == [client_id]
    assert requests_mock.last_request.qs.get("response_type") == ["code"]
    assert requests_mock.last_request.qs.get("redirect_uri") == [redirect_uri]
    assert requests_mock.last_request.qs.get("state") == [state]

    code = authorization_request.validate_callback(location)

    client = OAuth2Client(token_endpoint, ClientSecretPost(client_id, client_secret))

    access_token = secrets.token_urlsafe()

    requests_mock.post(
        token_endpoint,
        json={"access_token": access_token, "token_type": "Bearer", "expires_in": 3600},
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

    params = parse_qs(requests_mock.last_request.text)
    assert params.get("client_id") == [client_id]
    assert params.get("client_secret") == [client_secret]
    assert params.get("grant_type") == ["authorization_code"]
    assert params.get("code") == [authorization_code]


def test_authorization_code_pkce(
    session,
    requests_mock,
    issuer,
    discovery_document,
    client_id,
    client_secret,
    redirect_uri,
    scope,
    audience,
):
    discovery_url = oidc_discovery_document_url(issuer)
    requests_mock.get(discovery_url, json=discovery_document)
    discovery = session.get(discovery_url).json()
    authorization_endpoint = discovery.get("authorization_endpoint")
    assert authorization_endpoint
    token_endpoint = discovery.get("token_endpoint")
    assert token_endpoint

    code_verifier = PkceUtils.generate_code_verifier()
    authorization_request = AuthorizationRequest(
        authorization_endpoint,
        client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        audience=audience,
        code_verifier=code_verifier,
    )

    authorization_code = secrets.token_urlsafe()
    state = authorization_request.state
    authorization_response = furl(
        redirect_uri, query={"code": authorization_code, "state": state}
    ).url
    requests_mock.get(
        authorization_request.uri,
        status_code=302,
        headers={"Location": authorization_response},
    )
    resp = requests.get(authorization_request.uri, allow_redirects=False)
    assert resp.status_code == 302
    location = resp.headers.get("Location")
    assert location == authorization_response
    assert requests_mock.last_request.qs.get("client_id") == [client_id]
    assert requests_mock.last_request.qs.get("response_type") == ["code"]
    assert requests_mock.last_request.qs.get("redirect_uri") == [redirect_uri]

    code_challenge = requests_mock.last_request.qs.get("code_challenge")[0]
    assert code_challenge
    code_challenge_method = requests_mock.last_request.qs.get("code_challenge_method")
    assert code_challenge_method == ["S256"]
    assert (
        base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).rstrip(b"=")
        == code_challenge.encode()
    )

    code = authorization_request.validate_callback(location)

    client = OAuth2Client(token_endpoint, ClientSecretPost(client_id, client_secret))

    access_token = secrets.token_urlsafe()

    requests_mock.post(
        token_endpoint,
        json={"access_token": access_token, "token_type": "Bearer", "expires_in": 3600},
    )
    token = client.authorization_code(
        code=code, redirect_uri=redirect_uri, code_verifier=code_verifier
    )
    assert isinstance(token, BearerToken)
    assert token.access_token == access_token
    assert not token.is_expired()
    now = datetime.now()
    assert 3598 <= token.expires_in <= 3600
    assert (
        now + timedelta(seconds=3598)
        <= token.expires_at
        <= now + timedelta(seconds=3600)
    )
    params = parse_qs(requests_mock.last_request.text)
    assert params.get("client_id")[0] == client_id
    assert params.get("client_secret")[0] == client_secret
    assert params.get("grant_type")[0] == "authorization_code"
    assert params.get("code")[0] == authorization_code
    assert params.get("code_verifier")[0] == code_verifier
