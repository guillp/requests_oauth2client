import base64
import hashlib
import secrets
from datetime import datetime, timedelta

import requests
from furl import Query, furl  # type: ignore[import]
from requests_mock import Mocker

from requests_oauth2client import (
    AuthorizationRequest,
    BearerToken,
    ClientSecretPost,
    OAuth2Client,
    oidc_discovery_document_url,
)


def test_authorization_code(
    session: requests.Session,
    requests_mock: Mocker,
    issuer: str,
    discovery_document: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    scope: str,
    audience: str,
) -> None:
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
    assert requests_mock.last_request is not None
    qs = Query(requests_mock.last_request.qs).params
    assert qs.get("client_id") == client_id
    assert qs.get("response_type") == "code"
    assert qs.get("redirect_uri") == redirect_uri
    assert qs.get("state") == state
    code_challenge = qs.get("code_challenge")
    assert code_challenge
    code_challenge_method = requests_mock.last_request.qs.get("code_challenge_method")
    code_verifier = authorization_request.code_verifier
    assert code_verifier is not None
    assert code_challenge_method == ["S256"]
    assert (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(b"=")
        == code_challenge.encode()
    )

    auth_response = authorization_request.validate_callback(location)

    client = OAuth2Client(token_endpoint, ClientSecretPost(client_id, client_secret))

    access_token = secrets.token_urlsafe()

    requests_mock.post(
        token_endpoint,
        json={"access_token": access_token, "token_type": "Bearer", "expires_in": 3600},
    )
    token = client.authorization_code(code=auth_response, redirect_uri=redirect_uri)

    assert isinstance(token, BearerToken)
    assert token.access_token == access_token
    assert not token.is_expired()
    assert token.expires_at is not None
    assert (
        datetime.now() + timedelta(seconds=3598)
        <= token.expires_at
        <= datetime.now() + timedelta(seconds=3600)
    )

    assert requests_mock.last_request is not None
    params = Query(requests_mock.last_request.text).params
    assert params.get("client_id") == client_id
    assert params.get("client_secret") == client_secret
    assert params.get("grant_type") == "authorization_code"
    assert params.get("code") == authorization_code
