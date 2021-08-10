import secrets
from urllib.parse import parse_qs

import pytest

from requests_oauth2client import OAuth2Client
from requests_oauth2client.client_authentication import PublicApp
from requests_oauth2client.exceptions import InvalidTokenResponse

TOKEN_ENDPOINT = "https://as.local/token"
REVOCATION_ENDPOINT = "https://as.local/revoke"

client_id = "client_id"


def test_public_client():
    client = OAuth2Client(TOKEN_ENDPOINT, auth=client_id)
    assert isinstance(client.auth, PublicApp)
    assert client.auth.client_id == client_id


def test_missing_auth():
    with pytest.raises(ValueError):
        client = OAuth2Client(TOKEN_ENDPOINT, auth=None)


def test_from_discovery_document():
    client = OAuth2Client.from_discovery_document(
        {"token_endpoint": TOKEN_ENDPOINT, "revocation_endpoint": REVOCATION_ENDPOINT},
        auth=client_id,
    )
    assert client.token_endpoint == TOKEN_ENDPOINT
    assert client.revocation_endpoint == REVOCATION_ENDPOINT


def test_from_discovery_document_missing_token_endpoint():
    with pytest.raises(ValueError):
        client = OAuth2Client.from_discovery_document(
            {"revocation_endpoint": REVOCATION_ENDPOINT}, auth=client_id,
        )


def test_invalid_token_response(requests_mock):
    client = OAuth2Client(TOKEN_ENDPOINT, auth=client_id)
    requests_mock.post(TOKEN_ENDPOINT, status_code=500, json={"confusing": "data"})
    with pytest.raises(InvalidTokenResponse):
        client.authorization_code("mycode")

    requests_mock.post(
        TOKEN_ENDPOINT, status_code=500, json={"error_description": "this shouldn't happen"}
    )
    with pytest.raises(InvalidTokenResponse):
        client.authorization_code("mycode")


def test_revoke_token(requests_mock):
    client = OAuth2Client(
        TOKEN_ENDPOINT, revocation_endpoint=REVOCATION_ENDPOINT, auth=client_id
    )
    access_token = secrets.token_urlsafe()
    refresh_token = secrets.token_urlsafe()
    new_refresh_token = secrets.token_urlsafe()
    requests_mock.post(
        TOKEN_ENDPOINT,
        json={
            "access_token": access_token,
            "refresh_token": new_refresh_token,
            "token_type": "Bearer",
            "expires_in": 3600,
        },
    )
    token_resp = client.refresh_token(refresh_token)
    assert not token_resp.is_expired()
    assert token_resp.refresh_token == new_refresh_token
    params = parse_qs(requests_mock.last_request.text)
    assert params.get("grant_type") == ["refresh_token"]
    assert params.get("refresh_token") == [refresh_token]
    assert params.get("client_id") == [client_id]

    requests_mock.post(REVOCATION_ENDPOINT)
    assert client.revoke_access_token(token_resp.access_token) is True
    params = parse_qs(requests_mock.last_request.text)
    assert params.get("client_id") == [client_id]
    assert params.get("token") == [access_token]
    assert params.get("token_type_hint") == ["access_token"]

    assert client.revoke_refresh_token(token_resp.refresh_token) is True
    params = parse_qs(requests_mock.last_request.text)
    assert params.get("client_id") == [client_id]
    assert params.get("token") == [new_refresh_token]
    assert params.get("token_type_hint") == ["refresh_token"]


def test_revoke_token_no_revocation_endpoint(requests_mock):
    client = OAuth2Client(TOKEN_ENDPOINT, auth=client_id)
    access_token = secrets.token_urlsafe()
    refresh_token = secrets.token_urlsafe()
    new_refresh_token = secrets.token_urlsafe()
    requests_mock.post(
        TOKEN_ENDPOINT,
        json={
            "access_token": access_token,
            "refresh_token": new_refresh_token,
            "token_type": "Bearer",
            "expires_in": 3600,
        },
    )
    token_resp = client.refresh_token(refresh_token)
    assert not token_resp.is_expired()
    assert token_resp.refresh_token == new_refresh_token
    params = parse_qs(requests_mock.last_request.text)
    assert params.get("grant_type") == ["refresh_token"]
    assert params.get("refresh_token") == [refresh_token]
    assert params.get("client_id") == [client_id]

    assert client.revoke_access_token(token_resp.access_token) is False
    assert client.revoke_refresh_token(token_resp.refresh_token) is False
