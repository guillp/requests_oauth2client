import secrets
from urllib.parse import parse_qs

import requests

from requests_oauth2client import ClientSecretPost, OAuth2Client, OAuth2ClientCredentialsAuth

client_id = "TEST_CLIENT_ID"
client_secret = "TEST_CLIENT_SECRET"
token_endpoint = "https://test.com/token"
api = "https://test.com/api"


def test_client_credentials_get_token(requests_mock):
    access_token = secrets.token_urlsafe()
    requests_mock.post(
        token_endpoint,
        json={"access_token": access_token, "token_type": "Bearer", "expires_in": 3600},
    )
    client = OAuth2Client(token_endpoint, ClientSecretPost(client_id, client_secret))
    token_response = client.client_credentials()
    assert token_response.access_token == access_token
    params = parse_qs(requests_mock.last_request.text)
    assert params.get("client_id")[0] == client_id
    assert params.get("client_secret")[0] == client_secret
    assert params.get("grant_type")[0] == "client_credentials"


def test_client_credentials_api(requests_mock):
    access_token = secrets.token_urlsafe()

    client = OAuth2Client(token_endpoint, ClientSecretPost(client_id, client_secret))
    auth = OAuth2ClientCredentialsAuth(client)

    requests_mock.post(
        token_endpoint,
        json={"access_token": access_token, "token_type": "Bearer", "expires_in": 3600},
    )
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
