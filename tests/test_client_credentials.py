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

    def token_response_callback(request, context):
        params = parse_qs(request.text)
        assert params.get("client_id")[0] == client_id
        assert params.get("client_secret")[0] == client_secret
        assert params.get("grant_type")[0] == "client_credentials"

        return {"access_token": access_token, "token_type": "Bearer", "expires_in": 3600}

    requests_mock.post(
        token_endpoint, json=token_response_callback,
    )
    client = OAuth2Client(token_endpoint, ClientSecretPost(client_id, client_secret))
    token_response = client.client_credentials()
    assert token_response.access_token == access_token


def test_client_credentials_api(requests_mock):
    access_token = secrets.token_urlsafe()

    def token_response_callback(request, context):
        params = parse_qs(request.text)
        assert params.get("client_id")[0] == client_id
        assert params.get("client_secret")[0] == client_secret
        assert params.get("grant_type")[0] == "client_credentials"

        return {"access_token": access_token, "token_type": "Bearer", "expires_in": 3600}

    requests_mock.post(
        token_endpoint, json=token_response_callback,
    )
    client = OAuth2Client(token_endpoint, ClientSecretPost(client_id, client_secret))
    auth = OAuth2ClientCredentialsAuth(client)

    requests_mock.get(api, request_headers={"Authorization": f"Bearer {access_token}"})
    response = requests.get(api, auth=auth)
    assert response.ok
