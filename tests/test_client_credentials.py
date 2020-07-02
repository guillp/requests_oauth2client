from __future__ import annotations

import os
from pathlib import Path

import requests
from dotenv import load_dotenv

from requests_oauth2client import ClientSecretPost, OAuth2Client, OAuth2ClientCredentialsAuth

load_dotenv(Path(__file__).with_name("client_credentials.env"))

client_id = os.getenv("TEST_CLIENT_ID")
client_secret = os.getenv("TEST_CLIENT_SECRET")
token_endpoint = os.getenv("TEST_TOKEN_ENDPOINT")
audience = os.getenv("TEST_AUDIENCE")
api = os.getenv("TEST_API")


def test_client_credentials_get_token():
    client = OAuth2Client(token_endpoint, ClientSecretPost(client_id, client_secret))
    token_response = client.client_credentials(audience=audience)
    assert token_response.access_token
    print(token_response.access_token)


def test_client_credentials_api():
    client = OAuth2Client(token_endpoint, ClientSecretPost(client_id, client_secret))
    auth = OAuth2ClientCredentialsAuth(client, audience=audience)
    response = requests.get(api, auth=auth)
    assert response.ok
