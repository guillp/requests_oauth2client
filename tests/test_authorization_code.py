from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

from requests_oauth2client import ClientSecretPost, OAuth2Client
from requests_oauth2client.authorization_code import AuthorizationCodeHandler, PkceHelper
from requests_oauth2client.discovery import oidc_discovery_document_url

load_dotenv(Path(__file__).with_name("authorization_code.env"))

client_id = os.getenv("TEST_CLIENT_ID")
client_secret = os.getenv("TEST_CLIENT_SECRET")
issuer = os.getenv("TEST_ISSUER")
redirect_uri = os.getenv("TEST_REDIRECT_URI")
audience = os.getenv("TEST_AUDIENCE")
scope = os.getenv("TEST_SCOPE")


def test_authorization_code(session):
    discovery_url = oidc_discovery_document_url(issuer)
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
    print(authorization_request.request.url)
    params = input("Callback url or params: ")
    code = authorization_request.validate_callback(params)

    client = OAuth2Client(token_endpoint, ClientSecretPost(client_id, client_secret))
    token = client.authorization_code(code=code, redirect_uri=redirect_uri)
    print(token)


def test_authorization_code_pkce(session):
    discovery_url = oidc_discovery_document_url(issuer)
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
    print(authorization_request.request.url)
    params = input("Callback url or params: ")
    code = authorization_request.validate_callback(params)

    client = OAuth2Client(token_endpoint, ClientSecretPost(client_id, client_secret))
    token = client.authorization_code(
        code=code, redirect_uri=redirect_uri, code_verifier=code_verifier
    )
    print(token)
