import pytest

from requests_oauth2client import OAuth2ClientCredentialsAuth
from requests_oauth2client.vendor_specific import Auth0


def test_auth0_management() -> None:
    auth0api = Auth0.management_api_client("test.eu.auth0.com", ("client_id", "client_secret"))
    assert auth0api.auth is not None
    assert isinstance(auth0api.auth, OAuth2ClientCredentialsAuth)
    assert auth0api.auth.client is not None
    assert auth0api.auth.client.token_endpoint == "https://test.eu.auth0.com/oauth/token"
    assert auth0api.auth.token_kwargs == {"audience": "https://test.eu.auth0.com/api/v2/"}


def test_auth0_client() -> None:
    auth0client = Auth0.client("test.eu.auth0.com", ("client_id", "client_secret"))
    assert auth0client.token_endpoint == "https://test.eu.auth0.com/oauth/token"
    assert auth0client.revocation_endpoint == "https://test.eu.auth0.com/oauth/revoke"
    assert auth0client.userinfo_endpoint == "https://test.eu.auth0.com/userinfo"
    assert auth0client.jwks_uri == "https://test.eu.auth0.com/.well-known/jwks.json"


def test_auth0_client_short_tenant_name() -> None:
    auth0client = Auth0.client("test.eu", ("client_id", "client_secret"))
    assert auth0client.token_endpoint == "https://test.eu.auth0.com/oauth/token"
    assert auth0client.revocation_endpoint == "https://test.eu.auth0.com/oauth/revoke"
    assert auth0client.userinfo_endpoint == "https://test.eu.auth0.com/userinfo"
    assert auth0client.jwks_uri == "https://test.eu.auth0.com/.well-known/jwks.json"


def test_tenant() -> None:
    assert Auth0.tenant("https://mytenant.eu.auth0.com") == "mytenant.eu.auth0.com"
    assert Auth0.tenant("mytenant.eu") == "mytenant.eu.auth0.com"
    with pytest.raises(ValueError):
        Auth0.tenant("ftp://mytenant.eu")
    with pytest.raises(ValueError):
        Auth0.tenant("")
