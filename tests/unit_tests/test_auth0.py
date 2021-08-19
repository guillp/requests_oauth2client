from requests_oauth2client.vendor_specific import Auth0Client, Auth0ManagementApiClient


def test_auth0_management():
    auth0api = Auth0ManagementApiClient("test.eu", ("client_id", "client_secret"))
    assert auth0api.auth.client.token_endpoint == "https://test.eu.auth0.com/oauth/token"
    assert auth0api.auth.token_kwargs == {"audience": "https://test.eu.auth0.com/api/v2/"}


def test_auth0_client():
    auth0client = Auth0Client("test.eu.auth0.com", ("client_id", "client_secret"))
    assert auth0client.token_endpoint == "https://test.eu.auth0.com/oauth/token"
    assert auth0client.revocation_endpoint == "https://test.eu.auth0.com/oauth/revoke"
    assert auth0client.userinfo_endpoint == "https://test.eu.auth0.com/userinfo"
    assert auth0client.jwks_uri == "https://test.eu.auth0.com/.well-known/jwks.json"


def test_auth0_client_short_tenant_name():
    auth0client = Auth0Client("test.eu", ("client_id", "client_secret"))
    assert auth0client.token_endpoint == "https://test.eu.auth0.com/oauth/token"
    assert auth0client.revocation_endpoint == "https://test.eu.auth0.com/oauth/revoke"
    assert auth0client.userinfo_endpoint == "https://test.eu.auth0.com/userinfo"
    assert auth0client.jwks_uri == "https://test.eu.auth0.com/.well-known/jwks.json"
