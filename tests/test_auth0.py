from requests_oauth2client.vendor_specific import Auth0ManagementApiClient, Auth0OIDCClient


def test_auth0():
    auth0api = Auth0ManagementApiClient("test.eu", ("client_id", "client_secret"))
    assert auth0api.auth.client.token_endpoint == "https://test.eu.auth0.com/oauth/token"
    assert auth0api.auth.token_kwargs == {"audience": "https://test.eu.auth0.com/api/v2/"}


def test_auth0_oidc():
    auth0client = Auth0OIDCClient("test.eu", ("client_id", "client_secret"))
    assert auth0client.token_endpoint == "https://test.eu.auth0.com/oauth/token"
    assert auth0client.revocation_endpoint == "https://test.eu.auth0.com/oauth/revoke"
    assert auth0client.userinfo_endpoint == "https://test.eu.auth0.com/userinfo"
    assert auth0client.jwks_uri == "https://test.eu.auth0.com/.well-known/jwks.json"
