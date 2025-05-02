import pytest

from requests_oauth2client import (
    ApiClient,
    MismatchingAuthorizationServerIdentifier,
    MismatchingResourceIdentifier,
    OAuth2Client,
    OAuth2ClientCredentialsAuth,
)
from tests.conftest import RequestsMocker


def test_rfc9728_offline() -> None:
    """Test the RFC 9728 example."""
    client = OAuth2Client.from_discovery_document(
        {"issuer": "https://as.local", "token_endpoint": "https://as.local/token"},
        client_id="myclientid",
        client_secret="myclientsecret",
    )
    auth = OAuth2ClientCredentialsAuth(client=client)

    api = ApiClient.from_metadata_document(
        resource="https://api.local",
        document={
            "resource": "https://api.local",
            "authorization_servers": ["https://as.local"],
        },
        auth=auth,
    )

    assert api.base_url == "https://api.local"
    assert api.auth is auth


def test_rfc9728_get(requests_mock: RequestsMocker) -> None:
    requests_mock.get(
        "https://api.local/.well-known/oauth-protected-resource",
        json={
            "resource": "https://api.local",
            "authorization_servers": ["https://as.local"],
        },
    )
    client = OAuth2Client.from_discovery_document(
        {"issuer": "https://as.local", "token_endpoint": "https://as.local/token"},
        client_id="myclientid",
        client_secret="myclientsecret",
    )
    auth = OAuth2ClientCredentialsAuth(client=client)
    api = ApiClient.from_metadata_endpoint(
        resource="https://api.local",
        auth=auth,
    )
    prm_request = requests_mock.last_request
    assert prm_request is not None
    assert prm_request.method == "GET"
    assert prm_request.url == "https://api.local/.well-known/oauth-protected-resource"
    assert prm_request.headers["Accept"] == "application/json"
    assert "Authorization" not in prm_request.headers

    assert api.base_url == "https://api.local"
    assert api.auth is auth


def test_enable_dpop() -> None:
    """If the resource metadata enforces DPoP, auto-enable it for the auth handler."""
    client = OAuth2Client.from_discovery_document(
        {"issuer": "https://as.local", "token_endpoint": "https://as.local/token"},
        client_id="myclientid",
        client_secret="myclientsecret",
    )
    auth = OAuth2ClientCredentialsAuth(client=client, scope="foo")
    assert "dpop" not in auth.token_kwargs

    api = ApiClient.from_metadata_document(
        resource="https://api.local",
        document={
            "resource": "https://api.local",
            "authorization_servers": ["https://as.local"],
            "dpop_bound_access_tokens_required": True,
        },
        auth=auth,
    )

    assert api.base_url == "https://api.local"
    assert api.auth is auth
    assert isinstance(api.auth, OAuth2ClientCredentialsAuth)
    assert api.auth.token_kwargs["dpop"] is True


def test_mismatching_resource(requests_mock: RequestsMocker) -> None:
    """Test that a mismatching resource raises an error."""
    client = OAuth2Client.from_discovery_document(
        {"issuer": "https://as.local", "token_endpoint": "https://as.local/token"},
        client_id="myclientid",
        client_secret="myclientsecret",
    )
    auth = OAuth2ClientCredentialsAuth(client=client, scope="foo")

    requests_mock.get(
        "https://api.local/.well-known/oauth-protected-resource",
        json={
            "resource": "https://other.local",
            "authorization_servers": ["https://as.local"],
        },
    )
    with pytest.raises(MismatchingResourceIdentifier):
        ApiClient.from_metadata_endpoint(
            resource="https://api.local",
            auth=auth,
        )


def test_mismatching_auth_server() -> None:
    """Test that a mismatching auth server raises an error."""
    client = OAuth2Client.from_discovery_document(
        {"issuer": "https://as.local", "token_endpoint": "https://as.local/token"},
        client_id="myclientid",
        client_secret="myclientsecret",
    )
    auth = OAuth2ClientCredentialsAuth(client=client, scope="foo")

    with pytest.raises(MismatchingAuthorizationServerIdentifier):
        ApiClient.from_metadata_document(
            resource="https://api.local",
            document={
                "resource": "https://api.local",
                "authorization_servers": ["https://other.local"],
            },
            auth=auth,
        )
