from requests_oauth2client.discovery import (oauth2_discovery_document_url,
                                             oidc_discovery_document_url)


def test_oidc_discovery():
    assert (
            oidc_discovery_document_url("https://issuer.com")
            == "https://issuer.com/.well-known/openid-configuration"
    )
    assert (
            oidc_discovery_document_url("https://issuer.com/oidc")
            == "https://issuer.com/oidc/.well-known/openid-configuration"
    )
    assert (
            oidc_discovery_document_url("https://issuer.com/oidc/")
            == "https://issuer.com/oidc/.well-known/openid-configuration"
    )


def test_oauth20_discovery():
    assert (
            oauth2_discovery_document_url("https://issuer.com")
            == "https://issuer.com/.well-known/oauth-authorization-server"
    )
    assert (
            oauth2_discovery_document_url("https://issuer.com/oauth2")
            == "https://issuer.com/.well-known/oauth2/oauth-authorization-server"
    )
    assert (
            oauth2_discovery_document_url("https://issuer.com/oauth2/")
            == "https://issuer.com/.well-known/oauth2/oauth-authorization-server"
    )
