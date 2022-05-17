from requests_oauth2client import (
    oauth2_discovery_document_url,
    oidc_discovery_document_url,
    well_known_uri,
)


def test_well_known_uri() -> None:
    assert (
        well_known_uri("http://www.example.com", "example")
        == "http://www.example.com/.well-known/example"
    )
    assert (
        well_known_uri("http://www.example.com/", "example")
        == "http://www.example.com/.well-known/example"
    )

    assert (
        well_known_uri("http://www.example.com/foo", "example")
        == "http://www.example.com/.well-known/foo/example"
    )
    assert (
        well_known_uri("http://www.example.com/foo/", "example")
        == "http://www.example.com/.well-known/foo/example"
    )

    assert (
        well_known_uri("http://www.example.com/foo/bar", "example")
        == "http://www.example.com/.well-known/foo/bar/example"
    )
    assert (
        well_known_uri("http://www.example.com/foo/bar/", "example")
        == "http://www.example.com/.well-known/foo/bar/example"
    )


def test_oidc_discovery() -> None:
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


def test_oauth20_discovery() -> None:
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
