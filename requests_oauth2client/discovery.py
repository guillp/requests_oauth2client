"""Implements Metadata discovery documents URLS.

This is as defined in [RFC8615](https://datatracker.ietf.org/doc/html/rfc8615) and [OpenID Connect
Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata).

"""

from furl import Path, furl  # type: ignore[import-untyped]


class WellKnownDocument:
    """Some well-known documents for use with RFC5785."""

    OPENID_CONFIGURATION = "openid-configuration"
    OAUTH_AUTHORIZATION_SERVER = "oauth-authorization-server"
    OAUTH_PROTECTED_RESOURCE = "oauth-protected-resource"


def well_known_uri(origin: str, name: str, *, at_root: bool = True) -> str:
    """Return the location of a well-known document on an origin url.

    See [RFC8615](https://datatracker.ietf.org/doc/html/rfc8615) and [OIDC
    Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata).

    Args:
        origin: origin to use to build the well-known uri.
        name: document name to use to build the well-known uri.
        at_root: if `True`, assume the well-known document is at root level, as defined in [RFC8615](https://datatracker.ietf.org/doc/html/rfc8615).
            If `False`, assume the well-known location is per-directory, as defined in [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata).

    Returns:
        the well-know uri, relative to origin, where the well-known document `name` should be found.

    """
    url = furl(origin)
    if at_root:
        url.path.set(Path(".well-known") / url.path / name)
    else:
        url.path.add(Path(".well-known") / name)
    return str(url)


def oidc_discovery_document_url(issuer: str) -> str:
    """Construct the OIDC discovery document url for a given `issuer`.

    Given an `issuer` identifier, return the standardised URL where the OIDC discovery document can
    be retrieved.

    The returned URL is biuilt as specified in [OpenID Connect Discovery
    1.0](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata).

    Args:
        issuer: an OIDC Authentication Server `issuer`

    Returns:
        the standardised discovery document URL. Note that no attempt to fetch this document is
        made.

    """
    return well_known_uri(issuer, WellKnownDocument.OPENID_CONFIGURATION, at_root=False)


def oauth2_discovery_document_url(issuer: str) -> str:
    """Construct the standardised OAuth 2.0 discovery document url for a given `issuer`.

    Based an `issuer` identifier, returns the standardised URL where the OAuth20 server metadata can
    be retrieved.

    The returned URL is built as specified in
    [RFC8414](https://datatracker.ietf.org/doc/html/rfc8414).

    Args:
        issuer: an OAuth20 Authentication Server `issuer`

    Returns:
        the standardised discovery document URL. Note that no attempt to fetch this document is
        made.

    """
    return well_known_uri(issuer, WellKnownDocument.OAUTH_AUTHORIZATION_SERVER, at_root=True)


def oauth2_protected_resource_metadata_url(
    resource: str,
) -> str:
    """Construct the standardised OAuth 2.0 protected resource metadata url for a given `resource`.

    Based on a `resource` identifier, returns the standardised URL where the OAuth20 server metadata can
    be retrieved.

    The returned URL is built as specified in
    [RFC9728](https://datatracker.ietf.org/doc/html/rfc9728).

    Args:
        resource: an OAuth20 protected resource `resource`

    Returns:
        the standardised discovery document URL. Note that no attempt to fetch this document is
        made.

    """
    return well_known_uri(resource, WellKnownDocument.OAUTH_PROTECTED_RESOURCE, at_root=True)
