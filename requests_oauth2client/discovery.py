from furl import Path, furl


def oidc_discovery_document_url(issuer):
    """
    Given an `issuer` identifier, return the standardised URL where the OIDC discovery document can be retrieved,
    as specified in https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
    :param issuer: an OIDC Authentication Server `issuer`
    :return: the standardised discovery document URL. Note that no attempt to fetch this document is made.
    """
    url = furl(issuer)
    url.path.add(".well-known/openid-configuration")
    return str(url)


def oauth2_discovery_document_url(issuer):
    """
    Given an `issuer` identifier, return the standardised URL where the OAuth20 server metadata can be retrieved,
    as specified in RFC8414.
    :param issuer: an OAuth20 Authentication Server `issuer`
    :return: the standardised discovery document URL. Note that no attempt to fetch this document is made.
    """
    url = furl(issuer)
    url.path = Path(".well-known") / url.path / "oauth-authorization-server"
    return str(url)
