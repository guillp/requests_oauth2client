import pytest

from requests_oauth2client.vendor_specific import Ping


def test_ping_client() -> None:
    ping_client = Ping.client("mydomain.tld", auth=("client_id", "client_secret"))
    assert ping_client.token_endpoint == "https://mydomain.tld/as/token.oauth2"
    assert ping_client.authorization_endpoint == "https://mydomain.tld/as/authorization.oauth2"
    assert ping_client.token_endpoint == "https://mydomain.tld/as/token.oauth2"
    assert ping_client.revocation_endpoint == "https://mydomain.tld/as/revoke_token.oauth2"
    assert ping_client.userinfo_endpoint == "https://mydomain.tld/idp/userinfo.openid"
    assert ping_client.introspection_endpoint == "https://mydomain.tld/as/introspect.oauth2"
    assert ping_client.jwks_uri == "https://mydomain.tld/pf/JWKS"
    assert ping_client.extra_metadata["registration_endpoint"] == "https://mydomain.tld/as/clients.oauth2"
    assert (
        ping_client.extra_metadata["ping_revoked_sris_endpoint"]
        == "https://mydomain.tld/pf-ws/rest/sessionMgmt/revokedSris"
    )
    assert (
        ping_client.extra_metadata["ping_session_management_sris_endpoint"]
        == "https://mydomain.tld/pf-ws/rest/sessionMgmt/sessions"
    )
    assert (
        ping_client.extra_metadata["ping_session_management_users_endpoint"]
        == "https://mydomain.tld/pf-ws/rest/sessionMgmt/users"
    )
    assert ping_client.extra_metadata["ping_end_session_endpoint"] == "https://mydomain.tld/idp/startSLO.ping"
    assert ping_client.device_authorization_endpoint == "https://mydomain.tld/as/device_authz.oauth2"


def test_ping_invalid_domain() -> None:
    with pytest.raises(ValueError):
        Ping.client("foo")
    with pytest.raises(ValueError):
        Ping.client("ftp://foo.bar")
