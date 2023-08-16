"""PingID specific client."""
from __future__ import annotations

import requests

from requests_oauth2client import OAuth2Client


class PingClient(OAuth2Client):
    """A client for PingID Authorization Server.

    This will initialize all endpoints with the PingID specific urls, without using the metadata.
    Excepted for avoiding a round-trip to get the metadata url, this does not provide any advantage over using
    `OAuth2Client.from_discovery_endpoint(issuer="https://myissuer.domain.tld")`
    """

    def __init__(
        self,
        issuer: str,
        auth: requests.auth.AuthBase | tuple[str, str] | str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        session: requests.Session | None = None,
    ):
        if not issuer.startswith("https://"):
            if issuer.__contains__("://"):
                raise ValueError("Invalid issuer, must be an https:// url or a domain name")
            issuer = f"https://{issuer}"
        if "." not in issuer:
            raise ValueError(
                "Invalid issuer. It must contain at least a dot in the domain name"
            )

        super().__init__(
            authorization_endpoint=f"{issuer}/as/authorization.oauth2",
            token_endpoint=f"{issuer}/as/token.oauth2",
            revocation_endpoint=f"{issuer}/as/revoke_token.oauth2",
            userinfo_endpoint=f"{issuer}/idp/userinfo.openid",
            introspection_endpoint=f"{issuer}/as/introspect.oauth2",
            jwks_uri=f"{issuer}/pf/JWKS",
            registration_endpoint=f"{issuer}/as/clients.oauth2",
            ping_revoked_sris_endpoint=f"{issuer}/pf-ws/rest/sessionMgmt/revokedSris",
            ping_session_management_sris_endpoint=f"{issuer}/pf-ws/rest/sessionMgmt/sessions",
            ping_session_management_users_endpoint=f"{issuer}/pf-ws/rest/sessionMgmt/users",
            ping_end_session_endpoint=f"{issuer}/idp/startSLO.ping",
            device_authorization_endpoint=f"{issuer}/as/device_authz.oauth2",
            auth=auth,
            client_id=client_id,
            client_secret=client_secret,
            session=session,
        )
