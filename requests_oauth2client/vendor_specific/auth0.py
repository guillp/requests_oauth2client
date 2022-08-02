"""Implements subclasses for [Auth0](https://auth0.com)."""

from typing import Any, Optional, Tuple, Union

import requests

from requests_oauth2client import ApiClient, OAuth2Client, OAuth2ClientCredentialsAuth


class Auth0Client(OAuth2Client):
    """An OAuth2Client for an Auth0 tenant.

    Instead of providing each endpoint URL separately, you only have to provide a
    tenant name and all endpoints will be initialized to work with your tenant.

    Args:
        tenant: the tenant name or FQDN. If it doesn't contain a `.` or it ends with `.eu`, `.us`, or `.au`,
            then `.auth0.com` will automatically be suffixed to the provided tenant name.
        auth: the client credentials, same definition as for [OAuth2Client][requests_oauth2client.client.OAuth2Client]
        session: the session to use, same definition as for [OAuth2Client][requests_oauth2client.client.OAuth2Client]
    """

    def __init__(
        self,
        tenant: str,
        auth: Union[requests.auth.AuthBase, Tuple[str, str], str],
        session: Optional[requests.Session] = None,
    ):
        if (
            "." not in tenant
            or tenant.endswith(".eu")
            or tenant.endswith(".us")
            or tenant.endswith(".au")
        ):
            tenant = f"{tenant}.auth0.com"
        self.tenant = tenant
        token_endpoint = f"https://{tenant}/oauth/token"
        revocation_endpoint = f"https://{tenant}/oauth/revoke"
        userinfo_endpoint = f"https://{tenant}/userinfo"
        jwks_uri = f"https://{tenant}/.well-known/jwks.json"
        super().__init__(
            token_endpoint=token_endpoint,
            revocation_endpoint=revocation_endpoint,
            userinfo_endpoint=userinfo_endpoint,
            jwks_uri=jwks_uri,
            auth=auth,
            session=session,
        )


class Auth0ManagementApiClient(ApiClient):
    """A wrapper around the Auth0 Management API.

    See [Auth0 Management API v2](https://auth0.com/docs/api/management/v2).
    You must provide the target tenant name and the credentials for a client that is allowed access to the Management API.

    Args:
        tenant: the tenant name. Same definition as for [Auth0Client][requests_oauth2client.vendor_specific.auth0.Auth0Client]
        auth: client credentials. Same definition as for [OAuth2Client][requests_oauth2client.client.OAuth2Client]
        session: requests session. Same definition as for [OAuth2Client][requests_oauth2client.client.OAuth2Client]
        **kwargs: additional kwargs to pass to the ApiClient base class

    Usage:
        ```python
        a0mgmt = Auth0ManagementApiClient("mytenant.eu", (client_id, client_secret))
        users = a0mgmt.get("users", params={"page": 0, "per_page": 100})
        ```
    """

    def __init__(
        self,
        tenant: str,
        auth: Union[requests.auth.AuthBase, Tuple[str, str], str],
        session: Optional[requests.Session] = None,
        **kwargs: Any,
    ):
        client = Auth0Client(tenant, auth, session=session)
        audience = f"https://{client.tenant}/api/v2/"
        api_auth = OAuth2ClientCredentialsAuth(client, audience=audience)
        super().__init__(
            base_url=audience,
            auth=api_auth,
            session=session,
            **kwargs,
        )
