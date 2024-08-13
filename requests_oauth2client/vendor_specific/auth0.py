"""Implements subclasses for [Auth0](https://auth0.com)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from requests_oauth2client import ApiClient, OAuth2Client, OAuth2ClientCredentialsAuth

if TYPE_CHECKING:
    import requests
    from jwskate import Jwk


class Auth0:
    """Auth0-related utilities."""

    @classmethod
    def tenant(cls, tenant: str) -> str:
        """Given a short tenant name, returns the full tenant FQDN."""
        if not tenant:
            msg = "You must specify a tenant name."
            raise ValueError(msg)
        if "." not in tenant or tenant.endswith((".eu", ".us", ".au", ".jp")):
            tenant = f"{tenant}.auth0.com"
        if "://" in tenant:
            if tenant.startswith("https://"):
                return tenant[8:]
            msg = (
                "Invalid tenant name. "
                "It must be a tenant name like 'mytenant.myregion' "
                "or a full FQDN like 'mytenant.myregion.auth0.com'."
                "or an issuer like 'https://mytenant.myregion.auth0.com'"
            )
            raise ValueError(msg)
        return tenant

    @classmethod
    def client(
        cls,
        tenant: str,
        auth: (
            requests.auth.AuthBase | tuple[str, str] | tuple[str, Jwk] | tuple[str, dict[str, Any]] | str | None
        ) = None,
        *,
        client_id: str | None = None,
        client_secret: str | None = None,
        private_jwk: Any | None = None,
        session: requests.Session | None = None,
        **kwargs: Any,
    ) -> OAuth2Client:
        """Initialise an OAuth2Client for an Auth0 tenant."""
        tenant = cls.tenant(tenant)
        issuer = f"https://{tenant}"
        token_endpoint = f"{issuer}/oauth/token"
        authorization_endpoint = f"{issuer}/authorize"
        revocation_endpoint = f"{issuer}/oauth/revoke"
        userinfo_endpoint = f"{issuer}/userinfo"
        jwks_uri = f"{issuer}/.well-known/jwks.json"

        return OAuth2Client(
            auth=auth,
            client_id=client_id,
            client_secret=client_secret,
            private_jwk=private_jwk,
            session=session,
            token_endpoint=token_endpoint,
            authorization_endpoint=authorization_endpoint,
            revocation_endpoint=revocation_endpoint,
            userinfo_endpoint=userinfo_endpoint,
            issuer=issuer,
            jwks_uri=jwks_uri,
            **kwargs,
        )

    @classmethod
    def management_api_client(
        cls,
        tenant: str,
        auth: (
            requests.auth.AuthBase | tuple[str, str] | tuple[str, Jwk] | tuple[str, dict[str, Any]] | str | None
        ) = None,
        *,
        client_id: str | None = None,
        client_secret: str | None = None,
        private_jwk: Any | None = None,
        session: requests.Session | None = None,
        **kwargs: Any,
    ) -> ApiClient:
        """Initialize a client for the Auth0 Management API.

        See [Auth0 Management API v2](https://auth0.com/docs/api/management/v2). You must provide the
        target tenant name and the credentials for a client that is allowed access to the Management
        API.

        Args:
            tenant: the tenant name.
                Same definition as for [Auth0.client][requests_oauth2client.vendor_specific.auth0.Auth0.client]
            auth: client credentials.
                Same definition as for [OAuth2Client][requests_oauth2client.client.OAuth2Client]
            client_id: the Client ID.
                Same definition as for [OAuth2Client][requests_oauth2client.client.OAuth2Client]
            client_secret: the Client Secret.
                Same definition as for [OAuth2Client][requests_oauth2client.client.OAuth2Client]
            private_jwk: the private key to use for client authentication.
                Same definition as for [OAuth2Client][requests_oauth2client.client.OAuth2Client]
            session: requests session.
                Same definition as for [OAuth2Client][requests_oauth2client.client.OAuth2Client]
            **kwargs: additional kwargs to pass to the ApiClient base class

        Example:
            ```python
            from requests_oauth2client.vendor_specific import Auth0

            a0mgmt = Auth0.management_api_client("mytenant.eu", client_id=client_id, client_secret=client_secret)
            users = a0mgmt.get("users", params={"page": 0, "per_page": 100})
            ```

        """
        tenant = cls.tenant(tenant)
        client = cls.client(
            tenant,
            auth=auth,
            client_id=client_id,
            client_secret=client_secret,
            private_jwk=private_jwk,
            session=session,
        )
        audience = f"https://{tenant}/api/v2/"
        api_auth = OAuth2ClientCredentialsAuth(client, audience=audience)
        return ApiClient(
            base_url=audience,
            auth=api_auth,
            session=session,
            **kwargs,
        )
