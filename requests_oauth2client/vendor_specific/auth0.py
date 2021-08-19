from typing import Optional, Tuple, Type, Union

import requests

from ..api_client import ApiClient
from ..auth import OAuth2ClientCredentialsAuth
from ..client import OAuth2Client
from ..client_authentication import ClientSecretBasic, ClientSecretPost


class Auth0Client(OAuth2Client):
    def __init__(
        self,
        tenant: str,
        auth: Union[requests.auth.AuthBase, Tuple[str, str], str],
        session: Optional[requests.Session] = None,
        default_auth_handler: Union[
            Type[ClientSecretPost], Type[ClientSecretBasic]
        ] = ClientSecretPost,
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
            default_auth_handler=default_auth_handler,
        )


class Auth0ManagementApiClient(ApiClient):
    def __init__(
        self,
        tenant: str,
        auth: Union[requests.auth.AuthBase, Tuple[str, str], str],
        session: Optional[requests.Session] = None,
        raise_for_status: bool = False,
    ):
        client = Auth0Client(tenant, auth, session=session)
        audience = f"https://{client.tenant}/api/v2/"
        api_auth = OAuth2ClientCredentialsAuth(client, audience=audience)
        super().__init__(url=audience, auth=api_auth, raise_for_status=raise_for_status)
