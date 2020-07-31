from typing import Any, Callable, Dict, Tuple, Union

import requests
from jwcrypto.jwt import JWT  # type: ignore[import]

from . import BearerTokenEndpointResponse
from .auth import BearerAuth
from .client import OAuth2Client
from .token_response import BearerToken


class IdToken:
    def __init__(self, value, issuer):
        self.value = value
        self.issuer = issuer

    def validate(self, asymetric_signature=True, nonce=None):
        jwt = JWT(jwt=self.value)
        issuer = jwt.token.jose_header.get("iss")
        if not issuer:
            raise ValueError("no issuer set in this token")
        if issuer != self.issuer:
            raise ValueError("unexpected issuer value")


class OpenIdConnectTokenResponse(BearerTokenEndpointResponse):
    def id_token(self):
        # TODO: parse the id token
        return self._id_token


class OpenIdConnectClient(OAuth2Client):
    """
    An OIDC compatible client. It can do everything an OAuth20Client can do, and call the userinfo endpoint.
    """

    token_response_factory: "Callable[[OAuth2Client, requests.Response], BearerTokenEndpointResponse]" = OpenIdConnectTokenResponse.from_requests_response

    def __init__(
        self,
        token_endpoint: str,
        userinfo_endpoint: str,
        jwks_endpoint: str,
        auth: Union[requests.auth.AuthBase, Tuple[str, str]],
        session: requests.Session = None,
    ):
        super().__init__(token_endpoint=token_endpoint, auth=auth, session=session)
        self.userinfo_endpoint = userinfo_endpoint
        self.jwks_endpoint = jwks_endpoint

    def userinfo(self, access_token: Union[BearerToken, str]) -> Any:
        """
        Calls the userinfo endpoint with the specified access_token and returns the result.
        :param access_token: the access token to use
        :return: the requests Response returned by the userinfo endpoint.
        """
        return self.session.post(self.userinfo_endpoint, auth=BearerAuth(access_token)).json()

    @classmethod
    def from_discovery_document(
        cls,
        discovery: Dict[str, Any],
        auth: Union[requests.auth.AuthBase, Tuple[str, str]],
        session: requests.Session = None,
    ) -> "OpenIdConnectClient":
        return cls(
            token_endpoint=discovery["token_endpoint"],
            userinfo_endpoint=discovery["userinfo_endpoint"],
            jwks_endpoint=discovery["jwks_endpoint"],
            auth=auth,
            session=session,
        )
