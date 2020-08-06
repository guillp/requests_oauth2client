from typing import TYPE_CHECKING, Any, Callable, Dict, Optional, Tuple, Type, Union

import requests

from .client_authentication import ClientSecretPost, PublicApp
from .exceptions import (AccessDenied, InvalidGrant, InvalidScope,
                         InvalidTokenResponse, TokenResponseError, UnauthorizedClient)
from .token_response import BearerTokenEndpointResponse

if TYPE_CHECKING:
    from .token_response import BearerToken


class OAuth2Client:
    """
    An OAuth 2.0 client, able to obtain tokens from the Token Endpoint using one of the standardised Grant Types.
    """

    exception_classes: Dict[str, Type[Exception]] = {
        "invalid_scope": InvalidScope,
        "invalid_grant": InvalidGrant,
        "access_denied": AccessDenied,
        "unauthorized_client": UnauthorizedClient,
    }

    default_exception_class = TokenResponseError

    token_response_factory: "Callable[[OAuth2Client, requests.Response], BearerTokenEndpointResponse]" = BearerTokenEndpointResponse.from_requests_response

    def __init__(
        self,
        token_endpoint: str,
        auth: Union[requests.auth.AuthBase, Tuple[str, str], str],
        revocation_endpoint: str = None,
        discovery_endpoint: str = None,
        jwks_uri: str = None,
        session: requests.Session = None,
        default_auth_handler=ClientSecretPost,
    ):
        """
        :param token_endpoint: the token endpoint where this client will get access tokens
        :param auth: the authentication handler to use for client authentication on the token endpoint
        :param revocation_endpoint: the revocation endpoint url to use for revoking tokens
        :param session: a requests Session to use when sending HTTP requests
        :param default_auth_handler: if auth is a tuple (for example, a client_id and client_secret), init an object of
        this class with auth values as parameters. This parameter is ignored if auth is an instance of AuthBase already.
        """
        self.token_endpoint = str(token_endpoint)
        self.revocation_endpoint = str(revocation_endpoint)
        self.jwks_uri = str(jwks_uri)
        self.server_discovery_endpoint = str(discovery_endpoint)
        self.default_auth_handler = default_auth_handler
        self.auth = auth  # type: ignore[assignment]
        self.session = session or requests.Session()

    @property
    def auth(self) -> Optional[requests.auth.AuthBase]:
        return self._auth

    @auth.setter
    def auth(self, value: Union[requests.auth.AuthBase, Tuple[str, str], str]):
        if value is None:
            self._auth: Optional[requests.auth.AuthBase] = None
        elif isinstance(value, requests.auth.AuthBase):
            self._auth = value
        elif isinstance(value, tuple) and len(value) == 2:
            client_id, client_secret = value
            self._auth = self.default_auth_handler(client_id, client_secret)
        elif isinstance(value, str):
            client_id = value
            self._auth = PublicApp(client_id)

    def token_request(self, data: Dict[str, Any]) -> "BearerToken":
        """
        Sends a authenticated request to the token endpoint.
        :param data: parameters to send to the token endpoint
        :return: the token endpoint response, as TokenResponse instance.
        """
        response = self.session.post(self.token_endpoint, auth=self.auth, data=data)
        if response.ok:
            token_response = self.token_response_factory(self, response)  # type: ignore[call-arg, arg-type]
            return token_response

        # error handling
        error_json = response.json()
        error = error_json.get("error")
        error_description = error_json.get("error_description")
        error_uri = error_json.get("error_uri")
        if error:
            exception_class = self.exception_classes.get(error, self.default_exception_class)
            raise exception_class(error, error_description, error_uri)

        if error_description or error_uri:
            raise InvalidTokenResponse(
                "token endpoint returned a error_message or error_uri returned without an error",
                error_description,
                error_uri,
            )
        raise InvalidTokenResponse("token endpoint returned an error without description")

    def client_credentials(self, **token_kwargs: Any) -> "BearerToken":
        """
        Sends a request to the token endpoint with the client_credentials grant.
        :param token_kwargs: additional args to pass to the token endpoint
        :return: a TokenResponse
        """
        data = dict(grant_type="client_credentials", **token_kwargs)
        return self.token_request(data)

    def authorization_code(self, code: str, **token_kwargs: Any) -> "BearerToken":
        """
        Sends a request to the token endpoint with the authorization_code grant.
        :param code: an authorization code to exchange for tokens
        :param token_kwargs: additional args to pass to the token endpoint
        :return: a TokenResponse
        """
        data = dict(grant_type="authorization_code", code=code, **token_kwargs)
        return self.token_request(data)

    def refresh_token(self, refresh_token: str, **token_kwargs: Any) -> "BearerToken":
        """
        Sends a request to the token endpoint with the refresh_token grant.
        :param refresh_token: a refresh_token
        :param token_kwargs: additional args to pass to the token endpoint
        :return: a TokenResponse
        """
        data = dict(grant_type="refresh_token", refresh_token=refresh_token, **token_kwargs)
        return self.token_request(data)

    def revoke_access_token(
        self, access_token: "Union[BearerToken, str]", **requests_kwargs: Any
    ) -> None:
        """
        Sends a request to the revocation endpoint to revoke an access token.
        :param access_token: the access token to revoke
        :param requests_kwargs: additional parameters to pass to the revocation endpoint
        """
        if self.revocation_endpoint:
            self.session.post(
                data={"token": str(access_token), "token_type_hint": "access_token"},
                **requests_kwargs,
            ).raise_for_status()

    def revoke_refresh_token(self, refresh_token: str, **requests_kwargs: Any) -> None:
        """
        Sends a request to the revocation endpoint to revoke a refresh token.
        :param refresh_token: the refresh token to revoke
        :param requests_kwargs: additional parameters to pass to the revocation endpoint
        """
        if self.revocation_endpoint:
            self.session.post(
                data={"token": refresh_token, "token_type_hint": "refresh_token"},
                **requests_kwargs,
            ).raise_for_status()

    @classmethod
    def from_discovery_endpoint(
        cls,
        url: str,
        auth: Union[requests.auth.AuthBase, Tuple[str, str]],
        session: requests.Session = None,
    ) -> "OAuth2Client":
        """
        Initialise an OAuth20Client, retrieving server metadata from a discovery document.
        :param url: the url where the server metadata will be retrieved
        :param auth: the authentication handler to use for client authentication
        :param session: a requests Session to use to retrieve the document and initialise the client with
        :return: a OAuth20Client
        """
        session = session or requests.Session()
        discovery = session.get(url).json()
        return cls.from_discovery_document(discovery, auth=auth, session=session)

    @classmethod
    def from_discovery_document(
        cls,
        discovery: Dict[str, Any],
        auth: Union[requests.auth.AuthBase, Tuple[str, str]],
        session: requests.Session = None,
    ) -> "OAuth2Client":
        """
        Initialise an OAuth20Client, based on the server metadata from `discovery`.
        :param discovery: a dict of server metadata, in the same format as retrieved from a discovery endpoint.
        :param auth: the authentication handler to use for client authentication
        :param session: a requests Session to use to retrieve the document and initialise the client with
        :return: an OAuth20Client
        """
        return cls(token_endpoint=discovery["token_endpoint"], auth=auth, session=session)
