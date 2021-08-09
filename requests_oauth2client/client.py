from typing import Any, Dict, Optional, Tuple, Type, Union

import requests

from .client_authentication import ClientSecretBasic, ClientSecretPost, PublicApp
from .exceptions import (AccessDenied, AuthorizationPending, ExpiredDeviceCode,
                         InvalidGrant, InvalidScope, InvalidTokenResponse,
                         SlowDown, TokenResponseError, UnauthorizedClient)
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
        "authorization_pending": AuthorizationPending,
        "slow_down": SlowDown,
        "expired_token": ExpiredDeviceCode,
    }

    default_exception_class = TokenResponseError

    token_response_class: Type[BearerToken] = BearerToken

    def __init__(
        self,
        token_endpoint: str,
        auth: Union[requests.auth.AuthBase, Tuple[str, str], str],
        revocation_endpoint: Optional[str] = None,
        session: Optional[requests.Session] = None,
        default_auth_handler: Union[
            Type[ClientSecretPost], Type[ClientSecretBasic]
        ] = ClientSecretPost,
    ):
        """
        :param token_endpoint: the token endpoint where this client will get access tokens
        :param auth: the authentication handler to use for client authentication on the token endpoint.  Can be a
        `requests.auth.AuthBase` instance (which will be used directly), or a tuple of (client_id, client_secret) which
        will initialize an instance of `default_auth_handler`, or a client_id which will use PublicApp authentication.
        :param revocation_endpoint: the revocation endpoint url to use for revoking tokens, if any
        :param session: a requests Session to use when sending HTTP requests
        :param default_auth_handler: if auth is a tuple (for example, a client_id and client_secret), init an object of
        this class with auth values as parameters.
        """
        self.token_endpoint = str(token_endpoint)
        self.revocation_endpoint = str(revocation_endpoint)
        self.session = session or requests.Session()

        self.auth: Optional[requests.auth.AuthBase]
        if isinstance(auth, requests.auth.AuthBase):
            self.auth = auth
        elif isinstance(auth, tuple) and len(auth) == 2:
            client_id, client_secret = auth
            self.auth = default_auth_handler(client_id, client_secret)
        elif isinstance(auth, str):
            client_id = auth
            self.auth = PublicApp(client_id)
        else:
            raise ValueError("An AuthHandler is required")

    def token_request(
        self, data: Dict[str, Any], timeout: int = 10, **requests_kwargs: Any
    ) -> BearerToken:
        """
        Sends a authenticated request to the token endpoint.
        :param data: parameters to send to the token endpoint
        :param timeout: a timeout value for the call
        :param requests_kwargs: additional parameters for requests.post()
        :return: the token endpoint response, as BearerToken instance.
        """
        response = self.session.post(
            self.token_endpoint, auth=self.auth, data=data, timeout=timeout, **requests_kwargs
        )
        if response.ok:
            token_response = self.token_response_class(**response.json())
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

    def client_credentials(
        self, requests_kwargs: Optional[Dict[str, Any]] = None, **token_kwargs: Any
    ) -> BearerToken:
        """
        Sends a request to the token endpoint with the client_credentials grant.
        :param token_kwargs: additional parameters for the token endpoint, alongside grant_type. Common parameters
        to pass that way include scope, audience, resource, etc.
        :param requests_kwargs: additional parameters for the call to requests
        :return: a TokenResponse
        """
        requests_kwargs = requests_kwargs or {}
        data = dict(grant_type="client_credentials", **token_kwargs)
        return self.token_request(data, **requests_kwargs)

    def authorization_code(
        self, code: str, requests_kwargs: Optional[Dict[str, Any]] = None, **token_kwargs: Any
    ) -> BearerToken:
        """
        Sends a request to the token endpoint with the authorization_code grant.
        :param code: an authorization code to exchange for tokens
        :param token_kwargs: additional parameters for the token endpoint, alongside grant_type, code, etc.
        :param requests_kwargs: additional parameters for the call to requests
        :return: a TokenResponse
        """
        requests_kwargs = requests_kwargs or {}
        data = dict(grant_type="authorization_code", code=code, **token_kwargs)
        return self.token_request(data, **requests_kwargs)

    def refresh_token(
        self,
        refresh_token: str,
        requests_kwargs: Optional[Dict[str, Any]] = None,
        **token_kwargs: Any,
    ) -> BearerToken:
        """
        Sends a request to the token endpoint with the refresh_token grant.
        :param refresh_token: a refresh_token
        :param token_kwargs: additional parameters for the token endpoint, alongside grant_type, refresh_token, etc.
        :param requests_kwargs: additional parameters for the call to requests
        :return: a BearerToken
        """
        requests_kwargs = requests_kwargs or {}
        data = dict(grant_type="refresh_token", refresh_token=refresh_token, **token_kwargs)
        return self.token_request(data, **requests_kwargs)

    def device_code(
        self,
        device_code: str,
        requests_kwargs: Optional[Dict[str, Any]] = None,
        **token_kwargs: Any,
    ) -> BearerToken:
        """
        Sends a request to the token endpoint with the urn:ietf:params:oauth:grant-type:device_code grant.
        :param device_code: a device code as received during the device authorization request
        :param requests_kwargs: additional parameters for the call to requests
        :param token_kwargs: additional parameters for the token endpoint, alongside grant_type, device_code, etc.
        :return: a BearerToken
        """
        requests_kwargs = requests_kwargs or {}
        data = dict(
            grant_type="urn:ietf:params:oauth:grant-type:device_code",
            device_code=device_code,
            **token_kwargs,
        )
        return self.token_request(data, **requests_kwargs)

    def revoke_access_token(
        self,
        access_token: Union[BearerToken, str],
        requests_kwargs: Optional[Dict[str, Any]] = None,
        **revoke_kwargs: Any,
    ) -> None:
        """
        Sends a request to the revocation endpoint to revoke an access token.
        :param access_token: the access token to revoke
        :param requests_kwargs: additional parameters for the underlying requests.post() call
        :param revoke_kwargs: additional parameters to pass to the revocation endpoint
        """
        requests_kwargs = requests_kwargs or {}
        if self.revocation_endpoint:
            self.session.post(
                data=dict(
                    revoke_kwargs, token=str(access_token), token_type_hint="access_token"
                ),
                **requests_kwargs,
            ).raise_for_status()

    def revoke_refresh_token(
        self,
        refresh_token: str,
        requests_kwargs: Optional[Dict[str, Any]] = None,
        **revoke_kwargs: Any,
    ) -> None:
        """
        Sends a request to the revocation endpoint to revoke a refresh token.
        :param refresh_token: the refresh token to revoke
        :param requests_kwargs: additional parameters to pass to the revocation endpoint
        :param revoke_kwargs: additional parameters to pass to the revocation endpoint
        """
        requests_kwargs = requests_kwargs or {}
        if self.revocation_endpoint:
            self.session.post(
                data=dict(revoke_kwargs, token=refresh_token, token_type_hint="refresh_token"),
                **requests_kwargs,
            ).raise_for_status()

    @classmethod
    def from_discovery_endpoint(
        cls,
        url: str,
        auth: Union[requests.auth.AuthBase, Tuple[str, str], str],
        session: Optional[requests.Session] = None,
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
        auth: Union[requests.auth.AuthBase, Tuple[str, str], str],
        session: Optional[requests.Session] = None,
    ) -> "OAuth2Client":
        """
        Initialise an OAuth20Client, based on the server metadata from `discovery`.
        :param discovery: a dict of server metadata, in the same format as retrieved from a discovery endpoint.
        :param auth: the authentication handler to use for client authentication
        :param session: a requests Session to use to retrieve the document and initialise the client with
        :return: an OAuth20Client
        """
        return cls(token_endpoint=discovery["token_endpoint"], auth=auth, session=session)
