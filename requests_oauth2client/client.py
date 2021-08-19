from typing import Any, Dict, Iterable, Optional, Tuple, Type, Union

import requests

from .auth import BearerAuth
from .client_authentication import ClientSecretBasic, ClientSecretPost, client_auth_factory
from .exceptions import (AccessDenied, AuthorizationPending, EndpointError,
                         ExpiredDeviceCode, IntrospectionError, InvalidGrant, InvalidScope,
                         InvalidTarget, InvalidTokenResponse, RevocationError, ServerError,
                         SlowDown, UnauthorizedClient, UnsupportedTokenType)
from .tokens import BearerToken, IdToken
from .utils import validate_url


class OAuth2Client:
    """
    An OAuth 2.0 client, able to obtain tokens from the Token Endpoint using one of the standardised Grant Types.
    """

    exception_classes: Dict[str, Type[Exception]] = {
        "server_error": ServerError,
        "invalid_scope": InvalidScope,
        "invalid_target": InvalidTarget,
        "invalid_grant": InvalidGrant,
        "access_denied": AccessDenied,
        "unauthorized_client": UnauthorizedClient,
        "authorization_pending": AuthorizationPending,
        "slow_down": SlowDown,
        "expired_token": ExpiredDeviceCode,
        "unsupported_token_type": UnsupportedTokenType,
    }

    default_exception_class = EndpointError

    def __init__(
        self,
        token_endpoint: str,
        auth: Union[requests.auth.AuthBase, Tuple[str, str], str],
        revocation_endpoint: Optional[str] = None,
        introspection_endpoint: Optional[str] = None,
        userinfo_endpoint: Optional[str] = None,
        jwks_uri: Optional[str] = None,
        session: Optional[requests.Session] = None,
        default_auth_handler: Union[
            Type[ClientSecretPost], Type[ClientSecretBasic]
        ] = ClientSecretPost,
        token_response_class: Type[BearerToken] = BearerToken,
    ):
        """
        :param token_endpoint: the token endpoint where this client will get access tokens
        :param auth: the authentication handler to use for client authentication on the token endpoint.  Can be a
        `requests.auth.AuthBase` instance (which will be used directly), or a tuple of (client_id, client_secret) which
        will initialize an instance of `default_auth_handler`, or a client_id which will use PublicApp authentication.
        :param revocation_endpoint: the revocation endpoint url to use for revoking tokens, if any
        :param introspection_endpoint: the introspection endpoint url to get info about tokens, if any
        :param session: a requests Session to use when sending HTTP requests
        :param default_auth_handler: if auth is a tuple (for example, a client_id and client_secret), init an object of
        this class with auth values as parameters.
        """
        self.token_endpoint = str(token_endpoint)
        self.revocation_endpoint = str(revocation_endpoint) if revocation_endpoint else None
        self.introspection_endpoint = (
            str(introspection_endpoint) if introspection_endpoint else None
        )
        self.userinfo_endpoint = str(userinfo_endpoint) if userinfo_endpoint else None
        self.jwks_uri = str(jwks_uri) if jwks_uri else None
        self.session = session or requests.Session()
        self.auth = client_auth_factory(auth, default_auth_handler)
        self.token_response_class = token_response_class

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
        requests_kwargs = {
            key: value
            for key, value in requests_kwargs.items()
            if value is not None and value != ""
        }

        response = self.session.post(
            self.token_endpoint, auth=self.auth, data=data, timeout=timeout, **requests_kwargs
        )
        if response.ok:
            try:
                token_response = self.token_response_class(**response.json())
                return token_response
            except Exception as exc:
                self.on_token_error(response, exc)

        return self.on_token_error(response)

    def on_token_error(
        self, response: requests.Response, exc: Optional[Exception] = None
    ) -> BearerToken:
        """
        Excecuted when the token endpoint returns an error.
        :param response: the token response
        :param exc: if the token response is 20x but an exception occurred when creating the token_response_class,
         this will contain the exception. Otherwise, this will be None.
        :return: should return nothing and raise an exception instead. But a subclass can return a BearerToken
         to implement a default behaviour if needed.
        """
        error_json = response.json()
        error = error_json.get("error")
        error_description = error_json.get("error_description")
        error_uri = error_json.get("error_uri")
        if error:
            exception_class = self.exception_classes.get(error, self.default_exception_class)
            raise exception_class(error, error_description, error_uri)
        else:
            raise InvalidTokenResponse(
                "token endpoint returned an HTTP error without error message", error_json
            ) from exc

    def client_credentials(
        self,
        requests_kwargs: Optional[Dict[str, Any]] = None,
        scope: Optional[Union[str, Iterable[str]]] = None,
        **token_kwargs: Any,
    ) -> BearerToken:
        """
        Sends a request to the token endpoint with the client_credentials grant.
        :param token_kwargs: additional parameters for the token endpoint, alongside grant_type. Common parameters
        to pass that way include scope, audience, resource, etc.
        :param requests_kwargs: additional parameters for the call to requests
        :return: a TokenResponse
        """
        requests_kwargs = requests_kwargs or {}

        if scope is not None and not isinstance(scope, str):
            try:
                scope = " ".join(scope)
            except Exception as exc:
                raise ValueError("Unsupported scope value") from exc

        data = dict(grant_type="client_credentials", scope=scope, **token_kwargs)
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

    def authorization_code_pkce(
        self,
        code: str,
        code_verifier: str,
        requests_kwargs: Optional[Dict[str, Any]] = None,
        **token_kwargs: Any,
    ) -> BearerToken:
        """
        Sends a request to the token endpoint with the authorization_code grant, and
        This is just an alias to `authorization_code()` with code_verifier as mandatory parameter.
        :param code: an authorization code to exchange for tokens
        :param code_verifier: the code verifier that matches the authorization code
        :param token_kwargs: additional parameters for the token endpoint, alongside grant_type, code, etc.
        :param requests_kwargs: additional parameters for the call to requests
        :return: a BearerToken
        """
        return self.authorization_code(
            code=code,
            code_verifier=code_verifier,
            requests_kwargs=requests_kwargs,
            **token_kwargs,
        )

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

    def token_exchange(
        self,
        subject_token: Union[str, BearerToken],
        subject_token_type: Optional[str] = None,
        requests_kwargs: Optional[Dict[str, Any]] = None,
        actor_token: Union[None, str, BearerToken, IdToken] = None,
        actor_token_type: Optional[str] = None,
        requested_token_type: Optional[str] = None,
        **token_kwargs: Any,
    ) -> BearerToken:
        requests_kwargs = requests_kwargs or {}

        try:
            subject_token_type = self.get_token_type(subject_token_type, subject_token)
        except ValueError:
            raise TypeError(
                "Cannot determine the kind of subject_token you provided."
                "Please specify a subject_token_type."
            )
        if actor_token:  # pragma: no branch
            try:
                actor_token_type = self.get_token_type(actor_token_type, actor_token)
            except ValueError:
                raise TypeError(
                    "Cannot determine the kind of actor_token you provided."
                    "Please specify an actor_token_type."
                )

        data = dict(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=subject_token,
            subject_token_type=subject_token_type,
            actor_token=actor_token,
            actor_token_type=actor_token_type,
            requested_token_type=requested_token_type,
            **token_kwargs,
        )
        return self.token_request(data, **requests_kwargs)

    def userinfo(self, access_token: Union[BearerToken, str]) -> Any:
        """
        Calls the userinfo endpoint with the specified access_token and returns the result.
        :param access_token: the access token to use
        :return: the requests Response returned by the userinfo endpoint.
        """
        if not self.userinfo_endpoint:
            raise ValueError("No userinfo endpoint defined for this client")
        response = self.session.post(self.userinfo_endpoint, auth=BearerAuth(access_token))
        return self.parse_userinfo_response(response)

    def parse_userinfo_response(self, resp: requests.Response) -> Any:
        """
        Given a response obtained from the userinfo endpoint, extracts its JSON content.
        A subclass may implement the signature validation and/or decryption of a userinfo JWT response.
        :param resp: a response obtained from the userinfo endpoint
        :return: the parsed JSON content from this response
        """
        return resp.json()

    @classmethod
    def get_token_type(
        cls,
        token_type: Optional[str] = None,
        token: Union[None, str, BearerToken, IdToken] = None,
    ) -> str:
        if not (token_type or token):
            raise ValueError(
                "Cannot determine type of an empty token without a token_type hint"
            )

        if token_type is None:
            if isinstance(token, str):
                raise ValueError(
                    "Cannot determine the type of provided token when it is a bare str. "
                    "Please specify a token_type."
                )
            elif isinstance(token, BearerToken):
                return "urn:ietf:params:oauth:token-type:access_token"
            elif isinstance(token, IdToken):
                return "urn:ietf:params:oauth:token-type:id_token"
            else:
                raise TypeError(
                    "Unexpected type of token, please provide a string or a BearerToken or an IdToken",
                    type(token),
                )
        elif token_type == "access_token":
            if token is not None and not isinstance(token, (str, BearerToken)):
                raise TypeError(
                    "The supplied token is not a BearerToken or a string representation of it",
                    type(token),
                )
            return "urn:ietf:params:oauth:token-type:access_token"
        elif token_type == "refresh_token":
            if token is not None and isinstance(token, BearerToken) and not token.refresh_token:
                raise ValueError("The supplied BearerToken doesn't have a refresh_token")
            return "urn:ietf:params:oauth:token-type:refresh_token"
        elif token_type == "id_token":
            if token is not None and not isinstance(token, (str, IdToken)):
                raise TypeError(
                    "The supplied token is not an IdToken or a string representation of it",
                    type(token),
                )
            return "urn:ietf:params:oauth:token-type:id_token"
        else:
            return {
                "saml1": "urn:ietf:params:oauth:token-type:saml1",
                "saml2": "urn:ietf:params:oauth:token-type:saml2",
                "jwt": "urn:ietf:params:oauth:token-type:jwt",
            }.get(token_type, token_type)

    def revoke_access_token(
        self,
        access_token: Union[BearerToken, str],
        requests_kwargs: Optional[Dict[str, Any]] = None,
        **revoke_kwargs: Any,
    ) -> bool:
        """
        Sends a request to the revocation endpoint to revoke an access token.
        :param access_token: the access token to revoke
        :param requests_kwargs: additional parameters for the underlying requests.post() call
        :param revoke_kwargs: additional parameters to pass to the revocation endpoint
        """
        return self.revoke_token(
            access_token,
            token_type_hint="access_token",
            requests_kwargs=requests_kwargs,
            **revoke_kwargs,
        )

    def revoke_refresh_token(
        self,
        refresh_token: Union[str, BearerToken],
        requests_kwargs: Optional[Dict[str, Any]] = None,
        **revoke_kwargs: Any,
    ) -> bool:
        """
        Sends a request to the revocation endpoint to revoke a refresh token.
        :param refresh_token: the refresh token to revoke.
        :param requests_kwargs: additional parameters to pass to the revocation endpoint.
        :param revoke_kwargs: additional parameters to pass to the revocation endpoint.
        :return: True if the revocation request is successful, False if this client has no configured revocation
        endpoint.
        """

        if isinstance(refresh_token, BearerToken):
            if refresh_token.refresh_token is None:
                raise ValueError("The supplied BearerToken doesn't have a refresh token.")
            refresh_token = refresh_token.refresh_token

        return self.revoke_token(
            refresh_token,
            token_type_hint="refresh_token",
            requests_kwargs=requests_kwargs,
            **revoke_kwargs,
        )

    def revoke_token(
        self,
        token: Union[str, BearerToken],
        token_type_hint: Optional[str] = None,
        requests_kwargs: Optional[Dict[str, Any]] = None,
        **revoke_kwargs: Any,
    ) -> bool:
        """
        Generic method to use the Revocation Endpoint.
        :param token: the token to revoke.
        :param token_type_hint: a token_type_hint to send to the revocation endpoint.
        :param requests_kwargs: additional parameters to the underling call to requests.post()
        :param revoke_kwargs: additional parameters to send to the revocation endpoint.
        :return: True if the revocation succeeds,
        False if no revocation endpoint is present or a non-standardised error is returned.
        """
        if not self.revocation_endpoint:
            return False

        requests_kwargs = requests_kwargs or {}

        if token_type_hint == "refresh_token" and isinstance(token, BearerToken):
            if token.refresh_token is None:
                raise ValueError("The supplied BearerToken doesn't have a refresh token.")
            token = token.refresh_token

        data = dict(revoke_kwargs, token=str(token))
        if token_type_hint:
            data["token_type_hint"] = token_type_hint

        response = self.session.post(
            self.revocation_endpoint,
            data=data,
            auth=self.auth,
            **requests_kwargs,
        )
        if response.ok:
            return True

        return self.on_revocation_error(response)

    def on_revocation_error(self, response: requests.Response) -> bool:
        """
        Executed when the revocation endpoint return an error.
        :param response: the revocation response
        :return: returns False to signal that an error occurred.
        May raise exceptions instead depending on the revocation response.
        """
        try:
            data = response.json()
        except ValueError:
            return False
        error = data.get("error")
        error_description = data.get("error_description")
        error_uri = data.get("error_uri")
        if error is not None:
            exception_class = self.exception_classes.get(error, RevocationError)
            raise exception_class(error, error_description, error_uri)
        return False

    def introspect_token(
        self,
        token: Union[str, BearerToken],
        token_type_hint: Optional[str] = None,
        requests_kwargs: Optional[Dict[str, Any]] = None,
        **introspect_kwargs: Any,
    ):

        if not self.introspection_endpoint:
            return False

        requests_kwargs = requests_kwargs or {}

        if token_type_hint == "refresh_token" and isinstance(token, BearerToken):
            if token.refresh_token is None:
                raise ValueError("The supplied BearerToken doesn't have a refresh token.")
            token = token.refresh_token

        data = dict(introspect_kwargs, token=str(token))
        if token_type_hint:
            data["token_type_hint"] = token_type_hint

        response = self.session.post(
            self.introspection_endpoint,
            data=data,
            auth=self.auth,
            **requests_kwargs,
        )
        if response.ok:
            return response.json()

        return self.on_introspection_error(response)

    def on_introspection_error(self, response: requests.Response):
        try:
            data = response.json()
        except ValueError:
            response.raise_for_status()
        error = data.get("error")
        error_description = data.get("error_description")
        error_uri = data.get("error_uri")
        if error is not None:
            exception_class = self.exception_classes.get(error, IntrospectionError)
            raise exception_class(error, error_description, error_uri)
        return False

    def get_public_jwks(self) -> Dict[str, Any]:
        if not self.jwks_uri:
            raise ValueError("No jwks uri defined for this client")
        jwks = self.session.get(self.jwks_uri, auth=None).json()
        if (
            not isinstance(jwks, dict)
            or "keys" not in jwks
            or not isinstance(jwks["keys"], list)
            or any("kty" not in jwk for jwk in jwks["keys"])
        ):
            raise ValueError("Invalid JWKS returned by the server", jwks)
        return jwks

    @classmethod
    def from_discovery_endpoint(
        cls,
        url: str,
        issuer: Optional[str],
        auth: Union[requests.auth.AuthBase, Tuple[str, str], str],
        session: Optional[requests.Session] = None,
    ) -> "OAuth2Client":
        """
        Initialise an OAuth2Client, retrieving server metadata from a discovery document.
        :param url: the url where the server metadata will be retrieved
        :param auth: the authentication handler to use for client authentication
        :param session: a requests Session to use to retrieve the document and initialise the client with
        :param issuer: if an issuer is given, check that it matches the one from the retrieved document
        :return: a OAuth2Client
        """
        session = session or requests.Session()
        discovery = session.get(url).json()

        return cls.from_discovery_document(discovery, issuer=issuer, auth=auth, session=session)

    @classmethod
    def from_discovery_document(
        cls,
        discovery: Dict[str, Any],
        issuer: Optional[str],
        auth: Union[requests.auth.AuthBase, Tuple[str, str], str],
        session: Optional[requests.Session] = None,
        https: bool = True,
    ) -> "OAuth2Client":
        """
        Initialise an OAuth2Client, based on the server metadata from `discovery`.
        :param discovery: a dict of server metadata, in the same format as retrieved from a discovery endpoint.
        :param issuer: if an issuer is given, check that it matches the one mentioneed in the document
        :param auth: the authentication handler to use for client authentication
        :param session: a requests Session to use to retrieve the document and initialise the client with
        :param https: if True, validates that urls in the discovery document use the https scheme
        :return: an OAuth2Client
        """
        if issuer:  # pragma: no branch
            issuer_from_doc = discovery.get("issuer")
            if issuer_from_doc != issuer:
                raise ValueError("issuer mismatch!", issuer_from_doc)

        token_endpoint = discovery.get("token_endpoint")
        if token_endpoint is None:
            raise ValueError("token_endpoint not found in that discovery document")
        validate_url(token_endpoint, https=https)
        revocation_endpoint = discovery.get("revocation_endpoint")
        if revocation_endpoint is not None:
            validate_url(revocation_endpoint, https=https)
        introspection_endpoint = discovery.get("introspection_endpoint")
        if introspection_endpoint is not None:
            validate_url(introspection_endpoint, https=https)
        userinfo_endpoint = discovery.get("userinfo_endpoint")
        if userinfo_endpoint is not None:
            validate_url(userinfo_endpoint, https=https)
        jwks_uri = discovery.get("jwks_uri")
        if jwks_uri is not None:
            validate_url(userinfo_endpoint, https=https)

        return cls(
            token_endpoint=token_endpoint,
            revocation_endpoint=revocation_endpoint,
            introspection_endpoint=introspection_endpoint,
            userinfo_endpoint=userinfo_endpoint,
            jwks_uri=jwks_uri,
            auth=auth,
            session=session,
        )
