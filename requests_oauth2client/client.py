from typing import Any, Dict, Iterable, Optional, Tuple, Type, Union

import requests

from .auth import BearerAuth
from .authorization_request import AuthorizationResponse
from .backchannel_authentication import BackChannelAuthenticationResponse
from .client_authentication import ClientSecretPost, client_auth_factory
from .device_authorization import DeviceAuthorizationResponse
from .exceptions import (
    AccessDenied,
    AuthorizationPending,
    BackChannelAuthenticationError,
    DeviceAuthorizationError,
    ExpiredToken,
    IntrospectionError,
    InvalidBackChannelAuthenticationResponse,
    InvalidDeviceAuthorizationResponse,
    InvalidGrant,
    InvalidScope,
    InvalidTarget,
    InvalidTokenResponse,
    RevocationError,
    ServerError,
    SlowDown,
    UnauthorizedClient,
    UnknownIntrospectionError,
    UnknownTokenEndpointError,
    UnsupportedTokenType,
)
from .jwskate import Jwk, JwkSet, Jwt
from .tokens import BearerToken, IdToken
from .utils import validate_endpoint_uri


class OAuth2Client:
    """
    An OAuth 2.0 client, able to obtain tokens from the Token Endpoint using one of the standardised Grant Types,
    and to communicate with the various backend endpoints like the Revocation, Introspection, and UserInfo Endpoint.

    This class doesn't implement anything related to the end-user authentication or any request that goes in a browser.
    For authentication requests, see :class`AuthorizationRequest`.

    Usage:
    ```python
    client = OAuth2Client(
        token_endpoint="https://my.as.local/token",
        revocation_endpoint="https://my.as.local/revoke",
        auth=("client_id", "client_secret"),
    )

    # once intialized, a client can send requests to its configured endpoints
    cc_token = client.client_credentials(scope="my_scope")
    ac_token = client.authorization_code(code="my_code")
    client.revoke_access_token(cc_token)
    ```
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
        "expired_token": ExpiredToken,
        "unsupported_token_type": UnsupportedTokenType,
    }

    def __init__(
        self,
        token_endpoint: str,
        auth: Union[requests.auth.AuthBase, Tuple[str, str], str],
        revocation_endpoint: Optional[str] = None,
        introspection_endpoint: Optional[str] = None,
        userinfo_endpoint: Optional[str] = None,
        backchannel_authentication_endpoint: Optional[str] = None,
        device_authorization_endpoint: Optional[str] = None,
        jwks_uri: Optional[str] = None,
        session: Optional[requests.Session] = None,
    ):
        """
        :param token_endpoint: the Token Endpoint URI where this client will get access tokens
        :param auth: the authentication handler to use for client authentication on the token endpoint. Can be a [requests.auth.AuthBase][] instance (which will be as-is), or a tuple of `(client_id, client_secret)` which will initialize an instance of [ClientSecretPost][requests_oauth2client.client_authentication.ClientSecretPost], a `(client_id, jwk)` to initialize a [PrivateKeyJWK][requests_oauth2client.client_authentication.PrivateKeyJWK], or a `client_id` which will use [PublicApp][requests_oauth2client.client_authentication.PublicApp] authentication.
        :param revocation_endpoint: the Revocation Endpoint URI to use for revoking tokens
        :param introspection_endpoint: the Introspection Endpoint URI to use to get info about tokens
        :param userinfo_endpoint: the Userinfo Endpoint URI to use to get information about the user
        :param backchannel_authentication_endpoint: the BackChannel Authentication URI
        :param device_authorization_endpoint: the Device Authorization Endpoint URI to use to authorize devices
        :param jwks_uri: the JWKS URI to use to obtain the AS public keys
        :param session: a requests Session to use when sending HTTP requests. Useful if some extra parameters such as proxy or client certificate must be used to connect to the AS.
        """
        self.token_endpoint = str(token_endpoint)
        self.revocation_endpoint = (
            str(revocation_endpoint) if revocation_endpoint else None
        )
        self.introspection_endpoint = (
            str(introspection_endpoint) if introspection_endpoint else None
        )
        self.userinfo_endpoint = str(userinfo_endpoint) if userinfo_endpoint else None
        self.backchannel_authentication_endpoint = (
            str(backchannel_authentication_endpoint)
            if backchannel_authentication_endpoint
            else None
        )
        self.device_authorization_endpoint = (
            str(device_authorization_endpoint)
            if device_authorization_endpoint
            else None
        )
        self.jwks_uri = str(jwks_uri) if jwks_uri else None
        self.session = session or requests.Session()
        self.auth = client_auth_factory(auth, ClientSecretPost)

    def token_request(
        self, data: Dict[str, Any], timeout: int = 10, **requests_kwargs: Any
    ) -> BearerToken:
        """
        Sends a authenticated request to the token endpoint.
        :param data: parameters to send to the token endpoint. Items with a None or empty value will not be sent in the request.
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
            self.token_endpoint,
            auth=self.auth,
            data=data,
            timeout=timeout,
            **requests_kwargs,
        )
        if response.ok:
            return self.parse_token_response(response)

        return self.on_token_error(response)

    def parse_token_response(self, response: requests.Response) -> BearerToken:
        """
        Invoked by :method:`token_request` to parse responses returned by the Token Endpoint.
        :param response:
        :return:
        """
        try:
            token_response = BearerToken(**response.json())
            return token_response
        except Exception as response_class_exc:
            try:
                return self.on_token_error(response)
            except Exception as token_error_exc:
                raise token_error_exc from response_class_exc

    def on_token_error(self, response: requests.Response) -> BearerToken:
        """
        Incoked by :method:`token_request` when the token endpoint returns an error.
        :param response: the token response
        :return: returns nothing and raise an exception instead. But a subclass can return a BearerToken
         to implement a default behaviour if needed.
        """
        error_json = response.json()
        error = error_json.get("error")
        error_description = error_json.get("error_description")
        error_uri = error_json.get("error_uri")
        if error:
            exception_class = self.exception_classes.get(
                error, UnknownTokenEndpointError
            )
            raise exception_class(error, error_description, error_uri)
        else:
            raise InvalidTokenResponse(
                "token endpoint returned an HTTP error without error message",
                error_json,
            )

    def client_credentials(
        self,
        requests_kwargs: Optional[Dict[str, Any]] = None,
        scope: Optional[Union[str, Iterable[str]]] = None,
        **token_kwargs: Any,
    ) -> BearerToken:
        """
        Sends a request to the token endpoint using the `client_credentials` grant.
        :param scope: the scope to send with the request. Can be a str, or an iterable of str.
        :param token_kwargs: additional parameters for the token endpoint, alongside `grant_type`. Common parameters
        to pass that way include `scope`, `audience`, `resource`, etc.
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
        self,
        code: Union[str, AuthorizationResponse],
        requests_kwargs: Optional[Dict[str, Any]] = None,
        **token_kwargs: Any,
    ) -> BearerToken:
        """
        Sends a request to the token endpoint with the `authorization_code` grant.
        :param code: an authorization code to exchange for tokens
        :param token_kwargs: additional parameters for the token endpoint, alongside `grant_type`, `code`, etc.
        :param requests_kwargs: additional parameters for the call to requests
        :return: a TokenResponse
        """
        requests_kwargs = requests_kwargs or {}
        if isinstance(code, AuthorizationResponse):
            data = dict(
                grant_type="authorization_code",
                code=code.code,
                code_verifier=code.code_verifier,
                redirect_uri=code.redirect_uri,
                **token_kwargs,
            )
        else:
            data = dict(grant_type="authorization_code", code=code, **token_kwargs)
        return self.token_request(data, **requests_kwargs)

    def refresh_token(
        self,
        refresh_token: str,
        requests_kwargs: Optional[Dict[str, Any]] = None,
        **token_kwargs: Any,
    ) -> BearerToken:
        """
        Sends a request to the token endpoint with the `refresh_token` grant.
        :param refresh_token: a refresh_token
        :param token_kwargs: additional parameters for the token endpoint, alongside `grant_type`, `refresh_token`, etc.
        :param requests_kwargs: additional parameters for the call to `requests`
        :return: a BearerToken
        """
        requests_kwargs = requests_kwargs or {}
        data = dict(
            grant_type="refresh_token", refresh_token=refresh_token, **token_kwargs
        )
        return self.token_request(data, **requests_kwargs)

    def device_code(
        self,
        device_code: str,
        requests_kwargs: Optional[Dict[str, Any]] = None,
        **token_kwargs: Any,
    ) -> BearerToken:
        """
        Sends a request to the token endpoint with the `urn:ietf:params:oauth:grant-type:device_code` grant.
        :param device_code: a device code as received during the device authorization request
        :param requests_kwargs: additional parameters for the call to requests
        :param token_kwargs: additional parameters for the token endpoint, alongside `grant_type`, `device_code`, etc.
        :return: a BearerToken
        """
        requests_kwargs = requests_kwargs or {}
        data = dict(
            grant_type="urn:ietf:params:oauth:grant-type:device_code",
            device_code=device_code,
            **token_kwargs,
        )
        return self.token_request(data, **requests_kwargs)

    def ciba(
        self,
        auth_req_id: str,
        requests_kwargs: Optional[Dict[str, Any]] = None,
        **token_kwargs: Any,
    ) -> BearerToken:
        """
        Sends a request to the Token Endpoint using the `urn:openid:params:grant-type:ciba` grant.
        :param auth_req_id: an authentication request ID, as returned by the AS
        :param requests_kwargs: additional parameters for the call to requests
        :param token_kwargs: additional parameters for the token endpoint, alongside `grant_type`, `auth_req_id`, etc.
        :return:
        """
        requests_kwargs = requests_kwargs or {}
        data = dict(
            grant_type="urn:openid:params:grant-type:ciba",
            auth_req_id=auth_req_id,
            **token_kwargs,
        )
        return self.token_request(data, **requests_kwargs)

    def token_exchange(
        self,
        subject_token: Union[str, BearerToken, IdToken],
        subject_token_type: Optional[str] = None,
        actor_token: Union[None, str, BearerToken, IdToken] = None,
        actor_token_type: Optional[str] = None,
        requested_token_type: Optional[str] = None,
        requests_kwargs: Optional[Dict[str, Any]] = None,
        **token_kwargs: Any,
    ) -> BearerToken:
        """
        Sends a Token Exchange request, which is actually a request to the Token Endpoint with a
        grant_type `urn:ietf:params:oauth:grant-type:token-exchange`.

        :param subject_token: the subject token to exchange for a new token.
        :param subject_token_type: a token type identifier for the subject_token, mandatory if it cannot be guessed based
        on `type(subject_token)`.
        :param actor_token: the actor token to include in the request, if any.
        :param actor_token_type: a token type identifier for the actor_token, mandatory if it cannot be guessed based
        on `type(actor_token)`.
        :param requested_token_type: a token type identifier for the requested token.
        :param requests_kwargs: additional parameters to pass to the underlying `requests.post()` call.
        :param token_kwargs: additional parameters to include in the request body.
        :return: a BearerToken as returned by the Authorization Server.
        """
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
            raise AttributeError("No userinfo endpoint defined for this client")

        response = self.session.post(
            self.userinfo_endpoint, auth=BearerAuth(access_token)
        )
        return self.parse_userinfo_response(response)

    def parse_userinfo_response(self, resp: requests.Response) -> Any:
        """
        Given a response obtained from the userinfo endpoint, extract its JSON content.

        :param resp: a [Response][request.Response] returned from the UserInfo endpoint.
        :return: the parsed JSON content from this response.
        """
        return resp.json()

    @classmethod
    def get_token_type(
        cls,
        token_type: Optional[str] = None,
        token: Union[None, str, BearerToken, IdToken] = None,
    ) -> str:
        """
        An helper method that returns a token type, based on a short `token_type` hint and/or a token value.
        :param token_type: a token_type hint, as `str`. May be "access_token", "refresh_token" or "id_token" (optional)
        :param token: a token value, as an instance of BearerToken or IdToken, or as a `str`.
        :return: the token_type as defined in the Token Exchange RFC8693.
        """
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
            if (
                token is not None
                and isinstance(token, BearerToken)
                and not token.refresh_token
            ):
                raise ValueError(
                    "The supplied BearerToken doesn't have a refresh_token"
                )
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
                raise ValueError(
                    "The supplied BearerToken doesn't have a refresh token."
                )
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
                raise ValueError(
                    "The supplied BearerToken doesn't have a refresh token."
                )
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
        Invoked by :method:`revoke_token` when the revocation endpoint returns an error.
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
    ) -> Any:
        """
        Sends a request to the configured Introspection Endpoint.
        :param token: the token to introspect.
        :param token_type_hint: the token_type_hint to include in the request.
        :param requests_kwargs: additional parameters to the underling call to requests.post()
        :param introspect_kwargs: additional parameters to send to the introspection endpoint.
        :return: the response as returned by the Introspection Endpoint.
        """
        if not self.introspection_endpoint:
            raise AttributeError("No introspection endpoint defined for this client")

        requests_kwargs = requests_kwargs or {}

        if token_type_hint == "refresh_token" and isinstance(token, BearerToken):
            if token.refresh_token is None:
                raise ValueError(
                    "The supplied BearerToken doesn't have a refresh token."
                )
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
            return self.parse_introspection_response(response)

        return self.on_introspection_error(response)

    def parse_introspection_response(self, response: requests.Response) -> Any:
        """
        Invoked by :method:`introspect_token` to parse the returned response.
        This decodes the JSON content if possible, otherwise it returns the response as a string.
        :param response: the response as returned by the Introspection Endpoint.
        :return: the decoded JSON content, or a `str` with the content.
        """
        try:
            return response.json()
        except ValueError:
            return response.text

    def on_introspection_error(self, response: requests.Response) -> Any:
        """
        Invoked by :method:`introspect_token` to parse the returned response in the case an error is returned.
        :param response: the response as returned by the Introspection Endpoint.
        :return: raises exeptions. A subclass can return a default response instead.
        """
        try:
            data = response.json()
        except ValueError:
            try:
                response.raise_for_status()
            except Exception as exc:
                raise UnknownIntrospectionError(response) from exc
        error = data.get("error")
        error_description = data.get("error_description")
        error_uri = data.get("error_uri")
        if error is not None:
            exception_class = self.exception_classes.get(error, IntrospectionError)
            raise exception_class(error, error_description, error_uri)
        raise UnknownIntrospectionError(response)

    def backchannel_authentication_request(
        self,
        scope: Union[str, Iterable[str]] = "openid",
        client_notification_token: Optional[str] = None,
        acr_values: Union[None, str, Iterable[str]] = None,
        login_hint_token: Optional[str] = None,
        id_token_hint: Optional[str] = None,
        login_hint: Optional[str] = None,
        binding_message: Optional[str] = None,
        user_code: Optional[str] = None,
        requested_expiry: Optional[int] = None,
        private_jwk: Union[Jwk, Dict[str, Any], None] = None,
        alg: Optional[str] = None,
        requests_kwargs: Optional[Dict[str, Any]] = None,
        **ciba_kwargs: Any,
    ) -> BackChannelAuthenticationResponse:
        """

        Sends a CIBA Authentication Request.
        :param scope: the scope to include in the request.
        :param client_notification_token: the Client Notification Token to include in the request.
        :param acr_values: the acr values to include in the request.
        :param login_hint_token: the Login Hint Token to include in the request.
        :param id_token_hint: the ID Token Hint to include in the request.
        :param login_hint: the Login Hint to include in the request.
        :param binding_message: the Binding Message to include in the request.
        :param user_code: the User Code to include in the request
        :param requested_expiry: the Requested Expiry, in seconds, to include in the request.
        :param private_jwk: the JWK to use to sign the request (optional)
        :param alg: the alg to use to sign the request, if the provided JWK does not include an "alg" parameter.
        :param requests_kwargs: additional parameters for
        :param ciba_kwargs: additional parameters to include in the request.
        :return: a BackChannelAuthenticationResponse
        """
        if not self.backchannel_authentication_endpoint:
            raise AttributeError(
                "No backchannel authentication endpoint defined for this client"
            )

        if not (login_hint or login_hint_token or id_token_hint):
            raise ValueError(
                "One of `login_hint`, `login_hint_token` or `ìd_token_hint` must be provided"
            )

        if (
            (login_hint_token and id_token_hint)
            or (login_hint and id_token_hint)
            or (login_hint_token and login_hint)
        ):
            raise ValueError(
                "Only one of `login_hint`, `login_hint_token` or `ìd_token_hint` must be provided"
            )

        requests_kwargs = requests_kwargs or {}

        if scope is not None and not isinstance(scope, str):
            try:
                scope = " ".join(scope)
            except Exception as exc:
                raise ValueError("Unsupported `scope` value") from exc

        if acr_values is not None and not isinstance(acr_values, str):
            try:
                acr_values = " ".join(acr_values)
            except Exception as exc:
                raise ValueError("Unsupported `acr_values`") from exc

        data = dict(
            ciba_kwargs,
            scope=scope,
            client_notification_token=client_notification_token,
            acr_values=acr_values,
            login_hint_token=login_hint_token,
            id_token_hint=id_token_hint,
            login_hint=login_hint,
            binding_message=binding_message,
            user_code=user_code,
            requested_expiry=requested_expiry,
        )

        if private_jwk is not None:
            data = {"request": str(Jwt.sign(data, jwk=private_jwk, alg=alg))}

        response = self.session.post(
            self.backchannel_authentication_endpoint,
            data=data,
            auth=self.auth,
            **requests_kwargs,
        )

        if response.ok:
            return self.parse_backchannel_authentication_response(response)

        return self.on_backchannel_authentication_error(response)

    def parse_backchannel_authentication_response(
        self, response: requests.Response
    ) -> BackChannelAuthenticationResponse:
        """
        Invoked by :method:`backchannel_authentication_request` to parse the response
        returned by the BackChannel Authentication Endpoint.
        :param response: the response returned by the BackChannel Authentication Endpoint.
        :return: a :class:`BackChannelAuthenticationResponse`
        """
        try:
            return BackChannelAuthenticationResponse(**response.json())
        except TypeError as exc:
            raise InvalidBackChannelAuthenticationResponse(response) from exc

    def on_backchannel_authentication_error(
        self, response: requests.Response
    ) -> BackChannelAuthenticationResponse:
        """
        Invoked by :method:`backchannel_authentication_request` to parse the response
        returned by the BackChannel Authentication Endpoint, when it is an error.
        :param response: the response returned by the BackChannel Authentication Endpoint.
        :return: raises an exception. But a subclass can return a default response instead.
        """
        try:
            error_json = response.json()
        except ValueError as exc:
            raise InvalidBackChannelAuthenticationResponse(response) from exc

        error = error_json.get("error")
        error_description = error_json.get("error_description")
        error_uri = error_json.get("error_uri")
        if error:
            exception_class = self.exception_classes.get(
                error, BackChannelAuthenticationError
            )
            raise exception_class(error, error_description, error_uri)

        raise InvalidBackChannelAuthenticationResponse(response)

    def authorize_device(self, **data: Any) -> DeviceAuthorizationResponse:
        """
        Sends a Device Authorization Request.
        :param data: additional data to send to the Device Authorization Endpoint
        :return: a Device Authorization Response
        """
        if self.device_authorization_endpoint is None:
            raise AttributeError(
                "No device authorization endpoint defined for this client"
            )

        response = self.session.post(
            self.device_authorization_endpoint, data=data, auth=self.auth
        )

        if response.ok:
            return self.parse_device_authorization_response(response)

        return self.on_device_authorization_error(response)

    def parse_device_authorization_response(
        self, response: requests.Response
    ) -> DeviceAuthorizationResponse:
        """
        Invoked by :method:`authorize_device` to parse the response returned by the Device Authorization Endpoint.
        :param response: the response returned by the Device Authorization Endpoint.
        :return: a :class:`DeviceAuthorizationResponse`
        """
        device_authorization_response = DeviceAuthorizationResponse(**response.json())
        return device_authorization_response

    def on_device_authorization_error(
        self, response: requests.Response
    ) -> DeviceAuthorizationResponse:
        """
        Invoked by :method:`authorize_device` to parse the response returned by the Device Authorization Endpoint,
        when that response is an error.
        :param response: the response returned by the Device Authorization Endpoint.
        :return: raises an Exception. But a subclass may return a default response instead.
        """
        error_json = response.json()
        error = error_json.get("error")
        error_description = error_json.get("error_description")
        error_uri = error_json.get("error_uri")
        if error:
            exception_class = self.exception_classes.get(
                error, DeviceAuthorizationError
            )
            raise exception_class(error, error_description, error_uri)

        raise InvalidDeviceAuthorizationResponse(
            "device authorization endpoint returned an HTTP error without an error message",
            error_json,
        )

    def get_public_jwks(self) -> JwkSet:
        """
        Fetches and parse the public keys from the JWKS endpoint.
        :return:
        """
        if not self.jwks_uri:
            raise ValueError("No jwks uri defined for this client")
        jwks = self.session.get(self.jwks_uri, auth=None).json()
        return JwkSet(jwks)

    @classmethod
    def from_discovery_endpoint(
        cls,
        url: str,
        issuer: Optional[str],
        auth: Union[requests.auth.AuthBase, Tuple[str, str], str],
        session: Optional[requests.Session] = None,
    ) -> "OAuth2Client":
        """
        Initialise an OAuth2Client, retrieving the endpoint uris from the server metadata exposed on a discovery document.
        :param url: the url where the server metadata will be retrieved
        :param auth: the authentication handler to use for client authentication
        :param session: a requests Session to use to retrieve the document and initialise the client with
        :param issuer: if an issuer is given, check that it matches the one from the retrieved document
        :return: a OAuth2Client
        """
        session = session or requests.Session()
        discovery = session.get(url).json()

        return cls.from_discovery_document(
            discovery, issuer=issuer, auth=auth, session=session
        )

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
        :param issuer: if an issuer is given, check that it matches the one mentioned in the document
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
        validate_endpoint_uri(token_endpoint, https=https)
        revocation_endpoint = discovery.get("revocation_endpoint")
        if revocation_endpoint is not None:
            validate_endpoint_uri(revocation_endpoint, https=https)
        introspection_endpoint = discovery.get("introspection_endpoint")
        if introspection_endpoint is not None:
            validate_endpoint_uri(introspection_endpoint, https=https)
        userinfo_endpoint = discovery.get("userinfo_endpoint")
        if userinfo_endpoint is not None:
            validate_endpoint_uri(userinfo_endpoint, https=https)
        jwks_uri = discovery.get("jwks_uri")
        if jwks_uri is not None:
            validate_endpoint_uri(userinfo_endpoint, https=https)

        return cls(
            token_endpoint=token_endpoint,
            revocation_endpoint=revocation_endpoint,
            introspection_endpoint=introspection_endpoint,
            userinfo_endpoint=userinfo_endpoint,
            jwks_uri=jwks_uri,
            auth=auth,
            session=session,
        )
