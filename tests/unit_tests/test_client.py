from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

import pytest
import requests.auth
from jwskate import Jwk, JwkSet, Jwt, KeyManagementAlgs, SignatureAlgs
from requests import HTTPError

from requests_oauth2client import (
    AuthorizationRequest,
    BackChannelAuthenticationResponse,
    BaseClientAuthenticationMethod,
    BearerToken,
    ClientSecretBasic,
    ClientSecretJwt,
    ClientSecretPost,
    DeviceAuthorizationResponse,
    IdToken,
    InvalidIssuer,
    InvalidParam,
    InvalidPushedAuthorizationResponse,
    InvalidTokenResponse,
    InvalidUri,
    OAuth2Client,
    PrivateKeyJwt,
    PublicApp,
    RequestUriParameterAuthorizationRequest,
    ServerError,
    UnauthorizedClient,
    UnknownIntrospectionError,
    UnsupportedResponseTypeParam,
    oidc_discovery_document_url,
)

if TYPE_CHECKING:
    from tests.conftest import RequestsMocker, RequestValidatorType


def test_public_client_auth(token_endpoint: str, client_id: str) -> None:
    """Test for initializing an OAuth2Client with a PublicApp auth method."""
    client = OAuth2Client(token_endpoint, auth=client_id)
    assert isinstance(client.auth, PublicApp)
    assert client.auth.client_id == client_id


def test_private_key_jwt_auth(token_endpoint: str, client_id: str, private_jwk: Jwk) -> None:
    """Test for initializing an OAuth2Client with a PrivateKeyJwt auth method."""
    client = OAuth2Client(token_endpoint, auth=(client_id, private_jwk))
    assert isinstance(client.auth, PrivateKeyJwt)
    assert client.auth.client_id == client_id
    assert client.auth.private_jwk == private_jwk


def test_client_secret_post_auth(token_endpoint: str, client_id: str, client_secret: str) -> None:
    """Test for initializing an OAuth2Client with a ClientSecretPost auth method."""
    client = OAuth2Client(token_endpoint, auth=(client_id, client_secret))
    assert isinstance(client.auth, ClientSecretPost)
    assert client.auth.client_id == client_id
    assert client.auth.client_secret == client_secret


def test_client_secret_basic_auth(token_endpoint: str, client_id: str, client_secret: str) -> None:
    """Test for initializing an OAuth2Client with a ClientSecretBasic auth method."""
    client = OAuth2Client(token_endpoint, auth=ClientSecretBasic(client_id, client_secret))
    assert isinstance(client.auth, ClientSecretBasic)
    assert client.auth.client_id == client_id
    assert client.auth.client_secret == client_secret


def test_invalid_auth(token_endpoint: str) -> None:
    """`auth` is required."""
    with pytest.raises(ValueError):
        OAuth2Client(token_endpoint)
    with pytest.raises(ValueError):
        OAuth2Client(token_endpoint, auth=("client_id", "client_secret"), client_id="client_id")
    with pytest.raises(ValueError):
        OAuth2Client(token_endpoint, auth=("client_id", "client_secret"), client_secret="client_secret")
    with pytest.raises(ValueError):
        OAuth2Client(token_endpoint, ("client_id", "client_secret"), client_id="client_id")
    with pytest.raises(ValueError):
        OAuth2Client(
            token_endpoint,
            client_secret="client_secret",
            private_key=Jwk.generate(alg="ES256"),
        )


def test_client_credentials_grant(
    requests_mock: RequestsMocker,
    oauth2client: OAuth2Client,
    token_endpoint: str,
    access_token: str,
    refresh_token: str,
    scope: str,
    client_credentials_grant_validator: RequestValidatorType,
    client_auth_method_handler: type[BaseClientAuthenticationMethod],
    client_id: str,
    client_credential: None | str | Jwk,
    public_jwk: Jwk,
    public_app_auth_validator: RequestValidatorType,
    client_secret_post_auth_validator: RequestValidatorType,
    client_secret_basic_auth_validator: RequestValidatorType,
    client_secret_jwt_auth_validator: RequestValidatorType,
    private_key_jwt_auth_validator: RequestValidatorType,
) -> None:
    """Test for `OAuth2Client.client_credentials()`.

    It sends a request to the Token Endpoint using the Client Credentials grant.

    """
    requests_mock.post(
        token_endpoint,
        json={
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": 3600,
        },
    )

    oauth2client.client_credentials(scope=scope)

    assert requests_mock.called_once
    client_credentials_grant_validator(requests_mock.last_request, scope=scope)

    if client_auth_method_handler == PublicApp:
        public_app_auth_validator(requests_mock.last_request, client_id=client_id)
    elif client_auth_method_handler == ClientSecretPost:
        client_secret_post_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
        )
    elif client_auth_method_handler == ClientSecretBasic:
        client_secret_basic_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
        )
    elif client_auth_method_handler == ClientSecretJwt:
        client_secret_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
            endpoint=token_endpoint,
        )
    elif client_auth_method_handler == PrivateKeyJwt:
        private_key_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            endpoint=token_endpoint,
            public_jwk=public_jwk,
        )


def test_client_credentials_invalid_scope(oauth2client: OAuth2Client) -> None:
    with pytest.raises(ValueError):
        oauth2client.client_credentials(scope=1.634)  # type: ignore[arg-type]


def test_token_endpoint_error(
    requests_mock: RequestsMocker,
    oauth2client: OAuth2Client,
    token_endpoint: str,
) -> None:
    requests_mock.post(
        token_endpoint,
        json={
            "error": "server_error",
            "error_description": "something bad happened",
            "error_uri": "https://lmgtfy.com",
        },
    )

    with pytest.raises(ServerError) as exc_info:
        oauth2client.client_credentials()

    assert exc_info.type is ServerError
    assert exc_info.value.error == "server_error"
    assert exc_info.value.description == "something bad happened"
    assert exc_info.value.uri == "https://lmgtfy.com"
    assert exc_info.value.request.url == token_endpoint


def test_authorization_code_grant(
    requests_mock: RequestsMocker,
    oauth2client: OAuth2Client,
    token_endpoint: str,
    authorization_code: str,
    access_token: str,
    refresh_token: str,
    authorization_code_grant_validator: RequestValidatorType,
    client_auth_method_handler: type[BaseClientAuthenticationMethod],
    client_id: str,
    client_credential: None | str | Jwk,
    public_jwk: Jwk,
    public_app_auth_validator: RequestValidatorType,
    client_secret_post_auth_validator: RequestValidatorType,
    client_secret_basic_auth_validator: RequestValidatorType,
    client_secret_jwt_auth_validator: RequestValidatorType,
    private_key_jwt_auth_validator: RequestValidatorType,
) -> None:
    """Test for `OAuth2Client.authorization_code()`.

    It sends a request to the Token Endpoint using the Authorization Code grant.

    """
    requests_mock.post(
        token_endpoint,
        json={
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": 3600,
        },
    )

    oauth2client.authorization_code(code=authorization_code)

    assert requests_mock.called_once
    authorization_code_grant_validator(requests_mock.last_request, code=authorization_code)

    if client_auth_method_handler == PublicApp:
        public_app_auth_validator(requests_mock.last_request, client_id=client_id)
    elif client_auth_method_handler == ClientSecretPost:
        client_secret_post_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
        )
    elif client_auth_method_handler == ClientSecretBasic:
        client_secret_basic_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
        )
    elif client_auth_method_handler == ClientSecretJwt:
        client_secret_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
            endpoint=token_endpoint,
        )
    elif client_auth_method_handler == PrivateKeyJwt:
        private_key_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            endpoint=token_endpoint,
            public_jwk=public_jwk,
        )


def test_refresh_token_grant(
    requests_mock: RequestsMocker,
    oauth2client: OAuth2Client,
    token_endpoint: str,
    refresh_token: str,
    client_id: str,
    client_credential: None | str | Jwk,
    public_jwk: Jwk,
    client_auth_method_handler: type[BaseClientAuthenticationMethod],
    refresh_token_grant_validator: RequestValidatorType,
    public_app_auth_validator: RequestValidatorType,
    client_secret_basic_auth_validator: RequestValidatorType,
    client_secret_post_auth_validator: RequestValidatorType,
    client_secret_jwt_auth_validator: RequestValidatorType,
    private_key_jwt_auth_validator: RequestValidatorType,
) -> None:
    """Test for `OAuth2Client.refresh_token()`.

    It sends a requests to the Token Endpoint using the Refresh Token grant.

    """
    new_access_token = secrets.token_urlsafe()
    new_refresh_token = secrets.token_urlsafe()
    requests_mock.post(
        token_endpoint,
        json={
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "token_type": "Bearer",
            "expires_in": 3600,
        },
    )
    token_resp = oauth2client.refresh_token(refresh_token)
    assert requests_mock.called_once

    assert not token_resp.is_expired()
    assert token_resp.access_token == new_access_token
    assert token_resp.refresh_token == new_refresh_token

    refresh_token_grant_validator(requests_mock.last_request, refresh_token=refresh_token)

    if client_auth_method_handler == PublicApp:
        public_app_auth_validator(requests_mock.last_request, client_id=client_id)
    elif client_auth_method_handler == ClientSecretPost:
        client_secret_post_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
        )
    elif client_auth_method_handler == ClientSecretBasic:
        client_secret_basic_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
        )
    elif client_auth_method_handler == ClientSecretJwt:
        client_secret_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
            endpoint=token_endpoint,
        )
    elif client_auth_method_handler == PrivateKeyJwt:
        private_key_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            endpoint=token_endpoint,
            public_jwk=public_jwk,
        )


def test_refresh_token_with_bearer_instance_as_param(
    requests_mock: RequestsMocker,
    oauth2client: OAuth2Client,
    token_endpoint: str,
    access_token: str,
    refresh_token: str,
    client_id: str,
    client_credential: None | str | Jwk,
    public_jwk: Jwk,
    client_auth_method_handler: type[BaseClientAuthenticationMethod],
    refresh_token_grant_validator: RequestValidatorType,
    public_app_auth_validator: RequestValidatorType,
    client_secret_basic_auth_validator: RequestValidatorType,
    client_secret_post_auth_validator: RequestValidatorType,
    client_secret_jwt_auth_validator: RequestValidatorType,
    private_key_jwt_auth_validator: RequestValidatorType,
) -> None:
    new_access_token = secrets.token_urlsafe()
    new_refresh_token = secrets.token_urlsafe()
    requests_mock.post(
        token_endpoint,
        json={
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "token_type": "Bearer",
            "expires_in": 3600,
        },
    )
    token_resp = oauth2client.refresh_token(BearerToken(access_token=access_token, refresh_token=refresh_token))
    assert requests_mock.called_once

    assert not token_resp.is_expired()
    assert token_resp.access_token == new_access_token
    assert token_resp.refresh_token == new_refresh_token

    refresh_token_grant_validator(requests_mock.last_request, refresh_token=refresh_token)

    if client_auth_method_handler == PublicApp:
        public_app_auth_validator(requests_mock.last_request, client_id=client_id)
    elif client_auth_method_handler == ClientSecretPost:
        client_secret_post_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
        )
    elif client_auth_method_handler == ClientSecretBasic:
        client_secret_basic_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
        )
    elif client_auth_method_handler == ClientSecretJwt:
        client_secret_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
            endpoint=token_endpoint,
        )
    elif client_auth_method_handler == PrivateKeyJwt:
        private_key_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            endpoint=token_endpoint,
            public_jwk=public_jwk,
        )


def test_ressource_owner_password_grant(
    requests_mock: RequestsMocker,
    oauth2client: OAuth2Client,
    token_endpoint: str,
) -> None:
    username = "User01"
    password = "Th1s_I5_a_P4ssw0rd!"

    scope = "foo"
    new_access_token = secrets.token_urlsafe()
    requests_mock.post(
        token_endpoint,
        json={
            "access_token": new_access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": scope,
        },
    )

    oauth2client.resource_owner_password(username, password, scope=scope)
    assert requests_mock.called_once


def test_grants_with_invalid_response_objects_as_parameter(oauth2client: OAuth2Client) -> None:
    with pytest.raises(ValueError):
        oauth2client.refresh_token(BearerToken(access_token="foo"))
    with pytest.raises(ValueError):
        oauth2client.ciba(BackChannelAuthenticationResponse(auth_req_id=None))
    with pytest.raises(ValueError):
        oauth2client.device_code(DeviceAuthorizationResponse(device_code=None, user_code="foo", verification_uri="bar"))


def test_device_code_grant(
    requests_mock: RequestsMocker,
    oauth2client: OAuth2Client,
    token_endpoint: str,
    device_code: str,
    client_id: str,
    client_credential: None | str | Jwk,
    public_jwk: Jwk,
    client_auth_method_handler: type[BaseClientAuthenticationMethod],
    device_code_grant_validator: RequestValidatorType,
    public_app_auth_validator: RequestValidatorType,
    client_secret_basic_auth_validator: RequestValidatorType,
    client_secret_post_auth_validator: RequestValidatorType,
    client_secret_jwt_auth_validator: RequestValidatorType,
    private_key_jwt_auth_validator: RequestValidatorType,
) -> None:
    """.device_code() sends a requests to the Token Endpoint using the Device Code grant."""
    new_access_token = secrets.token_urlsafe()
    new_refresh_token = secrets.token_urlsafe()
    requests_mock.post(
        token_endpoint,
        json={
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "token_type": "Bearer",
            "expires_in": 3600,
        },
    )
    token_resp = oauth2client.device_code(device_code)

    assert requests_mock.called_once
    assert not token_resp.is_expired()
    assert token_resp.access_token == new_access_token
    assert token_resp.refresh_token == new_refresh_token

    device_code_grant_validator(requests_mock.last_request, device_code=device_code)

    if client_auth_method_handler == PublicApp:
        public_app_auth_validator(requests_mock.last_request, client_id=client_id)
    elif client_auth_method_handler == ClientSecretPost:
        client_secret_post_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
        )
    elif client_auth_method_handler == ClientSecretBasic:
        client_secret_basic_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
        )
    elif client_auth_method_handler == ClientSecretJwt:
        client_secret_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
            endpoint=token_endpoint,
        )
    elif client_auth_method_handler == PrivateKeyJwt:
        private_key_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            endpoint=token_endpoint,
            public_jwk=public_jwk,
        )

    requests_mock.reset()
    oauth2client.device_code(
        DeviceAuthorizationResponse(device_code=device_code, user_code="user_code", verification_uri="https://foo.bar")
    )
    assert requests_mock.called_once
    device_code_grant_validator(requests_mock.last_request, device_code=device_code)


def test_token_exchange_grant(
    requests_mock: RequestsMocker,
    oauth2client: OAuth2Client,
    token_endpoint: str,
    client_id: str,
    client_credential: None | str | Jwk,
    public_jwk: Jwk,
    client_auth_method_handler: type[BaseClientAuthenticationMethod],
    token_exchange_grant_validator: RequestValidatorType,
    public_app_auth_validator: RequestValidatorType,
    client_secret_basic_auth_validator: RequestValidatorType,
    client_secret_post_auth_validator: RequestValidatorType,
    client_secret_jwt_auth_validator: RequestValidatorType,
    private_key_jwt_auth_validator: RequestValidatorType,
) -> None:
    """.token_exchange() sends a requests to the Token Endpoint using the Token Exchange grant."""
    subject_token = secrets.token_urlsafe()
    actor_token = secrets.token_urlsafe()
    new_access_token = secrets.token_urlsafe()
    new_refresh_token = secrets.token_urlsafe()
    requests_mock.post(
        token_endpoint,
        json={
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "token_type": "Bearer",
            "expires_in": 3600,
        },
    )
    token_resp = oauth2client.token_exchange(
        subject_token=subject_token,
        subject_token_type="access_token",
        actor_token=actor_token,
        actor_token_type="access_token",
    )
    assert requests_mock.called_once
    assert not token_resp.is_expired()
    assert token_resp.access_token == new_access_token
    assert token_resp.refresh_token == new_refresh_token

    token_exchange_grant_validator(
        requests_mock.last_request,
        subject_token=subject_token,
        subject_token_type="urn:ietf:params:oauth:token-type:access_token",
    )

    if client_auth_method_handler == PublicApp:
        public_app_auth_validator(requests_mock.last_request, client_id=client_id)
    elif client_auth_method_handler == ClientSecretPost:
        client_secret_post_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
        )
    elif client_auth_method_handler == ClientSecretBasic:
        client_secret_basic_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
        )
    elif client_auth_method_handler == ClientSecretJwt:
        client_secret_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
            endpoint=token_endpoint,
        )
    elif client_auth_method_handler == PrivateKeyJwt:
        private_key_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            endpoint=token_endpoint,
            public_jwk=public_jwk,
        )


def test_token_exchange_invalid_tokens(oauth2client: OAuth2Client) -> None:
    with pytest.raises(TypeError):
        oauth2client.token_exchange(subject_token="foo")

    with pytest.raises(TypeError):
        oauth2client.token_exchange(subject_token="foo", subject_token_type="access_token", actor_token="foo")


def test_userinfo(
    requests_mock: RequestsMocker,
    oauth2client: OAuth2Client,
    userinfo_endpoint: str,
    bearer_auth_validator: RequestValidatorType,
    access_token: str,
    sub: str,
) -> None:
    """.userinfo_endpoint() sends a requests to the Userinfo Endpoint and returns a JSON."""
    userinfo = {"sub": sub}
    requests_mock.post(userinfo_endpoint, json=userinfo)
    resp = oauth2client.userinfo(access_token)
    assert requests_mock.last_request is not None
    assert resp == userinfo
    bearer_auth_validator(requests_mock.last_request, access_token=access_token)
    assert requests_mock.last_request.headers["Accept"] == "application/json"


def test_userinfo_no_uri(token_endpoint: str, client_id: str) -> None:
    """When userinfo_endpoint is not known, .userinfo() raises an exception."""
    client = OAuth2Client(token_endpoint, auth=client_id)
    with pytest.raises(AttributeError):
        client.userinfo("access_token")


def test_userinfo_error(
    requests_mock: RequestsMocker,
    oauth2client: OAuth2Client,
    userinfo_endpoint: str,
    access_token: str,
) -> None:
    requests_mock.post(userinfo_endpoint, json={"error": "access_denied"}, status_code=401)
    with pytest.raises(HTTPError):
        oauth2client.userinfo(access_token)


def test_from_discovery_document(
    issuer: str,
    token_endpoint: str,
    revocation_endpoint: str,
    introspection_endpoint: str,
    userinfo_endpoint: str,
    jwks_uri: str,
    client_id: str,
) -> None:
    """Test for `OAuth2Client.from_discovery_document()`."""
    client = OAuth2Client.from_discovery_document(
        {
            "issuer": issuer,
            "token_endpoint": token_endpoint,
            "revocation_endpoint": revocation_endpoint,
            "introspection_endpoint": introspection_endpoint,
            "userinfo_endpoint": userinfo_endpoint,
            "jwks_uri": jwks_uri,
        },
        issuer=issuer,
        auth=client_id,
    )

    assert client.token_endpoint == token_endpoint
    assert client.revocation_endpoint == revocation_endpoint
    assert client.introspection_endpoint == introspection_endpoint
    assert client.userinfo_endpoint == userinfo_endpoint
    assert client.jwks_uri == jwks_uri

    with pytest.raises(ValueError):
        OAuth2Client.from_discovery_document(
            {
                "issuer": "https://something.else",
                "token_endpoint": token_endpoint,
                "revocation_endpoint": revocation_endpoint,
                "introspection_endpoint": introspection_endpoint,
                "userinfo_endpoint": userinfo_endpoint,
                "jwks_uri": jwks_uri,
            },
            issuer=issuer,
            auth=client_id,
        )

    with pytest.warns(match="`https` parameter is deprecated"):
        OAuth2Client.from_discovery_document(
            {
                "issuer": issuer,
                "token_endpoint": token_endpoint,
                "revocation_endpoint": revocation_endpoint,
                "introspection_endpoint": introspection_endpoint,
                "userinfo_endpoint": userinfo_endpoint,
                "jwks_uri": jwks_uri,
            },
            issuer=issuer,
            auth=client_id,
            https=False,
        )


def test_from_discovery_document_missing_token_endpoint(revocation_endpoint: str, client_id: str) -> None:
    """Invalid discovery documents raises an exception."""
    with pytest.raises(ValueError):
        OAuth2Client.from_discovery_document(
            {"revocation_endpoint": revocation_endpoint},
            issuer=None,
            auth=client_id,
        )


def test_from_discovery_document_token_endpoint_only(token_endpoint: str, client_id: str) -> None:
    """Invalid discovery documents raises an exception."""
    client = OAuth2Client.from_discovery_document(
        {"token_endpoint": token_endpoint},
        issuer=None,
        auth=client_id,
    )

    assert client.token_endpoint == token_endpoint
    assert client.revocation_endpoint is None
    assert client.introspection_endpoint is None
    assert client.userinfo_endpoint is None
    assert client.jwks_uri is None


def test_from_discovery_document_test_issuer(token_endpoint: str, client_id: str) -> None:
    """Invalid discovery documents raises an exception."""
    with pytest.raises(ValueError):
        OAuth2Client.from_discovery_document(
            {"issuer": "https://example.com", "token_endpoint": token_endpoint},
            issuer="https://foo.bar",
            auth=client_id,
        )


def test_from_discovery_endpoint(
    requests_mock: RequestsMocker,
    issuer: str,
    discovery_document: dict[str, str],
    jwks_uri: str,
    as_public_jwks: JwkSet,
    client_auth_method: BaseClientAuthenticationMethod,
) -> None:
    discovery_url = oidc_discovery_document_url(issuer)

    requests_mock.get(discovery_url, json=discovery_document)
    requests_mock.get(jwks_uri, json=as_public_jwks.to_dict())

    client = OAuth2Client.from_discovery_endpoint(discovery_url, issuer, auth=client_auth_method)

    assert requests_mock.request_history[0].url == discovery_url
    assert requests_mock.request_history[1].url == jwks_uri
    assert isinstance(client, OAuth2Client)
    assert client.auth == client_auth_method
    assert client.authorization_server_jwks == as_public_jwks

    with pytest.raises(ValueError, match="at least one of `issuer` or `url`"):
        OAuth2Client.from_discovery_endpoint()


def test_invalid_token_response(requests_mock: RequestsMocker, token_endpoint: str, client_id: str) -> None:
    """Token Endpoint error responses outside the standard raises an InvalidTokenResponse."""
    client = OAuth2Client(token_endpoint, auth=client_id)
    requests_mock.post(token_endpoint, status_code=500, json={"confusing": "data"})
    with pytest.raises(InvalidTokenResponse):
        client.authorization_code("mycode")

    requests_mock.reset_mock()
    requests_mock.post(
        token_endpoint,
        status_code=500,
        json={"error_description": "this shouldn't happen"},
    )
    with pytest.raises(InvalidTokenResponse):
        client.authorization_code("mycode")
    assert requests_mock.called_once


def test_invalid_token_response_200(requests_mock: RequestsMocker, token_endpoint: str, client_id: str) -> None:
    """Token Endpoint successful responses outside the standard raises an InvalidTokenResponse."""
    client = OAuth2Client(token_endpoint, auth=client_id)
    requests_mock.post(token_endpoint, status_code=200, json={"confusing": "data"})
    with pytest.raises(InvalidTokenResponse):
        client.authorization_code("mycode")

    requests_mock.reset_mock()
    requests_mock.post(
        token_endpoint,
        status_code=200,
        json={"foo": "this shouldn't happen"},
    )
    with pytest.raises(InvalidTokenResponse):
        client.authorization_code("mycode")
    assert requests_mock.called_once


def test_revoke_access_token(
    requests_mock: RequestsMocker,
    token_endpoint: str,
    revocation_endpoint: str,
    client_auth_method: BaseClientAuthenticationMethod,
    access_token: str,
    client_auth_method_handler: type[BaseClientAuthenticationMethod],
    public_app_auth_validator: RequestValidatorType,
    client_secret_basic_auth_validator: RequestValidatorType,
    client_secret_post_auth_validator: RequestValidatorType,
    client_secret_jwt_auth_validator: RequestValidatorType,
    private_key_jwt_auth_validator: RequestValidatorType,
    client_id: str,
    client_credential: None | str | Jwk,
    public_jwk: Jwk,
    revocation_request_validator: RequestValidatorType,
) -> None:
    """Test for OAuth2Client.revoke_access_token().

    It sends a Revocation request to the Revocation Endpoint, with token_type_hint=access_token.

    """
    client = OAuth2Client(token_endpoint, revocation_endpoint=revocation_endpoint, auth=client_auth_method)

    requests_mock.post(revocation_endpoint)

    assert client.revoke_access_token(access_token) is True

    assert requests_mock.called_once
    revocation_request_validator(requests_mock.last_request, token=access_token, type_hint="access_token")

    if client_auth_method_handler == PublicApp:
        public_app_auth_validator(requests_mock.last_request, client_id=client_id)
    elif client_auth_method_handler == ClientSecretPost:
        client_secret_post_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
        )
    elif client_auth_method_handler == ClientSecretBasic:
        client_secret_basic_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
        )
    elif client_auth_method_handler == ClientSecretJwt:
        client_secret_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
            endpoint=revocation_endpoint,
        )
    elif client_auth_method_handler == PrivateKeyJwt:
        private_key_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            endpoint=revocation_endpoint,
            public_jwk=public_jwk,
        )


def test_revoke_refresh_token(
    requests_mock: RequestsMocker,
    token_endpoint: str,
    revocation_endpoint: str,
    client_auth_method: BaseClientAuthenticationMethod,
    refresh_token: str,
    client_auth_method_handler: type[BaseClientAuthenticationMethod],
    public_app_auth_validator: RequestValidatorType,
    client_secret_basic_auth_validator: RequestValidatorType,
    client_secret_post_auth_validator: RequestValidatorType,
    client_secret_jwt_auth_validator: RequestValidatorType,
    private_key_jwt_auth_validator: RequestValidatorType,
    client_id: str,
    client_credential: None | str | Jwk,
    public_jwk: Jwk,
    revocation_request_validator: RequestValidatorType,
) -> None:
    """Test for `OAuth2Client.revoke_refresh_token()`.

    It sends a Revocation request to the Revocation Endpoint, with token_type_hint=refresh_token.

    """
    client = OAuth2Client(token_endpoint, revocation_endpoint=revocation_endpoint, auth=client_auth_method)
    requests_mock.post(revocation_endpoint)
    assert client.revoke_refresh_token(refresh_token) is True

    assert requests_mock.called_once
    revocation_request_validator(requests_mock.last_request, token=refresh_token, type_hint="refresh_token")
    if client_auth_method_handler == PublicApp:
        public_app_auth_validator(requests_mock.last_request, client_id=client_id)
    elif client_auth_method_handler == ClientSecretPost:
        client_secret_post_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
        )
    elif client_auth_method_handler == ClientSecretBasic:
        client_secret_basic_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
        )
    elif client_auth_method_handler == ClientSecretJwt:
        client_secret_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
            endpoint=revocation_endpoint,
        )
    elif client_auth_method_handler == PrivateKeyJwt:
        private_key_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            endpoint=revocation_endpoint,
            public_jwk=public_jwk,
        )


def test_revoke_refresh_token_with_bearer_token_as_param(
    requests_mock: RequestsMocker,
    token_endpoint: str,
    revocation_endpoint: str,
    client_auth_method: BaseClientAuthenticationMethod,
    access_token: str,
    refresh_token: str,
    revocation_request_validator: RequestValidatorType,
) -> None:
    """Test for `OAuth2Client.revoke_refresh_token()`.

    If passed a BearerToken containing a refresh_token, it sends a Revocation request to the Revocation Endpoint, with
    that refresh token, and token_type_hint=refresh_token.

    """
    client = OAuth2Client(token_endpoint, revocation_endpoint=revocation_endpoint, auth=client_auth_method)
    bearer = BearerToken(access_token, refresh_token=refresh_token)
    requests_mock.post(revocation_endpoint)
    assert client.revoke_refresh_token(bearer) is True

    assert requests_mock.called_once
    revocation_request_validator(
        requests_mock.last_request,
        token=bearer.refresh_token,
        type_hint="refresh_token",
    )

    bearer_no_refresh = BearerToken(access_token)
    with pytest.raises(ValueError):
        client.revoke_refresh_token(bearer_no_refresh)


def test_revoke_token(
    requests_mock: RequestsMocker,
    token_endpoint: str,
    revocation_endpoint: str,
    client_auth_method: BaseClientAuthenticationMethod,
    refresh_token: str,
    client_auth_method_handler: type[BaseClientAuthenticationMethod],
    public_app_auth_validator: RequestValidatorType,
    client_secret_basic_auth_validator: RequestValidatorType,
    client_secret_post_auth_validator: RequestValidatorType,
    client_secret_jwt_auth_validator: RequestValidatorType,
    private_key_jwt_auth_validator: RequestValidatorType,
    client_id: str,
    client_credential: None | str | Jwk,
    public_jwk: Jwk,
    revocation_request_validator: RequestValidatorType,
) -> None:
    """.revoke_token() sends a Revocation request to the Revocation Endpoint."""
    client = OAuth2Client(token_endpoint, revocation_endpoint=revocation_endpoint, auth=client_auth_method)
    requests_mock.post(revocation_endpoint, status_code=200)

    assert client.revoke_token(refresh_token) is True

    assert requests_mock.called_once
    revocation_request_validator(requests_mock.last_request, refresh_token)

    if client_auth_method_handler == PublicApp:
        public_app_auth_validator(requests_mock.last_request, client_id=client_id)
    elif client_auth_method_handler == ClientSecretPost:
        client_secret_post_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
        )
    elif client_auth_method_handler == ClientSecretBasic:
        client_secret_basic_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
        )
    elif client_auth_method_handler == ClientSecretJwt:
        client_secret_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
            endpoint=revocation_endpoint,
        )
    elif client_auth_method_handler == PrivateKeyJwt:
        private_key_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            endpoint=revocation_endpoint,
            public_jwk=public_jwk,
        )


def test_revoke_token_with_bearer_token_as_param(
    requests_mock: RequestsMocker,
    token_endpoint: str,
    revocation_endpoint: str,
    client_auth_method: BaseClientAuthenticationMethod,
    access_token: str,
    refresh_token: str,
    revocation_request_validator: RequestValidatorType,
) -> None:
    """Test for OAuth2Client.revoke_token().

    If a BearerToken is supplied and token_token_type_hint=refresh_token, take the refresh token from the BearerToken.

    """
    client = OAuth2Client(token_endpoint, revocation_endpoint=revocation_endpoint, auth=client_auth_method)
    bearer = BearerToken(access_token, refresh_token=refresh_token)
    requests_mock.post(revocation_endpoint, status_code=200)

    assert client.revoke_token(bearer, token_type_hint="refresh_token") is True

    assert requests_mock.called_once
    revocation_request_validator(requests_mock.last_request, refresh_token)

    bearer_no_refresh = BearerToken(access_token)
    with pytest.raises(ValueError):
        client.revoke_token(bearer_no_refresh, token_type_hint="refresh_token")


def test_revoke_token_error(
    requests_mock: RequestsMocker,
    token_endpoint: str,
    revocation_endpoint: str,
    client_auth_method: BaseClientAuthenticationMethod,
    refresh_token: str,
    client_auth_method_handler: type[BaseClientAuthenticationMethod],
    public_app_auth_validator: RequestValidatorType,
    client_secret_basic_auth_validator: RequestValidatorType,
    client_secret_post_auth_validator: RequestValidatorType,
    client_secret_jwt_auth_validator: RequestValidatorType,
    private_key_jwt_auth_validator: RequestValidatorType,
    client_id: str,
    client_credential: None | str | Jwk,
    public_jwk: Jwk,
    revocation_request_validator: RequestValidatorType,
) -> None:
    """Test for OAuth2Client.revoke_token() error cases."""
    client = OAuth2Client(token_endpoint, revocation_endpoint=revocation_endpoint, auth=client_auth_method)
    requests_mock.post(revocation_endpoint, status_code=400, json={"error": "server_error"})

    with pytest.raises(ServerError):
        client.revoke_token(refresh_token)

    assert requests_mock.called_once
    revocation_request_validator(requests_mock.last_request, refresh_token)

    if client_auth_method_handler == PublicApp:
        public_app_auth_validator(requests_mock.last_request, client_id=client_id)
    elif client_auth_method_handler == ClientSecretPost:
        client_secret_post_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
        )
    elif client_auth_method_handler == ClientSecretBasic:
        client_secret_basic_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
        )
    elif client_auth_method_handler == ClientSecretJwt:
        client_secret_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
            endpoint=revocation_endpoint,
        )
    elif client_auth_method_handler == PrivateKeyJwt:
        private_key_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            endpoint=revocation_endpoint,
            public_jwk=public_jwk,
        )


def test_revoke_token_error_non_standard(
    requests_mock: RequestsMocker,
    token_endpoint: str,
    revocation_endpoint: str,
    client_auth_method: BaseClientAuthenticationMethod,
    refresh_token: str,
) -> None:
    """Test for `OAuth2Client.revoke_token()`.

    It sends a Revocation request to the Revocation Endpoint, with token_type_hint=access_token.

    """
    client = OAuth2Client(token_endpoint, revocation_endpoint=revocation_endpoint, auth=client_auth_method)
    requests_mock.post(revocation_endpoint, status_code=400, text="Error")

    assert client.revoke_token(refresh_token) is False
    assert requests_mock.called_once

    requests_mock.reset_mock()
    requests_mock.post(revocation_endpoint, status_code=400, json={"foo": "bar"})
    assert client.revoke_token(refresh_token) is False
    assert requests_mock.called_once


def test_revoke_token_no_revocation_endpoint(token_endpoint: str, client_id: str) -> None:
    """Revocation methods raise AttributeError if no revocation_endpoint is configured."""
    client = OAuth2Client(token_endpoint, revocation_endpoint=None, auth=client_id)

    with pytest.raises(AttributeError):
        client.revoke_token("foo", token_type_hint="access_token")


def test_server_jwks(
    requests_mock: RequestsMocker,
    oauth2client: OAuth2Client,
    jwks_uri: str,
    server_public_jwks: JwkSet,
) -> None:
    """Use OAuth2Client as a context manager to automatically get public JWKS from its JWKS URI."""
    assert not oauth2client.authorization_server_jwks
    requests_mock.get(jwks_uri, json=server_public_jwks.to_dict())
    with oauth2client as client:
        assert client.authorization_server_jwks == server_public_jwks
    assert requests_mock.called_once


def test_server_jwks_no_jwks_uri(token_endpoint: str) -> None:
    """If JWKS URI is not known, update_authorization_server_public_keys() raises an exception."""
    client = OAuth2Client(token_endpoint=token_endpoint, auth=("foo", "bar"))
    with pytest.raises(AttributeError):
        client.update_authorization_server_public_keys()


def test_server_jwks_not_json(requests_mock: RequestsMocker, token_endpoint: str, jwks_uri: str) -> None:
    """If JWKS URI is not known, get_public_jwks() raises an exception."""
    requests_mock.get(jwks_uri, text="Hello World!")
    client = OAuth2Client(token_endpoint=token_endpoint, jwks_uri=jwks_uri, auth=("foo", "bar"))
    with pytest.raises(ValueError):
        client.update_authorization_server_public_keys()
    assert requests_mock.called_once


def test_server_jwks_invalid_doc(requests_mock: RequestsMocker, token_endpoint: str, jwks_uri: str) -> None:
    """If JWKS URI is an invalid document, get_public_jwks() raises an exception."""
    requests_mock.get(jwks_uri, json={"foo": "bar"})
    client = OAuth2Client(token_endpoint=token_endpoint, jwks_uri=jwks_uri, auth=("foo", "bar"))
    jwks = client.update_authorization_server_public_keys()
    assert requests_mock.called_once
    assert not jwks.jwks


def test_get_token_type() -> None:
    assert OAuth2Client.get_token_type(token_type="access_token") == "urn:ietf:params:oauth:token-type:access_token"
    assert OAuth2Client.get_token_type(token_type="refresh_token") == "urn:ietf:params:oauth:token-type:refresh_token"
    assert OAuth2Client.get_token_type(token_type="id_token") == "urn:ietf:params:oauth:token-type:id_token"
    assert OAuth2Client.get_token_type(token_type="saml2") == "urn:ietf:params:oauth:token-type:saml2"

    with pytest.raises(ValueError):
        OAuth2Client.get_token_type(token="token")

    assert (
        OAuth2Client.get_token_type(token=BearerToken("access_token"))
        == "urn:ietf:params:oauth:token-type:access_token"
    )
    assert (
        OAuth2Client.get_token_type(token=BearerToken("access_token", refresh_token="refresh_token"))
        == "urn:ietf:params:oauth:token-type:access_token"
    )
    assert (
        OAuth2Client.get_token_type(
            token=BearerToken("access_token", refresh_token="refresh_token"),
            token_type="refresh_token",
        )
        == "urn:ietf:params:oauth:token-type:refresh_token"
    )

    with pytest.raises(ValueError):
        OAuth2Client.get_token_type(token=BearerToken("access_token"), token_type="refresh_token")

    with pytest.raises(ValueError):
        OAuth2Client.get_token_type()

    assert (
        OAuth2Client.get_token_type(
            token=IdToken(
                "eyJhbGciOiJSUzI1NiIsImtpZCI6Im15X2tleSJ9."
                "eyJhY3IiOiIyIiwiYW1yIjpbInB3ZCIsIm90cCJdLCJhdWQiOiJjbGllbnRfaWQiLCJhdXRoX3RpbWUiOjE2MjkyMDQ1NjAsImV4"
                "cCI6MTYyOTIwNDYyMCwiaWF0IjoxNjI5MjA0NTYwLCJpc3MiOiJodHRwczovL215YXMubG9jYWwiLCJub25jZSI6Im5vbmNlIiwi"
                "c3ViIjoiMTIzNDU2In0.wUfjMyjlOSdvbFGFP8O8wGcNBK7akeyOUBMvYcNZclFUtokOyxhLUPxmo1THo1DV1BHUVd6AWfeKUnyT"
                "xl_8-G3E_a9u5wJfDyfghPDhCmfkYARvqQnnV_3aIbfTfUBC4f0bHr08d_q0fED88RLu77wESIPCVqQYy2bk4FLucc63yGBvaCsk"
                "qzthZ85DbBJYWLlR8qBUk_NA8bWATYEtjwTrxoZe-uA-vB6NwUv1h8DKRsDF-9HSVHeWXXAeoG9UW7zgxoY3KbDIVzemvGzs2R9O"
                "gDBRRafBBVeAkDV6CdbdMNJDmHzcjase5jX6LE-3YCy7c7AMM1uWRCnK3f"
            )
        )
        == "urn:ietf:params:oauth:token-type:id_token"
    )

    with pytest.raises(TypeError):
        OAuth2Client.get_token_type(token=1.33)  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        OAuth2Client.get_token_type(token=1.33, token_type="access_token")  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        OAuth2Client.get_token_type(token=1.33, token_type="id_token")  # type: ignore[arg-type]


def test_introspection(
    requests_mock: RequestsMocker,
    oauth2client: OAuth2Client,
    introspection_endpoint: str,
    introspection_request_validator: RequestValidatorType,
    client_auth_method_handler: type[BaseClientAuthenticationMethod],
    public_app_auth_validator: RequestValidatorType,
    client_id: str,
    client_secret_post_auth_validator: RequestValidatorType,
    client_credential: None | str | Jwk,
    client_secret_basic_auth_validator: RequestValidatorType,
    client_secret_jwt_auth_validator: RequestValidatorType,
    private_key_jwt_auth_validator: RequestValidatorType,
    public_jwk: Jwk,
) -> None:
    introspection_data = {"active": False}
    requests_mock.post(introspection_endpoint, json=introspection_data)
    data = oauth2client.introspect_token("access_token")
    assert data == introspection_data
    assert requests_mock.called_once
    introspection_request_validator(requests_mock.last_request, token="access_token")

    if client_auth_method_handler == PublicApp:
        public_app_auth_validator(requests_mock.last_request, client_id=client_id)
    elif client_auth_method_handler == ClientSecretPost:
        client_secret_post_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
        )
    elif client_auth_method_handler == ClientSecretBasic:
        client_secret_basic_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
        )
    elif client_auth_method_handler == ClientSecretJwt:
        client_secret_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
            endpoint=introspection_endpoint,
        )
    elif client_auth_method_handler == PrivateKeyJwt:
        private_key_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            endpoint=introspection_endpoint,
            public_jwk=public_jwk,
        )


def test_introspection_no_introspection_endpoint(
    token_endpoint: str,
    client_id: str,
    client_secret: str,
) -> None:
    client = OAuth2Client(token_endpoint, auth=(client_id, client_secret))

    with pytest.raises(AttributeError):
        client.introspect_token("foo")


def test_introspection_error(
    requests_mock: RequestsMocker,
    oauth2client: OAuth2Client,
    introspection_endpoint: str,
    introspection_request_validator: RequestValidatorType,
) -> None:
    requests_mock.post(introspection_endpoint, status_code=400, json={"error": "unauthorized_client"})
    with pytest.raises(UnauthorizedClient):
        oauth2client.introspect_token("access_token")

    assert requests_mock.called_once
    introspection_request_validator(requests_mock.last_request, token="access_token")


def test_introspection_jwt(
    requests_mock: RequestsMocker,
    oauth2client: OAuth2Client,
    introspection_endpoint: str,
    introspection_request_validator: RequestValidatorType,
) -> None:
    introspection = "This.ShouldBe.aJWT"
    requests_mock.post(introspection_endpoint, text=introspection)
    assert oauth2client.introspect_token("access_token") == introspection

    assert requests_mock.called_once
    introspection_request_validator(requests_mock.last_request, token="access_token")


def test_introspection_unknown_error(
    requests_mock: RequestsMocker,
    oauth2client: OAuth2Client,
    introspection_endpoint: str,
    introspection_request_validator: RequestValidatorType,
) -> None:
    requests_mock.post(introspection_endpoint, status_code=400, text="Error")
    with pytest.raises(UnknownIntrospectionError):
        oauth2client.introspect_token("access_token")

    assert requests_mock.called_once
    introspection_request_validator(requests_mock.last_request, token="access_token")

    requests_mock.reset_mock()
    requests_mock.post(introspection_endpoint, status_code=400, json={"foo": "bar"})
    with pytest.raises(UnknownIntrospectionError):
        oauth2client.introspect_token("access_token")

    assert requests_mock.called_once


def test_introspection_with_bearer_token_as_param(
    requests_mock: RequestsMocker,
    oauth2client: OAuth2Client,
    introspection_endpoint: str,
    access_token: str,
    refresh_token: str,
    introspection_request_validator: RequestValidatorType,
) -> None:
    requests_mock.post(introspection_endpoint, status_code=200, json={"active": False})
    bearer = BearerToken(access_token, refresh_token=refresh_token)
    assert oauth2client.introspect_token(bearer, "refresh_token")
    assert requests_mock.called_once
    introspection_request_validator(requests_mock.last_request, token=refresh_token, type_hint="refresh_token")

    requests_mock.reset()
    assert oauth2client.introspect_token(bearer, token_type_hint="access_token")
    assert requests_mock.called_once
    introspection_request_validator(requests_mock.last_request, token=access_token, type_hint="access_token")

    bearer_no_refresh = BearerToken(access_token, refresh_token=None)
    with pytest.raises(ValueError):
        oauth2client.introspect_token(bearer_no_refresh, "refresh_token")

    with pytest.raises(ValueError, match="Invalid `token_type_hint`"):
        oauth2client.introspect_token(bearer, token_type_hint="unknown_token")


def test_ciba(
    requests_mock: RequestsMocker,
    oauth2client: OAuth2Client,
    auth_req_id: str,
    token_endpoint: str,
    access_token: str,
    ciba_request_validator: RequestValidatorType,
) -> None:
    requests_mock.post(token_endpoint, json={"access_token": access_token, "expires_in": 60})
    token = oauth2client.ciba(auth_req_id=auth_req_id)
    assert isinstance(token, BearerToken)
    assert requests_mock.called_once
    ciba_request_validator(requests_mock.last_request, auth_req_id=auth_req_id)


def test_pushed_authorization_request(
    requests_mock: RequestsMocker,
    oauth2client: OAuth2Client,
    pushed_authorization_request_endpoint: str,
    authorization_request: AuthorizationRequest,
) -> None:
    request_uri = "request_uri"
    expires_in = 60

    requests_mock.post(
        pushed_authorization_request_endpoint,
        json={"request_uri": request_uri, "expires_in": expires_in},
    )

    razr = oauth2client.pushed_authorization_request(authorization_request)
    assert isinstance(razr, RequestUriParameterAuthorizationRequest)
    assert razr.request_uri == request_uri
    assert isinstance(razr.expires_at, datetime)
    assert datetime.now(tz=timezone.utc) - timedelta(seconds=2) < razr.expires_at - timedelta(seconds=expires_in)


def test_pushed_authorization_request_error(
    requests_mock: RequestsMocker,
    oauth2client: OAuth2Client,
    pushed_authorization_request_endpoint: str,
    authorization_request: AuthorizationRequest,
) -> None:
    requests_mock.post(pushed_authorization_request_endpoint, json={"error": "server_error"}, status_code=500)

    with pytest.raises(ServerError):
        oauth2client.pushed_authorization_request(authorization_request)

    requests_mock.post(pushed_authorization_request_endpoint, text="foobar", status_code=500)

    with pytest.raises(InvalidPushedAuthorizationResponse):
        oauth2client.pushed_authorization_request(authorization_request)


def test_jwt_bearer_grant(requests_mock: RequestsMocker, oauth2client: OAuth2Client, token_endpoint: str) -> None:
    key = Jwk.generate(alg="ES256")
    assertion = Jwt.sign({"iat": 1661759343, "exp": 1661759403, "sub": "some_user_id"}, key)
    scope = "my_scope"

    requests_mock.post(
        token_endpoint,
        json={"access_token": "access_token", "token_type": "Bearer", "scope": scope},
    )

    # pass the assertion as a `Jwt`
    token = oauth2client.jwt_bearer(assertion=assertion, scope=scope)
    assert isinstance(token, BearerToken)
    assert requests_mock.called_once
    assert token.scope == scope

    # pass the assertion as `str`
    requests_mock.reset_mock()
    token = oauth2client.jwt_bearer(assertion=str(assertion), scope=scope)
    assert isinstance(token, BearerToken)
    assert requests_mock.called_once
    assert token.scope == scope


def test_authorization_request(oauth2client: OAuth2Client, authorization_endpoint: str) -> None:
    scope = "my_scope"
    auth_req = oauth2client.authorization_request(scope="my_scope")
    assert isinstance(auth_req, AuthorizationRequest)
    assert auth_req.authorization_endpoint == authorization_endpoint
    assert auth_req.response_type == "code"
    assert auth_req.scope == tuple(scope.split())

    with pytest.raises(ValueError) as exc:
        oauth2client.authorization_request(response_type="token")
    assert exc.type is UnsupportedResponseTypeParam


def test_custom_token_type(requests_mock: RequestsMocker, token_endpoint: str) -> None:
    class CustomBearerToken(BearerToken):
        TOKEN_TYPE = "CustomBearerToken"

    client = OAuth2Client(token_endpoint, ("client_id", "client_secret"), token_class=CustomBearerToken)

    requests_mock.post(
        token_endpoint,
        json={"access_token": "access_token", "token_type": "CustomBearerToken"},
    )

    token = client.client_credentials()
    assert isinstance(token, CustomBearerToken)


def test_client_jwks() -> None:
    private_key = Jwk.generate(alg=SignatureAlgs.RS256).with_kid_thumbprint()
    id_token_decryption_key = Jwk.generate(alg=KeyManagementAlgs.ECDH_ES_A256KW, crv="P-256").with_kid_thumbprint()
    client = OAuth2Client(
        authorization_endpoint="https://as.local/authorize",
        token_endpoint="https://as.local/token",
        client_id="my_client_id",
        private_key=private_key,
        id_token_decryption_key=id_token_decryption_key,
    )

    jwks = client.client_jwks
    assert not jwks.is_private
    assert private_key.public_jwk() in jwks.jwks
    assert id_token_decryption_key.public_jwk() in jwks.jwks


def test_issuer_identification_missing_issuer() -> None:
    with pytest.raises(ValueError, match="issuer"):
        OAuth2Client(
            authorization_endpoint="https://as.local/authorize",
            token_endpoint="https://as.local/token",
            client_id="my_client_id",
            authorization_response_iss_parameter_supported=True,
        )


def test_client_authorization_server_jwks() -> None:
    jwks = Jwk.generate(alg="ES256").public_jwk().as_jwks()
    assert (
        OAuth2Client(
            "https://as.local/token", client_id="client_id", authorization_server_jwks=jwks
        ).authorization_server_jwks
        is jwks
    )
    assert (
        OAuth2Client(
            "https://as.local/token", client_id="client_id", authorization_server_jwks=jwks.to_dict()
        ).authorization_server_jwks
        == jwks
    )


def test_client_id_token_decryption_key() -> None:
    decryption_key = Jwk.generate(alg=KeyManagementAlgs.ECDH_ES_A256KW, crv="P-256")
    assert (
        OAuth2Client(
            "https://as.local/token", client_id="client_id", id_token_decryption_key=decryption_key
        ).id_token_decryption_key
        is decryption_key
    )
    assert (
        OAuth2Client(
            "https://as.local/token", client_id="client_id", id_token_decryption_key=decryption_key.to_dict()
        ).id_token_decryption_key
        == decryption_key
    )

    with pytest.raises(ValueError, match="no decryption algorithm is defined"):
        OAuth2Client("https://as.local/token", client_id="client_id", id_token_decryption_key=decryption_key.minimize())


def test_client_custom_auth_method() -> None:
    class CustomAuthHandler(requests.auth.AuthBase):
        def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
            request.headers["Super-Secure"] = "true"
            return request

    with pytest.raises(AttributeError, match="custom authentication method without client_id"):
        OAuth2Client("https://as.local/token", auth=CustomAuthHandler()).client_id


def test_testing_oauth2client() -> None:
    issuer = "http://localhost:1234"
    token_endpoint = "http://localhost:1234/token"

    with pytest.raises(ValueError, match="must use https"):
        OAuth2Client(token_endpoint=token_endpoint, client_id="client_id")

    with pytest.raises(ValueError, match="must use https"):
        OAuth2Client(token_endpoint="https://valid.token/endpoint", client_id="client_id", issuer=issuer)

    with pytest.raises(ValueError, match="must include a path"):
        OAuth2Client(token_endpoint="https://foo.bar/", client_id="client_id")

    test_client = OAuth2Client(
        token_endpoint=token_endpoint,
        client_id="foo",
        client_secret="bar",
        issuer=issuer,
        testing=True,
    )

    assert test_client.token_endpoint == token_endpoint
    assert test_client.issuer == issuer


def test_proxy_authorization(requests_mock: RequestsMocker, target_api: str) -> None:
    access_token = "my_proxy_auth_token"
    auth_header = "Proxy-Authorization"

    class ProxyAuthorizationBearerToken(BearerToken):
        AUTHORIZATION_HEADER = auth_header

    requests_mock.post(target_api)

    requests.post(target_api, auth=ProxyAuthorizationBearerToken(access_token))
    assert requests_mock.last_request is not None
    assert requests_mock.last_request.headers[auth_header] == f"Bearer {access_token}"


def test_custom_ports_in_endpoints(requests_mock: RequestsMocker) -> None:
    issuer = "https://as.local:8443"
    token_endpoint = "https://as.local:8443/token"
    client = OAuth2Client(token_endpoint=token_endpoint, client_id="client_id", client_secret="client_secret")
    assert client.token_endpoint == token_endpoint

    assert not requests_mock.called_once
    with pytest.raises(InvalidIssuer, match="must use https"):
        OAuth2Client.from_discovery_endpoint(issuer="http://as.local")
    assert not requests_mock.called_once

    with pytest.raises(InvalidIssuer, match="must use https"):
        OAuth2Client.from_discovery_endpoint(issuer="http://as.local:8080")
    assert not requests_mock.called_once

    with pytest.raises(InvalidUri, match="must use https"):
        OAuth2Client.from_discovery_endpoint(url="http://as.local/.well-known/openid-configuration")
    assert not requests_mock.called_once

    requests_mock.get(
        "https://as.local/.well-known/openid-configuration", json={"issuer": issuer, "token_endpoint": token_endpoint}
    )
    with pytest.raises(
        InvalidParam,
        match=rf"Mismatching `issuer` value in discovery document \(received '{issuer}', expected 'https://as.local'\)",
    ):
        OAuth2Client.from_discovery_endpoint(issuer="https://as.local", client_id="client_id")
    assert requests_mock.called_once

    discovery_url = "https://as.local:8443/.well-known/openid-configuration"
    requests_mock.get(discovery_url, json={"issuer": issuer, "token_endpoint": token_endpoint})

    requests_mock.reset()
    assert (
        OAuth2Client.from_discovery_endpoint(
            url="https://as.local:8443/.well-known/openid-configuration", client_id="client_id"
        ).token_endpoint
        == token_endpoint
    )
    assert requests_mock.called_once

    requests_mock.reset()
    assert (
        OAuth2Client.from_discovery_endpoint(issuer="https://as.local:8443", client_id="client_id").token_endpoint
        == token_endpoint
    )
    assert requests_mock.called_once
