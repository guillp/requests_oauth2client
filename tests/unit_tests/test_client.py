import secrets

import pytest

from requests_oauth2client import (
    BearerToken,
    ClientSecretBasic,
    ClientSecretJWT,
    ClientSecretPost,
    IdToken,
    InvalidTokenResponse,
    OAuth2Client,
    PrivateKeyJWT,
    PublicApp,
    ServerError,
    UnauthorizedClient,
    UnknownIntrospectionError,
    oidc_discovery_document_url,
)


def test_public_client_auth(token_endpoint, client_id):
    """Passing a client_id as `auth` uses PublicApp authentication."""
    client = OAuth2Client(token_endpoint, auth=client_id)
    assert isinstance(client.auth, PublicApp)
    assert client.auth.client_id == client_id


def test_private_key_jwt_auth(token_endpoint, client_id, private_jwk):
    """Passing a (client_id, private_jwk) tuple  as `auth` uses PrivateKeyJWT authentication."""
    client = OAuth2Client(token_endpoint, auth=(client_id, private_jwk))
    assert isinstance(client.auth, PrivateKeyJWT)
    assert client.auth.client_id == client_id
    assert client.auth.private_jwk == private_jwk


def test_client_secret_post_auth(token_endpoint, client_id, client_secret):
    """Passing a (client_id, client_secret) tuple  as `auth` uses ClientSecretPost authentication."""
    client = OAuth2Client(token_endpoint, auth=(client_id, client_secret))
    assert isinstance(client.auth, ClientSecretPost)
    assert client.auth.client_id == client_id
    assert client.auth.client_secret == client_secret


def test_client_secret_basic_auth(token_endpoint, client_id, client_secret):
    """Passing a (client_id, client_secret) tuple  as `auth` and ClientSecretBasic as `default_auth_handler` uses ClientSecretBasic authentication."""
    client = OAuth2Client(
        token_endpoint, auth=ClientSecretBasic(client_id, client_secret)
    )
    assert isinstance(client.auth, ClientSecretBasic)
    assert client.auth.client_id == client_id
    assert client.auth.client_secret == client_secret


def test_missing_auth(token_endpoint):
    """`auth` is required"""
    with pytest.raises(ValueError):
        OAuth2Client(token_endpoint, auth=None)


def test_client_credentials_grant(
    requests_mock,
    oauth2client,
    token_endpoint,
    access_token,
    refresh_token,
    scope,
    client_credentials_grant_validator,
    client_auth_method_handler,
    client_id,
    client_credential,
    public_jwk,
    public_app_auth_validator,
    client_secret_post_auth_validator,
    client_secret_basic_auth_validator,
    client_secret_jwt_auth_validator,
    private_key_jwt_auth_validator,
):
    """.client_credentials() sends a requests to the Token Endpoint using the Client Credentials grant."""
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
    elif client_auth_method_handler == ClientSecretJWT:
        client_secret_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
            endpoint=token_endpoint,
        )
    elif client_auth_method_handler == PrivateKeyJWT:
        private_key_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            endpoint=token_endpoint,
            public_jwk=public_jwk,
        )


def test_client_credentials_grant_with_scope_list(
    requests_mock,
    oauth2client,
    token_endpoint,
    access_token,
    refresh_token,
    scope,
    client_credentials_grant_validator,
    client_auth_method_handler,
    client_id,
    client_credential,
    public_jwk,
    public_app_auth_validator,
    client_secret_post_auth_validator,
    client_secret_basic_auth_validator,
    client_secret_jwt_auth_validator,
    private_key_jwt_auth_validator,
):
    """the 'scope' parameter to .client_credentials() can be a list."""
    requests_mock.post(
        token_endpoint,
        json={
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": 3600,
        },
    )

    oauth2client.client_credentials(scope=scope.split(" "))
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
    elif client_auth_method_handler == ClientSecretJWT:
        client_secret_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
            endpoint=token_endpoint,
        )
    elif client_auth_method_handler == PrivateKeyJWT:
        private_key_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            endpoint=token_endpoint,
            public_jwk=public_jwk,
        )


def test_client_credentials_invalid_scope(oauth2client):
    with pytest.raises(ValueError):
        oauth2client.client_credentials(scope=1.634)


def test_authorization_code_grant(
    requests_mock,
    oauth2client,
    token_endpoint,
    authorization_code,
    access_token,
    refresh_token,
    authorization_code_grant_validator,
    client_auth_method_handler,
    client_id,
    client_credential,
    public_jwk,
    public_app_auth_validator,
    client_secret_post_auth_validator,
    client_secret_basic_auth_validator,
    client_secret_jwt_auth_validator,
    private_key_jwt_auth_validator,
):
    """.authorization_code() sends a requests to the Token Endpoint using the Authorization Code grant."""
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
    authorization_code_grant_validator(
        requests_mock.last_request, code=authorization_code
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
    elif client_auth_method_handler == ClientSecretJWT:
        client_secret_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
            endpoint=token_endpoint,
        )
    elif client_auth_method_handler == PrivateKeyJWT:
        private_key_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            endpoint=token_endpoint,
            public_jwk=public_jwk,
        )


def test_authorization_code_pkce_grant(
    requests_mock,
    oauth2client,
    token_endpoint,
    authorization_code,
    code_verifier,
    access_token,
    refresh_token,
    authorization_code_grant_validator,
    client_auth_method_handler,
    client_id,
    client_credential,
    public_jwk,
    public_app_auth_validator,
    client_secret_post_auth_validator,
    client_secret_basic_auth_validator,
    client_secret_jwt_auth_validator,
    private_key_jwt_auth_validator,
):
    """.authorization_code_pkce() sends a requests to the Token Endpoint using the Authorization Code grant, with PKCE extension."""
    requests_mock.post(
        token_endpoint,
        json={
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": 3600,
        },
    )

    oauth2client.authorization_code_pkce(
        code=authorization_code, code_verifier=code_verifier
    )

    assert requests_mock.called_once
    authorization_code_grant_validator(
        requests_mock.last_request, code=authorization_code, code_verifier=code_verifier
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
    elif client_auth_method_handler == ClientSecretJWT:
        client_secret_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
            endpoint=token_endpoint,
        )
    elif client_auth_method_handler == PrivateKeyJWT:
        private_key_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            endpoint=token_endpoint,
            public_jwk=public_jwk,
        )


def test_refresh_token_grant(
    requests_mock,
    oauth2client,
    token_endpoint,
    refresh_token,
    client_id,
    client_credential,
    public_jwk,
    client_auth_method_handler,
    refresh_token_grant_validator,
    public_app_auth_validator,
    client_secret_basic_auth_validator,
    client_secret_post_auth_validator,
    client_secret_jwt_auth_validator,
    private_key_jwt_auth_validator,
):
    """.refresh_token() sends a requests to the Token Endpoint using the Refresh Token grant."""
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

    refresh_token_grant_validator(
        requests_mock.last_request, refresh_token=refresh_token
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
    elif client_auth_method_handler == ClientSecretJWT:
        client_secret_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
            endpoint=token_endpoint,
        )
    elif client_auth_method_handler == PrivateKeyJWT:
        private_key_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            endpoint=token_endpoint,
            public_jwk=public_jwk,
        )


def test_device_code_grant(
    requests_mock,
    oauth2client,
    token_endpoint,
    device_code,
    client_id,
    client_credential,
    public_jwk,
    client_auth_method_handler,
    device_code_grant_validator,
    public_app_auth_validator,
    client_secret_basic_auth_validator,
    client_secret_post_auth_validator,
    client_secret_jwt_auth_validator,
    private_key_jwt_auth_validator,
):
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
    elif client_auth_method_handler == ClientSecretJWT:
        client_secret_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
            endpoint=token_endpoint,
        )
    elif client_auth_method_handler == PrivateKeyJWT:
        private_key_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            endpoint=token_endpoint,
            public_jwk=public_jwk,
        )


def test_token_exchange_grant(
    requests_mock,
    oauth2client,
    token_endpoint,
    client_id,
    client_credential,
    public_jwk,
    client_auth_method_handler,
    token_exchange_grant_validator,
    public_app_auth_validator,
    client_secret_basic_auth_validator,
    client_secret_post_auth_validator,
    client_secret_jwt_auth_validator,
    private_key_jwt_auth_validator,
):
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
    elif client_auth_method_handler == ClientSecretJWT:
        client_secret_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
            endpoint=token_endpoint,
        )
    elif client_auth_method_handler == PrivateKeyJWT:
        private_key_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            endpoint=token_endpoint,
            public_jwk=public_jwk,
        )


def test_token_exchange_invalid_tokens(oauth2client):
    with pytest.raises(TypeError):
        oauth2client.token_exchange(subject_token="foo")

    with pytest.raises(TypeError):
        oauth2client.token_exchange(
            subject_token="foo", subject_token_type="access_token", actor_token="foo"
        )


def test_userinfo(
    requests_mock,
    oauth2client,
    userinfo_endpoint,
    bearer_auth_validator,
    access_token,
    sub,
):
    """.userinfo_endpoint() sends a requests to the Userinfo Endpoint and returns a JSON."""
    userinfo = {"sub": sub}
    requests_mock.post(userinfo_endpoint, json=userinfo)
    resp = oauth2client.userinfo(access_token)
    assert requests_mock.called_once
    assert resp == userinfo
    bearer_auth_validator(requests_mock.last_request, access_token)


def test_userinfo_jwt(
    requests_mock,
    oauth2client,
    userinfo_endpoint,
    bearer_auth_validator,
    access_token,
    sub,
):
    """.userinfo_endpoint() sends a requests to the Userinfo Endpoint and returns a JSON."""
    userinfo = "This.ShouldBe.aJWT"
    requests_mock.post(userinfo_endpoint, text=userinfo)
    resp = oauth2client.userinfo(access_token)
    assert requests_mock.called_once
    assert resp == userinfo
    bearer_auth_validator(requests_mock.last_request, access_token)


def test_userinfo_no_uri(token_endpoint, client_id):
    """When userinfo_endpoint is not known, .userinfo() raises an exception."""
    client = OAuth2Client(token_endpoint, auth=client_id)
    with pytest.raises(AttributeError):
        client.userinfo("access_token")


def test_from_discovery_document(
    issuer,
    token_endpoint,
    revocation_endpoint,
    introspection_endpoint,
    userinfo_endpoint,
    jwks_uri,
    client_id,
):
    """You initialize an OAuth2Client based on a standardised discovery document with OAuth2Client.from_discovery_document()."""
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


def test_from_discovery_document_missing_token_endpoint(revocation_endpoint, client_id):
    """Invalid discovery documents raises an exception."""
    with pytest.raises(ValueError):
        OAuth2Client.from_discovery_document(
            {"revocation_endpoint": revocation_endpoint},
            issuer=None,
            auth=client_id,
        )


def test_from_discovery_document_token_endpoint_only(token_endpoint, client_id):
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


def test_from_discovery_document_test_issuer(token_endpoint, client_id):
    """Invalid discovery documents raises an exception."""
    with pytest.raises(ValueError):
        OAuth2Client.from_discovery_document(
            {"issuer": "https://example.com", "token_endpoint": token_endpoint},
            issuer="https://foo.bar",
            auth=client_id,
        )


def test_from_discovery_endpoint(
    requests_mock, issuer, discovery_document, client_auth_method
):
    discovery_url = oidc_discovery_document_url(issuer)

    requests_mock.get(discovery_url, json=discovery_document)

    client = OAuth2Client.from_discovery_endpoint(
        discovery_url, issuer, auth=client_auth_method
    )

    assert requests_mock.called_once
    assert isinstance(client, OAuth2Client)
    assert client.auth == client_auth_method


def test_invalid_token_response(requests_mock, token_endpoint, client_id):
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


def test_invalid_token_response_200(requests_mock, token_endpoint, client_id):
    """Token Endpoint successful responses outside the standard raises an InvalidTokenResponse"""
    client = OAuth2Client(token_endpoint, auth=client_id)
    requests_mock.post(token_endpoint, status_code=200, json={"confusing": "data"})
    with pytest.raises(InvalidTokenResponse):
        client.authorization_code("mycode")

    requests_mock.reset_mock()
    requests_mock.post(
        token_endpoint,
        status_code=200,
        json={"error_description": "this shouldn't happen"},
    )
    with pytest.raises(InvalidTokenResponse):
        client.authorization_code("mycode")
    assert requests_mock.called_once


def test_revoke_access_token(
    requests_mock,
    token_endpoint,
    revocation_endpoint,
    client_auth_method,
    access_token,
    client_auth_method_handler,
    public_app_auth_validator,
    client_secret_basic_auth_validator,
    client_secret_post_auth_validator,
    client_secret_jwt_auth_validator,
    private_key_jwt_auth_validator,
    client_id,
    client_credential,
    public_jwk,
    revocation_request_validator,
):
    """.revoke_access_token() sends a Revocation request to the Revocation Endpoint, with token_type_hint=access_token."""
    client = OAuth2Client(
        token_endpoint, revocation_endpoint=revocation_endpoint, auth=client_auth_method
    )

    requests_mock.post(revocation_endpoint)

    assert client.revoke_access_token(access_token) is True

    assert requests_mock.called_once
    revocation_request_validator(
        requests_mock.last_request, token=access_token, type_hint="access_token"
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
    elif client_auth_method_handler == ClientSecretJWT:
        client_secret_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
            endpoint=revocation_endpoint,
        )
    elif client_auth_method_handler == PrivateKeyJWT:
        private_key_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            endpoint=revocation_endpoint,
            public_jwk=public_jwk,
        )


def test_revoke_refresh_token(
    requests_mock,
    token_endpoint,
    revocation_endpoint,
    client_auth_method,
    refresh_token,
    client_auth_method_handler,
    public_app_auth_validator,
    client_secret_basic_auth_validator,
    client_secret_post_auth_validator,
    client_secret_jwt_auth_validator,
    private_key_jwt_auth_validator,
    client_id,
    client_credential,
    public_jwk,
    revocation_request_validator,
):
    """.revoke_refresh_token() sends a Revocation request to the Revocation Endpoint, with token_type_hint=refresh_token."""
    client = OAuth2Client(
        token_endpoint, revocation_endpoint=revocation_endpoint, auth=client_auth_method
    )
    requests_mock.post(revocation_endpoint)
    assert client.revoke_refresh_token(refresh_token) is True

    assert requests_mock.called_once
    revocation_request_validator(
        requests_mock.last_request, token=refresh_token, type_hint="refresh_token"
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
    elif client_auth_method_handler == ClientSecretJWT:
        client_secret_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
            endpoint=revocation_endpoint,
        )
    elif client_auth_method_handler == PrivateKeyJWT:
        private_key_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            endpoint=revocation_endpoint,
            public_jwk=public_jwk,
        )


def test_revoke_refresh_token_with_bearer_token_as_param(
    requests_mock,
    token_endpoint,
    revocation_endpoint,
    client_auth_method,
    access_token,
    refresh_token,
    revocation_request_validator,
):
    """.revoke_refresh_token() sends a Revocation request to the Revocation Endpoint, with token_type_hint=refresh_token."""
    client = OAuth2Client(
        token_endpoint, revocation_endpoint=revocation_endpoint, auth=client_auth_method
    )
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
        client.revoke_refresh_token(bearer_no_refresh, token_type_hint="refresh_token")


def test_revoke_token(
    requests_mock,
    token_endpoint,
    revocation_endpoint,
    client_auth_method,
    refresh_token,
    client_auth_method_handler,
    public_app_auth_validator,
    client_secret_basic_auth_validator,
    client_secret_post_auth_validator,
    client_secret_jwt_auth_validator,
    private_key_jwt_auth_validator,
    client_id,
    client_credential,
    public_jwk,
    revocation_request_validator,
):
    """.revoke_token() sends a Revocation request to the Revocation Endpoint."""
    client = OAuth2Client(
        token_endpoint, revocation_endpoint=revocation_endpoint, auth=client_auth_method
    )
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
    elif client_auth_method_handler == ClientSecretJWT:
        client_secret_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
            endpoint=revocation_endpoint,
        )
    elif client_auth_method_handler == PrivateKeyJWT:
        private_key_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            endpoint=revocation_endpoint,
            public_jwk=public_jwk,
        )


def test_revoke_token_with_bearer_token_as_param(
    requests_mock,
    token_endpoint,
    revocation_endpoint,
    client_auth_method,
    access_token,
    refresh_token,
    revocation_request_validator,
):
    """if a BearerToken is supplied and token_token_type_hint=refresh_token, take the refresh token from the BearerToken"""
    client = OAuth2Client(
        token_endpoint, revocation_endpoint=revocation_endpoint, auth=client_auth_method
    )
    bearer = BearerToken(access_token, refresh_token=refresh_token)
    requests_mock.post(revocation_endpoint, status_code=200)

    assert client.revoke_token(bearer, token_type_hint="refresh_token") is True

    assert requests_mock.called_once
    revocation_request_validator(requests_mock.last_request, refresh_token)

    bearer_no_refresh = BearerToken(access_token)
    with pytest.raises(ValueError):
        client.revoke_token(bearer_no_refresh, token_type_hint="refresh_token")


def test_revoke_token_error(
    requests_mock,
    token_endpoint,
    revocation_endpoint,
    client_auth_method,
    refresh_token,
    client_auth_method_handler,
    public_app_auth_validator,
    client_secret_basic_auth_validator,
    client_secret_post_auth_validator,
    client_secret_jwt_auth_validator,
    private_key_jwt_auth_validator,
    client_id,
    client_credential,
    public_jwk,
    revocation_request_validator,
):
    """.revoke_token() sends a Revocation request to the Revocation Endpoint, with token_type_hint=access_token."""
    client = OAuth2Client(
        token_endpoint, revocation_endpoint=revocation_endpoint, auth=client_auth_method
    )
    requests_mock.post(
        revocation_endpoint, status_code=400, json={"error": "server_error"}
    )

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
    elif client_auth_method_handler == ClientSecretJWT:
        client_secret_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
            endpoint=revocation_endpoint,
        )
    elif client_auth_method_handler == PrivateKeyJWT:
        private_key_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            endpoint=revocation_endpoint,
            public_jwk=public_jwk,
        )


def test_revoke_token_error_non_standard(
    requests_mock,
    token_endpoint,
    revocation_endpoint,
    client_auth_method,
    refresh_token,
):
    """.revoke_token() sends a Revocation request to the Revocation Endpoint, with token_type_hint=access_token."""
    client = OAuth2Client(
        token_endpoint, revocation_endpoint=revocation_endpoint, auth=client_auth_method
    )
    requests_mock.post(revocation_endpoint, status_code=400, text="Error")

    assert client.revoke_token(refresh_token) is False
    assert requests_mock.called_once

    requests_mock.reset_mock()
    requests_mock.post(revocation_endpoint, status_code=400, json={"foo": "bar"})
    assert client.revoke_token(refresh_token) is False
    assert requests_mock.called_once


def test_revoke_token_no_revocation_endpoint(token_endpoint, client_id):
    """Revocation methods return False if no revocation_endpoint is configured."""
    client = OAuth2Client(token_endpoint, revocation_endpoint=None, auth=client_id)

    assert client.revoke_access_token("foo") is False
    assert client.revoke_refresh_token("foo") is False
    assert client.revoke_token("foo") is False


def test_server_jwks(requests_mock, oauth2client, jwks_uri, server_public_jwks):
    """get_public_jwks() fetches the AS public JWKS from its JWKS URI"""
    requests_mock.get(jwks_uri, json=server_public_jwks)
    assert oauth2client.get_public_jwks() == server_public_jwks
    assert requests_mock.called_once


def test_server_jwks_no_jwks_uri(token_endpoint):
    """If JWKS URI is not known, get_public_jwks() raises an exception."""
    client = OAuth2Client(token_endpoint=token_endpoint, auth=("foo", "bar"))
    with pytest.raises(ValueError):
        assert client.get_public_jwks()


def test_server_jwks_not_json(requests_mock, token_endpoint, jwks_uri):
    """If JWKS URI is not known, get_public_jwks() raises an exception."""
    requests_mock.get(jwks_uri, text="Hello World!")
    client = OAuth2Client(
        token_endpoint=token_endpoint, jwks_uri=jwks_uri, auth=("foo", "bar")
    )
    with pytest.raises(ValueError):
        assert client.get_public_jwks()
    assert requests_mock.called_once


def test_server_jwks_invalid_doc(requests_mock, token_endpoint, jwks_uri):
    """If JWKS URI is not known, get_public_jwks() raises an exception."""
    requests_mock.get(jwks_uri, json={"foo": "bar"})
    client = OAuth2Client(
        token_endpoint=token_endpoint, jwks_uri=jwks_uri, auth=("foo", "bar")
    )
    with pytest.raises(ValueError):
        assert client.get_public_jwks()
    assert requests_mock.called_once


def test_get_token_type():
    assert (
        OAuth2Client.get_token_type(token_type="access_token")
        == "urn:ietf:params:oauth:token-type:access_token"
    )
    assert (
        OAuth2Client.get_token_type(token_type="refresh_token")
        == "urn:ietf:params:oauth:token-type:refresh_token"
    )
    assert (
        OAuth2Client.get_token_type(token_type="id_token")
        == "urn:ietf:params:oauth:token-type:id_token"
    )
    assert (
        OAuth2Client.get_token_type(token_type="saml2")
        == "urn:ietf:params:oauth:token-type:saml2"
    )

    with pytest.raises(ValueError):
        assert OAuth2Client.get_token_type(token="token")

    assert (
        OAuth2Client.get_token_type(token=BearerToken("access_token"))
        == "urn:ietf:params:oauth:token-type:access_token"
    )
    assert (
        OAuth2Client.get_token_type(
            token=BearerToken("access_token", refresh_token="refresh_token")
        )
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
        OAuth2Client.get_token_type(
            token=BearerToken("access_token"), token_type="refresh_token"
        )

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
        OAuth2Client.get_token_type(token=1.33)

    with pytest.raises(TypeError):
        OAuth2Client.get_token_type(token=1.33, token_type="access_token")

    with pytest.raises(TypeError):
        OAuth2Client.get_token_type(token=1.33, token_type="id_token")


def test_introspection(
    requests_mock,
    oauth2client,
    introspection_endpoint,
    introspection_request_validator,
    client_auth_method_handler,
    public_app_auth_validator,
    client_id,
    client_secret_post_auth_validator,
    client_credential,
    client_secret_basic_auth_validator,
    client_secret_jwt_auth_validator,
    private_key_jwt_auth_validator,
    public_jwk,
):
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
    elif client_auth_method_handler == ClientSecretJWT:
        client_secret_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            client_secret=client_credential,
            endpoint=introspection_endpoint,
        )
    elif client_auth_method_handler == PrivateKeyJWT:
        private_key_jwt_auth_validator(
            requests_mock.last_request,
            client_id=client_id,
            endpoint=introspection_endpoint,
            public_jwk=public_jwk,
        )


def test_introspection_no_introspection_endpoint(
    token_endpoint,
    client_id,
    client_secret,
):
    client = OAuth2Client(token_endpoint, auth=(client_id, client_secret))

    with pytest.raises(AttributeError):
        client.introspect_token("foo")


def test_introspection_error(
    requests_mock,
    oauth2client,
    introspection_endpoint,
    introspection_request_validator,
):
    requests_mock.post(
        introspection_endpoint, status_code=400, json={"error": "unauthorized_client"}
    )
    with pytest.raises(UnauthorizedClient):
        oauth2client.introspect_token("access_token")

    assert requests_mock.called_once
    introspection_request_validator(requests_mock.last_request, token="access_token")


def test_introspection_jwt(
    requests_mock,
    oauth2client,
    introspection_endpoint,
    introspection_request_validator,
):
    introspection = "This.ShouldBe.aJWT"
    requests_mock.post(introspection_endpoint, text=introspection)
    assert oauth2client.introspect_token("access_token") == introspection

    assert requests_mock.called_once
    introspection_request_validator(requests_mock.last_request, token="access_token")


def test_introspection_unknown_error(
    requests_mock,
    oauth2client,
    introspection_endpoint,
    introspection_request_validator,
):
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
    requests_mock,
    oauth2client,
    introspection_endpoint,
    access_token,
    refresh_token,
    introspection_request_validator,
):
    requests_mock.post(introspection_endpoint, status_code=200, json={"active": False})
    bearer = BearerToken(access_token, refresh_token=refresh_token)
    assert oauth2client.introspect_token(bearer, "refresh_token")

    assert requests_mock.called_once
    introspection_request_validator(
        requests_mock.last_request, token=refresh_token, type_hint="refresh_token"
    )

    bearer_no_refresh = BearerToken(access_token, refresh_token=None)
    with pytest.raises(ValueError):
        oauth2client.introspect_token(bearer_no_refresh, "refresh_token")


def test_ciba(
    requests_mock,
    oauth2client,
    auth_req_id,
    token_endpoint,
    access_token,
    ciba_request_validator,
):
    requests_mock.post(
        token_endpoint, json={"access_token": access_token, "expires_in": 60}
    )
    token = oauth2client.ciba(auth_req_id=auth_req_id)
    assert isinstance(token, BearerToken)
    assert requests_mock.called_once
    ciba_request_validator(requests_mock.last_request, auth_req_id=auth_req_id)
