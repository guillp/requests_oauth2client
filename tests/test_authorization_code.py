import base64
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import requests
from freezegun import freeze_time
from furl import Query, furl  # type: ignore[import-untyped]
from jwskate import Jwk
from requests_mock import Mocker

from requests_oauth2client import (
    AuthorizationRequest,
    BearerToken,
    ClientSecretPost,
    IdToken,
    OAuth2Client,
    oidc_discovery_document_url,
)


@freeze_time()
def test_authorization_code(
    session: requests.Session,
    requests_mock: Mocker,
    issuer: str,
    token_endpoint: str,
    authorization_endpoint: str,
    jwks_uri: str,
    discovery_document: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    scope: str,
    audience: str,
) -> None:
    id_token_sig_alg = "ES256"
    id_token_signing_key = Jwk.generate(alg=id_token_sig_alg).with_kid_thumbprint()

    requests_mock.get(issuer + "/.well-known/openid-configuration", json=discovery_document)
    requests_mock.get(jwks_uri, json={"keys": [id_token_signing_key.public_jwk().to_dict()]})
    client = OAuth2Client.from_discovery_endpoint(
        issuer=issuer,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
        id_token_signed_response_alg=id_token_sig_alg,
    )
    authorization_request = client.authorization_request(scope=scope, audience=audience)
    assert authorization_request.authorization_endpoint == authorization_endpoint
    assert authorization_request.client_id == client_id
    assert authorization_request.response_type == "code"
    assert authorization_request.redirect_uri == redirect_uri
    assert authorization_request.scope is not None
    assert " ".join(authorization_request.scope) == scope
    assert authorization_request.state is not None
    assert authorization_request.nonce is not None
    assert authorization_request.audience == audience
    assert authorization_request.code_challenge_method == "S256"
    assert authorization_request.code_challenge is not None

    authorization_code = secrets.token_urlsafe()
    state = authorization_request.state

    authorization_response = furl(redirect_uri, query={"code": authorization_code, "state": state}).url

    access_token = secrets.token_urlsafe()

    c_hash = IdToken.hash_method(id_token_signing_key)(authorization_code)
    at_hash = IdToken.hash_method(id_token_signing_key)(access_token)
    s_hash = IdToken.hash_method(id_token_signing_key)(state)

    id_token = IdToken.sign(
        {
            "iss": issuer,
            "sub": "248289761001",
            "aud": client_id,
            "nonce": authorization_request.nonce,
            "iat": IdToken.timestamp(),
            "exp": IdToken.timestamp(60),
            "c_hash": c_hash,
            "at_hash": at_hash,
            "s_hash": s_hash,
            "auth_time": IdToken.timestamp(),
        },
        key=id_token_signing_key,
    )
    code_verifier = authorization_request.code_verifier
    assert code_verifier is not None
    assert (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(b"=")
        == authorization_request.code_challenge.encode()
    )

    auth_response = authorization_request.validate_callback(authorization_response)

    requests_mock.post(
        token_endpoint,
        json={"access_token": access_token, "token_type": "Bearer", "expires_in": 3600, "id_token": str(id_token)},
    )
    token = client.authorization_code(code=auth_response)

    assert isinstance(token, BearerToken)
    assert token.access_token == access_token
    assert not token.is_expired()
    assert token.expires_at is not None
    assert token.expires_at == datetime.now(tz=timezone.utc).replace(microsecond=0) + timedelta(seconds=3600)

    assert requests_mock.last_request is not None
    params = Query(requests_mock.last_request.text).params
    assert params.get("client_id") == client_id
    assert params.get("client_secret") == client_secret
    assert params.get("grant_type") == "authorization_code"
    assert params.get("code") == authorization_code


@freeze_time()
def test_authorization_code_legacy(
    session: requests.Session,
    requests_mock: Mocker,
    issuer: str,
    discovery_document: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    scope: str,
    audience: str,
) -> None:
    discovery_url = oidc_discovery_document_url(issuer)
    requests_mock.get(discovery_url, json=discovery_document)
    discovery = session.get(discovery_url).json()
    authorization_endpoint = discovery.get("authorization_endpoint")
    assert authorization_endpoint
    token_endpoint = discovery.get("token_endpoint")
    assert token_endpoint

    authorization_request = AuthorizationRequest(
        authorization_endpoint,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        audience=audience,
    )

    authorization_code = secrets.token_urlsafe()

    state = authorization_request.state

    authorization_response = furl(redirect_uri, query={"code": authorization_code, "state": state}).url
    requests_mock.get(
        authorization_request.uri,
        status_code=302,
        headers={"Location": authorization_response},
    )
    resp = requests.get(authorization_request.uri, allow_redirects=False)
    assert resp.status_code == 302
    location = resp.headers.get("Location")
    assert location == authorization_response
    assert requests_mock.last_request is not None
    qs = Query(requests_mock.last_request.qs).params
    assert qs.get("client_id") == client_id
    assert qs.get("response_type") == "code"
    assert qs.get("redirect_uri") == redirect_uri
    assert qs.get("state") == state
    code_challenge = qs.get("code_challenge")
    assert code_challenge
    code_challenge_method = requests_mock.last_request.qs.get("code_challenge_method")
    code_verifier = authorization_request.code_verifier
    assert code_verifier is not None
    assert code_challenge_method == ["S256"]
    assert (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(b"=")
        == code_challenge.encode()
    )

    auth_response = authorization_request.validate_callback(location)

    client = OAuth2Client(token_endpoint, ClientSecretPost(client_id, client_secret))

    access_token = secrets.token_urlsafe()

    requests_mock.post(
        token_endpoint,
        json={"access_token": access_token, "token_type": "Bearer", "expires_in": 3600},
    )
    token = client.authorization_code(code=auth_response, redirect_uri=redirect_uri, validate=False)

    assert isinstance(token, BearerToken)
    assert token.access_token == access_token
    assert not token.is_expired()
    assert token.expires_at is not None
    assert token.expires_at == datetime.now(tz=timezone.utc).replace(microsecond=0) + timedelta(seconds=3600)

    assert requests_mock.last_request is not None
    params = Query(requests_mock.last_request.text).params
    assert params.get("client_id") == client_id
    assert params.get("client_secret") == client_secret
    assert params.get("grant_type") == "authorization_code"
    assert params.get("code") == authorization_code
