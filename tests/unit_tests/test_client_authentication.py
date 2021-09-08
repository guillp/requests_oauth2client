import pytest
import requests
from requests_mock import ANY

from requests_oauth2client import (
    ClientSecretBasic,
    ClientSecretJWT,
    ClientSecretPost,
    OAuth2Client,
    PrivateKeyJWT,
)


def test_client_secret_post(
    requests_mock,
    access_token,
    token_endpoint,
    client_id,
    client_secret,
    client_secret_post_auth_validator,
):
    client = OAuth2Client(token_endpoint, ClientSecretPost(client_id, client_secret))

    requests_mock.post(
        token_endpoint,
        json={"access_token": access_token, "token_type": "Bearer", "expires_in": 3600},
    )

    assert client.client_credentials()
    assert requests_mock.called_once
    client_secret_post_auth_validator(
        requests_mock.last_request, client_id=client_id, client_secret=client_secret
    )


def test_client_secret_basic(
    requests_mock,
    access_token,
    token_endpoint,
    client_id,
    client_secret,
    client_secret_basic_auth_validator,
):

    client = OAuth2Client(token_endpoint, ClientSecretBasic(client_id, client_secret))

    requests_mock.post(
        token_endpoint,
        json={"access_token": access_token, "token_type": "Bearer", "expires_in": 3600},
    )

    assert client.client_credentials()
    assert requests_mock.called_once
    client_secret_basic_auth_validator(
        requests_mock.last_request, client_id=client_id, client_secret=client_secret
    )


def test_private_key_jwt(
    requests_mock,
    access_token,
    token_endpoint,
    client_id,
    private_jwk,
    kid,
    private_key_jwt_auth_validator,
    public_jwk,
):

    client = OAuth2Client(
        token_endpoint, PrivateKeyJWT(client_id, private_jwk=private_jwk)
    )

    requests_mock.post(
        token_endpoint,
        json={"access_token": access_token, "token_type": "Bearer", "expires_in": 3600},
    )

    assert client.client_credentials()
    assert requests_mock.called_once
    private_key_jwt_auth_validator(
        requests_mock.last_request,
        client_id=client_id,
        public_jwk=public_jwk,
        endpoint=token_endpoint,
    )


def test_private_key_jwt_with_kid(
    requests_mock,
    access_token,
    token_endpoint,
    client_id,
    private_jwk,
    private_key_jwt_auth_validator,
    public_jwk,
):
    client = OAuth2Client(
        token_endpoint, PrivateKeyJWT(client_id, private_jwk=private_jwk)
    )

    requests_mock.post(
        token_endpoint,
        json={"access_token": access_token, "token_type": "Bearer", "expires_in": 3600},
    )

    assert client.client_credentials()
    assert requests_mock.called_once
    private_key_jwt_auth_validator(
        requests_mock.last_request,
        client_id=client_id,
        public_jwk=public_jwk,
        endpoint=token_endpoint,
    )


def test_client_secret_jwt(
    requests_mock,
    access_token,
    token_endpoint,
    client_id,
    client_secret,
    client_secret_jwt_auth_validator,
):

    client = OAuth2Client(token_endpoint, ClientSecretJWT(client_id, client_secret))

    requests_mock.post(
        token_endpoint,
        json={"access_token": access_token, "token_type": "Bearer", "expires_in": 3600},
    )

    assert client.client_credentials()
    assert requests_mock.called_once
    client_secret_jwt_auth_validator(
        requests_mock.last_request,
        client_id=client_id,
        client_secret=client_secret,
        endpoint=token_endpoint,
    )


def test_public_client(
    requests_mock,
    access_token,
    token_endpoint,
    client_id,
    target_api,
    public_app_auth_validator,
):

    client = OAuth2Client(token_endpoint, client_id)

    requests_mock.post(
        token_endpoint,
        json={"access_token": access_token, "token_type": "Bearer", "expires_in": 3600},
    )

    assert client.client_credentials()
    assert requests_mock.called_once
    public_app_auth_validator(requests_mock.last_request, client_id=client_id)


def test_invalid_request(requests_mock, client_id, client_secret):
    requests_mock.get(ANY)
    with pytest.raises(RuntimeError):
        requests.get(
            "http://localhost", auth=ClientSecretBasic(client_id, client_secret)
        )


def test_private_key_jwt_missing_alg(client_id, private_jwk):
    private_jwk.pop("alg")
    with pytest.raises(ValueError):
        PrivateKeyJWT(client_id=client_id, private_jwk=private_jwk, alg=None)


def test_private_key_jwt_missing_kid(client_id, private_jwk):
    private_jwk.pop("kid")
    with pytest.raises(ValueError):
        PrivateKeyJWT(client_id=client_id, private_jwk=private_jwk)
