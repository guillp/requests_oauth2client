import secrets

from requests_oauth2client import OAuth2Client

from .conftest import RequestsMocker, RequestValidatorType


def test_refresh_token(
    requests_mock: RequestsMocker,
    token_endpoint: str,
    revocation_endpoint: str,
    refresh_token: str,
    client_secret_post_auth_validator: RequestValidatorType,
    client_id: str,
    client_secret: str,
    refresh_token_grant_validator: RequestValidatorType,
    revocation_request_validator: RequestValidatorType,
) -> None:
    client = OAuth2Client(
        token_endpoint,
        revocation_endpoint=revocation_endpoint,
        auth=(client_id, client_secret),
    )

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
    token_resp = client.refresh_token(refresh_token)
    assert not token_resp.is_expired()
    assert token_resp.access_token == new_access_token
    assert token_resp.refresh_token == new_refresh_token

    refresh_token_grant_validator(requests_mock.last_request, refresh_token=refresh_token)
    client_secret_post_auth_validator(
        requests_mock.last_request, client_id=client_id, client_secret=client_secret
    )

    requests_mock.post(revocation_endpoint)

    assert client.revoke_access_token(token_resp.access_token) is True

    revocation_request_validator(requests_mock.last_request, new_access_token, "access_token")
    client_secret_post_auth_validator(
        requests_mock.last_request, client_id=client_id, client_secret=client_secret
    )

    assert client.revoke_refresh_token(token_resp.refresh_token) is True

    revocation_request_validator(requests_mock.last_request, new_refresh_token, "refresh_token")
    client_secret_post_auth_validator(
        requests_mock.last_request, client_id=client_id, client_secret=client_secret
    )
