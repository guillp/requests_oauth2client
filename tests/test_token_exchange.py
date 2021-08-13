import secrets
from urllib.parse import parse_qs

from requests_oauth2client import BearerToken, ClientSecretPost, OAuth2Client

client_id = "TEST_CLIENT_ID"
client_secret = "TEST_CLIENT_SECRET"
token_endpoint = "https://test.com/token"


def test_token_exchange(requests_mock):
    access_token = secrets.token_urlsafe()

    client = OAuth2Client(token_endpoint, ClientSecretPost(client_id, client_secret))

    requests_mock.post(
        token_endpoint,
        json={
            "access_token": access_token,
            "token_type": "Bearer",
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "expires_in": 60,
        },
    )

    subject_token = "accVkjcJyb4BWCxGsndESCJQbdFMogUC5PbRDqceLTC"
    resource = "https://backend.example.com/api"
    token_response = client.token_exchange(
        subject_token=BearerToken(subject_token), resource=resource
    )

    assert token_response.access_token == access_token
    assert token_response.issued_token_type == "urn:ietf:params:oauth:token-type:access_token"
    assert token_response.token_type == "Bearer"
    assert token_response.expires_in == 60

    params = parse_qs(requests_mock.last_request.text)
    assert params.pop("client_id") == [client_id]
    assert params.pop("client_secret") == [client_secret]
    assert params.pop("grant_type") == ["urn:ietf:params:oauth:grant-type:token-exchange"]
    assert params.pop("subject_token") == [subject_token]
    assert params.pop("subject_token_type") == ["urn:ietf:params:oauth:token-type:access_token"]
    assert params.pop("resource") == [resource]
    assert not params
