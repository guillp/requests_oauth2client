import secrets
from urllib.parse import parse_qs

from requests_oauth2client import OAuth2Client
from requests_oauth2client.device_authorization import (DeviceAuthorizationClient,
                                                        DeviceAuthorizationPoolingJob)

client_id = "TEST_CLIENT_ID"
client_secret = "TEST_CLIENT_SECRET"
token_endpoint = "https://test.com/token"
device_authorization_endpoint = "http://localhost/device_authorization"
api = "https://test.com/api"


def test_device_authorization(requests_mock):
    device_code = secrets.token_urlsafe()
    user_code = secrets.token_urlsafe(6)
    verification_uri = "https://test.com/verify_device"

    def device_authorization_response_callback(request, context):
        params = parse_qs(request.text)
        assert params.get("client_id")[0] == client_id
        assert params.get("client_secret")[0] == client_secret

        return {
            "device_code": device_code,
            "user_code": user_code,
            "verification_uri": verification_uri,
            "expires_in": 3600,
        }

    requests_mock.post(
        device_authorization_endpoint, json=device_authorization_response_callback,
    )

    da_client = DeviceAuthorizationClient(
        device_authorization_endpoint=device_authorization_endpoint,
        auth=(client_id, client_secret),
    )

    device_auth_resp = da_client.authorize_device()
    assert device_auth_resp.device_code
    assert device_auth_resp.user_code
    assert device_auth_resp.verification_uri

    access_token = secrets.token_urlsafe()

    requests_mock.post(
        token_endpoint,
        [
            {"json": {"error": "authorization_pending"}, "status_code": 400},
            {"json": {"error": "slow_down"}, "status_code": 400},
            {
                "json": {
                    "access_token": access_token,
                    "token_type": "Bearer",
                    "expires_in": 3600,
                }
            },
        ],
    )

    client = OAuth2Client(token_endpoint, (client_id, client_secret))
    pool_job = DeviceAuthorizationPoolingJob(
        client, device_auth_resp.device_code, interval=device_auth_resp.interval
    )

    # 1st attempt: authorization_pending
    resp = pool_job()
    params = parse_qs(requests_mock.last_request.text)
    assert params.get("client_id")[0] == client_id
    assert params.get("client_secret")[0] == client_secret

    assert pool_job.interval == 5
    assert resp is None

    # 2nd attempt: slow down
    resp = pool_job()
    params = parse_qs(requests_mock.last_request.text)
    assert params.get("client_id")[0] == client_id
    assert params.get("client_secret")[0] == client_secret

    assert pool_job.interval == 10
    assert resp is None

    # 3rd attempt: access token delivered
    resp = pool_job()
    params = parse_qs(requests_mock.last_request.text)
    assert params.get("client_id")[0] == client_id
    assert params.get("client_secret")[0] == client_secret

    assert not resp.is_expired()
