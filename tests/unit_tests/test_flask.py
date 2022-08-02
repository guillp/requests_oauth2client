from typing import Any, Iterable
from urllib.parse import parse_qs

import pytest

from requests_oauth2client import ApiClient, ClientSecretPost, OAuth2Client
from tests.conftest import RequestsMocker

session_key = "session_key"


def test_flask(
    requests_mock: RequestsMocker,
    token_endpoint: str,
    client_id: str,
    client_secret: str,
    scope: str,
    target_api: str,
) -> None:
    try:
        from flask import Flask

        from requests_oauth2client.flask import FlaskOAuth2ClientCredentialsAuth
    except ImportError:
        pytest.skip("Flask is not available")

    oauth_client = OAuth2Client(token_endpoint, ClientSecretPost(client_id, client_secret))
    api_client = ApiClient(
        auth=FlaskOAuth2ClientCredentialsAuth(
            oauth_client, session_key=session_key, scope=scope
        )
    )

    app = Flask("testapp")
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "thisissecret"

    @app.route("/api")
    def get() -> Any:
        return api_client.get(target_api).json()

    access_token = "access_token"
    json_resp = {"status": "success"}
    requests_mock.post(
        token_endpoint,
        json={"access_token": access_token, "token_type": "Bearer", "expires_in": 3600},
    )
    requests_mock.get(target_api, json=json_resp)

    with app.test_client() as client:
        resp = client.get("/api")
        assert resp.json == json_resp
        resp = client.get("/api")
        assert resp.json == json_resp
        # api_client.auth.token = None  # strangely this has no effect in a test session
        with client.session_transaction() as sess:  # does what 'api_client.auth.token = None' should do
            sess.pop("session_key", None)
        resp = client.get("/api")
        assert resp.json == json_resp

    assert len(requests_mock.request_history) == 5
    token_request = requests_mock.request_history[0]
    api_request1 = requests_mock.request_history[1]
    api_request2 = requests_mock.request_history[2]

    token_params = parse_qs(token_request.text)
    assert token_params.get("client_id") == [client_id]
    if not scope:
        assert token_params.get("scope") is None
    elif isinstance(scope, str):
        assert token_params.get("scope") == [scope]
    elif isinstance(scope, Iterable):
        assert token_params.get("scope") == [" ".join(scope)]
    assert token_params.get("client_secret") == [client_secret]

    assert api_request1.headers.get("Authorization") == f"Bearer {access_token}"
    assert api_request2.headers.get("Authorization") == f"Bearer {access_token}"
