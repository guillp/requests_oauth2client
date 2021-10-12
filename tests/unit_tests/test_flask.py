from urllib.parse import parse_qs

import pytest

from requests_oauth2client import ApiClient, ClientSecretPost, OAuth2Client

token_endpoint = "https://myas.local/token"
client_id = "clientid"
client_secret = "clientsecret"
scope = "myscope"

session_key = "session_key"

external_api = "https://myapi.local/foo"


def test_flask(requests_mock):
    try:
        from flask import Flask

        from requests_oauth2client.flask import FlaskOAuth2ClientCredentialsAuth
    except ImportError:
        pytest.skip("Flask is not available")

    oauth_client = OAuth2Client(
        token_endpoint, ClientSecretPost(client_id, client_secret)
    )
    api_client = ApiClient(
        auth=FlaskOAuth2ClientCredentialsAuth(
            oauth_client, session_key=session_key, scope=scope
        )
    )

    app = Flask("testapp")
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "thisissecret"

    @app.route("/api")
    def get():
        return api_client.get(external_api).json()

    access_token = "access_token"
    json_resp = {"status": "success"}
    requests_mock.post(
        token_endpoint,
        json={"access_token": access_token, "token_type": "Bearer", "expires_in": 3600},
    )
    requests_mock.get(external_api, json=json_resp)

    with app.test_client() as client:
        resp = client.get("/api")
        assert resp.json == json_resp
        resp = client.get("/api")
        assert resp.json == json_resp
        api_client.auth.token = None  # strangely this has no effect in a test session
        with client.session_transaction() as sess:  # does what 'api_client.auth.token = None' should do
            sess.pop("session_key")
        resp = client.get("/api")
        assert resp.json == json_resp

    assert len(requests_mock.request_history) == 5
    token_request = requests_mock.request_history[0]
    api_request1 = requests_mock.request_history[1]
    api_request2 = requests_mock.request_history[2]

    token_params = parse_qs(token_request.text)
    assert token_params.get("client_id") == [client_id]
    assert token_params.get("scope") == [scope]
    assert token_params.get("client_secret") == [client_secret]

    assert api_request1.headers.get("Authorization") == f"Bearer {access_token}"
    assert api_request2.headers.get("Authorization") == f"Bearer {access_token}"
