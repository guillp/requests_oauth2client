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
        from flask import Flask, request

        from requests_oauth2client.flask import FlaskOAuth2ClientCredentialsAuth
    except ImportError:
        pytest.skip("Flask is not available")

    oauth_client = OAuth2Client(token_endpoint, ClientSecretPost(client_id, client_secret))
    auth = FlaskOAuth2ClientCredentialsAuth(
        session_key=session_key,
        scope=scope,
        client=oauth_client,
    )
    api_client = ApiClient(target_api, auth=auth)

    assert isinstance(api_client.auth, FlaskOAuth2ClientCredentialsAuth)

    app = Flask("testapp")
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "thisissecret"

    @app.route("/api")
    def get() -> Any:
        return api_client.get(params=request.args).json()

    access_token = "access_token"
    json_resp = {"status": "success"}
    requests_mock.post(
        token_endpoint,
        json={"access_token": access_token, "token_type": "Bearer", "expires_in": 3600},
    )
    requests_mock.get(target_api, json=json_resp)

    with app.test_client() as client:
        resp = client.get("/api?call=1")
        assert resp.json == json_resp
        resp = client.get("/api?call=2")
        assert resp.json == json_resp
        api_client.auth.forget_token()
        # assert api_client.session.auth.token is None
        with client.session_transaction() as sess:
            sess.pop(auth.session_key)
        # this should trigger a new token request then the API request
        resp = client.get("/api?call=3")
        assert resp.json == json_resp

    token_request1 = requests_mock.request_history[0]
    assert token_request1.url == token_endpoint
    token_params = parse_qs(token_request1.text)
    assert token_params.get("client_id") == [client_id]
    if not scope:
        assert token_params.get("scope") is None
    elif isinstance(scope, str):
        assert token_params.get("scope") == [scope]
    elif isinstance(scope, Iterable):
        assert token_params.get("scope") == [" ".join(scope)]
    assert token_params.get("client_secret") == [client_secret]

    api_request1 = requests_mock.request_history[1]
    assert api_request1.url == "https://myapi.local/root/?call=1"
    assert api_request1.headers.get("Authorization") == f"Bearer {access_token}"

    api_request2 = requests_mock.request_history[2]
    assert api_request2.url == "https://myapi.local/root/?call=2"
    assert api_request2.headers.get("Authorization") == f"Bearer {access_token}"

    token_request2 = requests_mock.request_history[3]
    assert token_request2.url == token_endpoint
    token_params = parse_qs(token_request2.text)
    assert token_params.get("client_id") == [client_id]
    if not scope:
        assert token_params.get("scope") is None
    elif isinstance(scope, str):
        assert token_params.get("scope") == [scope]
    elif isinstance(scope, Iterable):
        assert token_params.get("scope") == [" ".join(scope)]
    assert token_params.get("client_secret") == [client_secret]

    api_request3 = requests_mock.request_history[4]
    assert api_request3.url == "https://myapi.local/root/?call=3"
    assert api_request3.headers.get("Authorization") == f"Bearer {access_token}"


def test_flask_token_kwarg() -> None:
    try:
        from flask import Flask

        from requests_oauth2client.flask import FlaskOAuth2ClientCredentialsAuth
    except ImportError:
        pytest.skip("Flask is not available")

    app = Flask("testapp")
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "thisissecret"

    with app.test_request_context("/"):
        auth = FlaskOAuth2ClientCredentialsAuth(
            client=None,
            session_key=session_key,
            token="xyz",
        )
        assert auth.token
        assert auth.token.access_token == "xyz"
