from furl import furl

from requests_oauth2client import AuthorizationRequest


def test_authorization_request():
    authorization_endpoint = "https://myas.local/authorize"
    client_id = "myclientid"
    redirect_uri = "http://127.0.0.1/"
    scope = "openid"
    response_type = "code"
    state = "mystate"
    nonce = "mynonce"
    code_verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMOPQRSTUVWXYZ1234567890"
    code_challenge_method = "S256"
    kwargs = {"foo": "bar"}

    azr = AuthorizationRequest(
        authorization_endpoint=authorization_endpoint,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        response_type=response_type,
        state=state,
        nonce=nonce,
        code_verifier=code_verifier,
        code_challenge_method=code_challenge_method,
        **kwargs,
    )

    url = furl(str(azr))
    assert url.origin + str(url.path) == authorization_endpoint
    assert url.args == dict(
        client_id=client_id,
        redirect_uri=redirect_uri,
        response_type=response_type,
        state=state,
        nonce=nonce,
        scope=scope,
        code_challenge="FYKCx6MubiaOxWp8-ciyDkkkOapyAjR9sxikqOSXLdw",
        code_challenge_method=code_challenge_method,
        **kwargs,
    )


def test_authorization_request_no_nonce():
    authorization_endpoint = "https://myas.local/authorize"
    client_id = "myclientid"
    redirect_uri = "http://127.0.0.1/"
    scope = "openid"
    response_type = "code"
    state = "mystate"
    nonce = False
    code_verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMOPQRSTUVWXYZ1234567890"
    code_challenge_method = "S256"
    kwargs = {"foo": "bar"}

    azr = AuthorizationRequest(
        authorization_endpoint=authorization_endpoint,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        response_type=response_type,
        state=state,
        nonce=nonce,
        code_verifier=code_verifier,
        code_challenge_method=code_challenge_method,
        **kwargs,
    )

    url = furl(str(azr))
    assert url.origin + str(url.path) == authorization_endpoint
    assert url.args == dict(
        client_id=client_id,
        redirect_uri=redirect_uri,
        response_type=response_type,
        state=state,
        scope=scope,
        code_challenge="FYKCx6MubiaOxWp8-ciyDkkkOapyAjR9sxikqOSXLdw",
        code_challenge_method=code_challenge_method,
        **kwargs,
    )


def test_authorization_request_scope_list():
    authorization_endpoint = "https://myas.local/authorize"
    client_id = "myclientid"
    redirect_uri = "http://127.0.0.1/"
    scope = ["openid", "email", "profile"]
    response_type = "code"
    state = "mystate"
    nonce = "mynonce"
    code_verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMOPQRSTUVWXYZ1234567890"
    code_challenge_method = "S256"
    kwargs = {"foo": "bar"}

    azr = AuthorizationRequest(
        authorization_endpoint=authorization_endpoint,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        response_type=response_type,
        state=state,
        nonce=nonce,
        code_verifier=code_verifier,
        code_challenge_method=code_challenge_method,
        **kwargs,
    )

    url = furl(str(azr))
    assert url.origin + str(url.path) == authorization_endpoint
    assert url.args == dict(
        client_id=client_id,
        redirect_uri=redirect_uri,
        response_type=response_type,
        state=state,
        nonce=nonce,
        scope="+".join(scope),
        code_challenge="FYKCx6MubiaOxWp8-ciyDkkkOapyAjR9sxikqOSXLdw",
        code_challenge_method=code_challenge_method,
        **kwargs,
    )


def test_authorization_request_no_pkce():
    authorization_endpoint = "https://myas.local/authorize"
    client_id = "myclientid"
    redirect_uri = "http://127.0.0.1/"
    scope = "openid"
    response_type = "code"
    state = "mystate"
    nonce = "mynonce"
    kwargs = {"foo": "bar"}

    azr = AuthorizationRequest(
        authorization_endpoint=authorization_endpoint,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        response_type=response_type,
        state=state,
        nonce=nonce,
        code_challenge_method=None,
        **kwargs,
    )

    url = furl(str(azr))
    assert url.origin + str(url.path) == authorization_endpoint
    assert url.args == dict(
        client_id=client_id,
        redirect_uri=redirect_uri,
        response_type=response_type,
        state=state,
        nonce=nonce,
        scope=scope,
        **kwargs,
    )
