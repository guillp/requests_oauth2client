import base64
import hashlib
from typing import Any, Dict, List, Optional, Type, Union

import pytest
import requests
from furl import furl  # type: ignore[import]
from jwskate import Jwk

from requests_oauth2client import (
    ApiClient,
    AuthorizationRequest,
    BearerAuth,
    ClientSecretBasic,
    ClientSecretJwt,
    ClientSecretPost,
    OAuth2Client,
    PrivateKeyJwt,
    PublicApp,
)
from requests_oauth2client.client_authentication import BaseClientAuthenticationMethod
from tests.conftest import FixtureRequest


@pytest.fixture(scope="session")
def session() -> requests.Session:
    return requests.Session()


def join_url(root: str, path: str) -> str:
    if path:
        f = furl(root).add(path=path)
        f.path.normalize()
        return str(f.url)
    else:
        return root


@pytest.fixture(scope="session")
def access_token() -> str:
    return "access_token"


@pytest.fixture(scope="session")
def bearer_auth(access_token: str) -> BearerAuth:
    return BearerAuth(access_token)


@pytest.fixture(scope="session")
def target_api() -> str:
    return "https://myapi.local/root/"


@pytest.fixture(scope="session")
def api(target_api: str, bearer_auth: BearerAuth) -> ApiClient:
    return ApiClient(target_api, auth=bearer_auth)


@pytest.fixture(scope="session")
def issuer() -> str:
    return "https://test.com"


@pytest.fixture(scope="session")
def token_endpoint(issuer: str) -> str:
    return join_url(issuer, "oauth/token")


@pytest.fixture(scope="session")
def authorization_endpoint(issuer: str) -> str:
    return join_url(issuer, "login/authorize")


@pytest.fixture(scope="session")
def revocation_endpoint(issuer: str) -> str:
    return join_url(issuer, "oauth/revoke")


@pytest.fixture(scope="session")
def introspection_endpoint(issuer: str) -> str:
    return join_url(issuer, "oauth/introspect")


@pytest.fixture(scope="session")
def userinfo_endpoint(issuer: str) -> str:
    return join_url(issuer, "oidc/userinfo")


@pytest.fixture(scope="session")
def jwks_uri(issuer: str) -> str:
    return join_url(issuer, "jwks")


@pytest.fixture(scope="session")
def device_authorization_endpoint(issuer: str) -> str:
    return join_url(issuer, "device")


@pytest.fixture(scope="session")
def backchannel_authentication_endpoint(issuer: str) -> str:
    return join_url(issuer, "bc_authorize")


@pytest.fixture(scope="session")
def pushed_authorization_request_endpoint(issuer: str) -> str:
    return join_url(issuer, "par")


@pytest.fixture(scope="session")
def client_id() -> str:
    return "client_id"


@pytest.fixture(
    scope="session",
    params=[PublicApp, ClientSecretPost, ClientSecretBasic, ClientSecretJwt],
)
def client_auth_method_handler(
    request: pytest.FixtureRequest,
) -> Type[BaseClientAuthenticationMethod]:
    return request.param  # type: ignore[attr-defined,no-any-return]


@pytest.fixture(scope="session")
def kid() -> str:
    return "JWK-ABCD"


@pytest.fixture(scope="session")
def private_jwk(kid: str) -> Jwk:
    return Jwk(
        {
            "kty": "RSA",
            "kid": kid,
            "alg": "RS256",
            "n": "2jgK-5aws3_fjllgnAacPkwjbz3RCeAHni1pcHvReuTgk9qEiTmXWJiSS_F20VeI1zEwFM36e836ROCyOQ8cjjaPWpdzCajWC0koY7X8MPhZbdoSptOmDBseRCyYqmeMCp8mTTOD6Cs43SiIYSMNlPuio89qjf_4u32eVF_5YqOGtwfzC4p2NUPPCxpljYpAcf2BBG1tRX1mY4WP_8zwmx3ZH7Sy0V_fXI46tzDqfRXdMhHW7ARJAnEr_EJhlMgUaM7FUQKUNpi1ZdeeLxYv44eRx9-Roy5zTG1b0yRuaKaAG3559572quOcxISZzK5Iy7BhE7zxVa9jabEl-Y1Daw",
            "e": "AQAB",
            "d": "XCtpsCRQ1DBBm51yqdQ88C82lEjW30Xp0cy6iVEzBKZhmPGmI1PY8gnXWQ5PMlK3sLTM6yypDNvORoNlo6YXWJYA7LGlXEIczj2DOsJmF8T9-OEwGZixvNFDcmYnwWnlA6N_CQKmR0ziQr9ZAzZMCU5Tvr7f8cRZKdAALQEwk5FYpLnEbXOBduJtY9x2kddJSCJwRaEJhx0fG_pJAO3yLUZBY20dZK8UrxDoCgB9eiZV3N4uWGt367r1MDdaxGY6l6bC1HZCHkttBuTxfSUMCgooZevdU6ThQNpFrwZNY3KoP-OksEdqMs-neecfk_AQREkubDW2VPNFnaVEa38BKQ",
            "p": "8QNZGwUINpkuZi8l2ZfQzKVeOeNe3aQ7UW0wperM-63DFEJDRO1UyNC1n6yeo8_RxPZKSTlr6xZDoilQq23mopeF6O0ZmYz6E2VWJuma65V-A7tB-6xjqUXPlSkCNA6Ia8kMeCmNpKs0r0ijTBf_2y2GSsNH4EcP7XzcDEeJIh0",
            "q": "58nWgg-qRorRddwKM7qhLxJnEDsnCiYhbKJrP78OfBZ-839bNRvL5D5sfjJqxcKMQidgpYZVvVNL8oDEywcC5T7kKW0HK1JUdYiX9DuI40Mv9WzXQ8B8FBjp5wV4IX6_0KgyIiyoUiKpVHBvO0YFPUYuk0Ns4H9yEws93RWwhSc",
            "dp": "zFsLZcaphSnzVr9pd4urhqo9MBZjbMmBZnSQCE8ECe729ymMQlh-SFv3dHF4feuLsVcn-9iNceMJ6-jeNs1T_s89wxevWixYKrQFDa-MJW83T1CrDQvJ4VCJR69i5-Let43cXdLWACcO4AVWOQIsdpquQJw-SKPYlIUHS_4n_90",
            "dq": "fP79rNnhy3TlDBgDcG3-qjHUXo5nuTNi5wCXsaLInuZKw-k0OGmrBIUdYNizd744gRxXJCxTZGvdEwOaHJrFVvcZd7WSHiyh21g0CcNpSJVc8Y8mbyUIRJZC3RC3_egqbM2na4KFqvWCN0UC1wYloSuNxmCgAFj6HYb8b5NYxBU",
            "qi": "hxXfLYgwrfZBvZ27nrPsm6mLuoO-V2rKdOj3-YDJzf0gnVGBLl0DZbgydZ8WZmSLn2290mO_J8XY-Ss8PjLYbz3JXPDNLMJ-da3iEPKTvh6OfliM_dBxhaW8sq5afLMUR0H8NeabbWkfPz5h0W11CCBYxsyPC6CzniFYCYXfByU",
        }
    )


@pytest.fixture(scope="session")
def public_jwk(private_jwk: Jwk) -> Jwk:
    return private_jwk.public_jwk()


@pytest.fixture(scope="session")
def client_secret() -> str:
    return "client_secret"


@pytest.fixture(scope="session")
def client_credential(
    client_auth_method_handler: Union[
        Type[PublicApp],
        Type[ClientSecretPost],
        Type[ClientSecretBasic],
        Type[ClientSecretJwt],
        Type[PrivateKeyJwt],
    ],
    client_secret: str,
    private_jwk: Jwk,
) -> Union[None, str, Jwk]:
    if client_auth_method_handler == PublicApp:
        return None
    elif client_auth_method_handler in (
        ClientSecretPost,
        ClientSecretBasic,
        ClientSecretJwt,
    ):
        return client_secret
    elif client_auth_method_handler == PrivateKeyJwt:
        return private_jwk
    assert False


@pytest.fixture(scope="session")
def client_auth_method(
    client_auth_method_handler: Union[
        Type[PublicApp],
        Type[ClientSecretPost],
        Type[ClientSecretBasic],
        Type[ClientSecretJwt],
        Type[PrivateKeyJwt],
    ],
    client_id: str,
    client_credential: Union[None, str, Jwk],
) -> BaseClientAuthenticationMethod:
    if client_auth_method_handler == PublicApp:
        return client_auth_method_handler(client_id)  # type: ignore[call-arg]
    return client_auth_method_handler(client_id, client_credential)  # type: ignore[arg-type,call-arg]


@pytest.fixture(scope="session")
def target_path() -> str:
    return "/resource"


@pytest.fixture(scope="session")
def target_uri(target_api: str, target_path: str) -> str:
    return join_url(target_api, target_path)


@pytest.fixture(scope="session")
def refresh_token() -> str:
    return "refresh_token"


@pytest.fixture(scope="session")
def authorization_code() -> str:
    return "authorization_code"


@pytest.fixture(scope="session")
def device_code() -> str:
    return "device_code"


@pytest.fixture(scope="session")
def user_code() -> str:
    return "user_code"


@pytest.fixture(scope="session")
def redirect_uri() -> str:
    return "http://localhost:12345/callback"


@pytest.fixture(scope="session")
def verification_uri(issuer: str) -> str:
    return join_url(issuer, "verification")


@pytest.fixture(scope="session")
def verification_uri_complete(verification_uri: str, user_code: str) -> str:
    return verification_uri + "?user_code=" + user_code


@pytest.fixture(scope="session")
def audience() -> str:
    return "https://myapi.com/path"


@pytest.fixture(scope="session")
def auth_req_id() -> str:
    return "auth_request_id"


@pytest.fixture(scope="session")
def discovery_document(
    issuer: str,
    token_endpoint: str,
    authorization_endpoint: str,
    revocation_endpoint: str,
    introspection_endpoint: str,
    userinfo_endpoint: str,
    jwks_uri: str,
) -> Dict[str, str]:
    return {
        "issuer": issuer,
        "authorization_endpoint": authorization_endpoint,
        "token_endpoint": token_endpoint,
        "userinfo_endpoint": userinfo_endpoint,
        "revocation_endpoint": revocation_endpoint,
        "introspection_endpoint": introspection_endpoint,
        "jwks_uri": jwks_uri,
    }


@pytest.fixture(scope="session")
def oauth2client(
    token_endpoint: str,
    revocation_endpoint: str,
    introspection_endpoint: str,
    userinfo_endpoint: str,
    pushed_authorization_request_endpoint: str,
    jwks_uri: str,
    client_auth_method: BaseClientAuthenticationMethod,
) -> OAuth2Client:
    return OAuth2Client(
        token_endpoint,
        revocation_endpoint=revocation_endpoint,
        introspection_endpoint=introspection_endpoint,
        userinfo_endpoint=userinfo_endpoint,
        pushed_authorization_request_endpoint=pushed_authorization_request_endpoint,
        jwks_uri=jwks_uri,
        auth=client_auth_method,
    )


@pytest.fixture(scope="session")
def sub() -> str:
    return "abcdefghijklmnopqrstuvwxyz"


@pytest.fixture(
    scope="session",
    params=[None, "state", True],
)
def state(request: FixtureRequest) -> Union[None, bool, str]:
    return request.param


@pytest.fixture(scope="session", params=[None, "https://myas.local", False])
def expected_issuer(request: FixtureRequest) -> Optional[str]:
    return request.param


@pytest.fixture(scope="session", params=[None, {"foo": "bar"}])
def auth_request_kwargs(request: FixtureRequest) -> Dict[str, Any]:
    return request.param or {}  # type: ignore[return-value]


@pytest.fixture(
    scope="session",
    params=[None, "nonce", False],
)
def nonce(request: FixtureRequest) -> Union[None, bool, str]:
    return request.param


@pytest.fixture(
    scope="session",
    params=[None, "openid", "openid profile email", ["openid", "profile", "email"], []],
    ids=["None", "single", "space-separated", "list", "empty-list"],
)
def scope(request: FixtureRequest) -> Union[None, str, List[str]]:
    return request.param


@pytest.fixture(
    scope="session",
    params=[None, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"],
    ids=["None", "rfc7636"],
)
def code_verifier(request: FixtureRequest) -> Optional[str]:
    return request.param


@pytest.fixture(scope="session", params=[None, "plain", "S256"])
def code_challenge_method(request: FixtureRequest) -> Optional[str]:
    return request.param


@pytest.fixture(scope="session")
@pytest.mark.slow
def authorization_request(
    authorization_endpoint: str,
    client_id: str,
    redirect_uri: str,
    scope: Union[None, str, List[str]],
    state: Union[None, bool, str],
    nonce: Union[None, bool, str],
    code_verifier: str,
    code_challenge_method: str,
    expected_issuer: Union[str, bool, None],
    auth_request_kwargs: Dict[str, Any],
) -> AuthorizationRequest:
    azr = AuthorizationRequest(
        authorization_endpoint=authorization_endpoint,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        state=state,
        nonce=nonce,
        code_verifier=code_verifier,
        code_challenge_method=code_challenge_method,
        issuer=expected_issuer,
        **auth_request_kwargs,
    )

    url = furl(str(azr))
    assert url.origin + str(url.path) == authorization_endpoint

    assert azr.authorization_endpoint == authorization_endpoint
    assert azr.client_id == client_id
    assert azr.redirect_uri == redirect_uri
    assert azr.issuer == expected_issuer
    assert azr.kwargs == auth_request_kwargs

    args = dict(url.args)
    expected_args = dict(
        client_id=client_id,
        redirect_uri=redirect_uri,
        response_type="code",
        scope=scope,
        **auth_request_kwargs,
    )

    if nonce is True:
        generated_nonce = args.pop("nonce")
        assert isinstance(generated_nonce, str)
        assert len(generated_nonce) > 20
        assert azr.nonce == generated_nonce
    elif nonce is False or nonce is None:
        assert azr.nonce is None
        assert "nonce" not in args
    elif isinstance(nonce, str):
        assert azr.nonce == nonce
        assert args.pop("nonce") == nonce
    else:
        assert False

    if state is True:
        generated_state = args.pop("state")
        assert isinstance(generated_state, str)
        assert len(generated_state) > 20
        assert azr.state == generated_state
    elif state is False:
        assert "state" not in args
        assert azr.state is None
    elif isinstance(state, str):
        assert args.pop("state") == state
        assert azr.state == state

    if scope is None:
        assert azr.scope is None
        assert "scope" not in args
        del expected_args["scope"]
    elif isinstance(scope, list):
        joined_scope = " ".join(scope)
        expected_args["scope"] = joined_scope
        assert azr.scope == joined_scope
    if isinstance(scope, str):
        expected_args["scope"] = scope
        assert azr.scope == scope

    if code_challenge_method is None:
        assert "code_challenge_method" not in args
        assert "code_challenge" not in args
        assert azr.code_challenge_method is None
        assert azr.code_verifier is None
        assert azr.code_challenge is None
    elif code_challenge_method == "S256":
        assert azr.code_challenge_method == "S256"
        assert args.pop("code_challenge_method") == "S256"
        generated_code_challenge = args.pop("code_challenge")
        assert azr.code_challenge == generated_code_challenge
        if code_verifier is None:
            assert isinstance(generated_code_challenge, str)
            assert len(generated_code_challenge) == 43
            assert base64.urlsafe_b64decode(
                generated_code_challenge.encode() + b"="
            ), f"Invalid B64U for generated code_challenge: {generated_code_challenge}"
        else:
            assert azr.code_verifier == code_verifier
            assert generated_code_challenge == base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode()).digest()
            ).decode().rstrip("=")
    elif code_challenge_method == "plain":
        assert azr.code_challenge_method == "plain"
        assert args.pop("code_challenge_method") == "plain"
        generated_code_challenge = args.pop("code_challenge")
        assert azr.code_challenge == generated_code_challenge
        if code_verifier is None:
            assert isinstance(generated_code_challenge, str)
            assert 43 <= len(generated_code_challenge) <= 128
        else:
            assert generated_code_challenge == code_verifier
            assert azr.code_verifier == code_verifier

    assert args == expected_args

    return azr
