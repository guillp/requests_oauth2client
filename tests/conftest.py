import base64
from datetime import datetime
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    Type,
    Union,
)
from urllib.parse import parse_qs

import pytest
import requests
import requests_mock
from furl import Query, furl  # type: ignore[import]
from jwskate import Jwk, JwkSet, SignedJwt, SymmetricJwk
from requests_mock import Mocker
from requests_mock.request import _RequestObjectProxy
from typing_extensions import Literal

from requests_oauth2client import (
    ApiClient,
    BaseClientAuthenticationMethod,
    BearerAuth,
    ClientSecretBasic,
    ClientSecretJwt,
    ClientSecretPost,
    PublicApp,
)

RequestValidatorType = Callable[..., None]

if TYPE_CHECKING:
    from pytest import FixtureRequest as __FixtureRequest

    class FixtureRequest(__FixtureRequest):
        param: str

    class RequestsMocker(Mocker):
        def reset_mock(self) -> None:
            ...

else:
    from pytest import FixtureRequest

    RequestsMocker = Mocker


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


@pytest.fixture(
    scope="session",
    params=["short_access_token", "extremely_long_access_token" * 256],
    ids=["short_access_token", "long_access_token"],
)
def access_token(request: FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="session")
def bearer_auth(access_token: str) -> BearerAuth:
    return BearerAuth(access_token)


@pytest.fixture(
    scope="session",
    params=[
        "http://localhost/",
        "https://myapi/",
        "https://myapi/root",
        "https://myapi.local/root/",
    ],
)
def target_api(request: FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="session")
def api(target_api: str, bearer_auth: BearerAuth) -> ApiClient:
    return ApiClient(target_api, auth=bearer_auth)


@pytest.fixture(scope="session")
def issuer() -> str:
    return "https://test.com"


@pytest.fixture(scope="session", params=["oauth/token"])
def token_endpoint(request: FixtureRequest, issuer: str) -> str:
    return join_url(issuer, request.param)


@pytest.fixture(scope="session", params=["login/authorize"])
def authorization_endpoint(request: FixtureRequest, issuer: str) -> str:
    return join_url(issuer, request.param)


@pytest.fixture(scope="session", params=["oauth/revoke"])
def revocation_endpoint(request: FixtureRequest, issuer: str) -> str:
    return join_url(issuer, request.param)


@pytest.fixture(scope="session", params=["oidc/userinfo"])
def userinfo_endpoint(request: FixtureRequest, issuer: str) -> str:
    return join_url(issuer, request.param)


@pytest.fixture(scope="session", params=["oidc/jwks", ".well-known/jwks.json"])
def jwks_uri(request: FixtureRequest, issuer: str) -> str:
    return join_url(issuer, request.param)


@pytest.fixture(scope="session", params=["oauth/par"])
def pushed_authorization_request_endpoint(request: FixtureRequest, issuer: str) -> str:
    return join_url(issuer, request.param)


@pytest.fixture(scope="session")
def client_id() -> str:
    return "client_id"


@pytest.fixture(scope="session")
def client_secret() -> str:
    return "client_secret"


@pytest.fixture(
    scope="session",
    params=[PublicApp, ClientSecretPost, ClientSecretBasic, ClientSecretJwt],
)
def client_auth_method_handler(
    request: FixtureRequest,
) -> Type[BaseClientAuthenticationMethod]:
    return request.param  # type: ignore[return-value]


@pytest.fixture(scope="session")
def client_auth_method(
    client_auth_method_handler: Union[
        Type[ClientSecretPost], Type[ClientSecretBasic], Type[ClientSecretJwt]
    ],
    client_id: str,
    client_secret: str,
) -> Union[ClientSecretPost, ClientSecretBasic, ClientSecretJwt]:
    return client_auth_method_handler(client_id, client_secret)


@pytest.fixture(scope="session")
def client_secret_post_auth_validator() -> RequestValidatorType:
    def validator(req: _RequestObjectProxy, *, client_id: str, client_secret: str) -> None:
        params = parse_qs(req.text)
        assert params.get("client_id") == [client_id]
        assert params.get("client_secret") == [client_secret]
        assert "Authorization" not in req.headers

    return validator


@pytest.fixture(scope="session")
def public_app_auth_validator() -> RequestValidatorType:
    def validator(req: _RequestObjectProxy, *, client_id: str) -> None:
        params = parse_qs(req.text)
        assert params.get("client_id") == [client_id]
        assert "client_secret" not in params

    return validator


@pytest.fixture(scope="session")
def client_secret_basic_auth_validator() -> RequestValidatorType:
    def validator(req: _RequestObjectProxy, *, client_id: str, client_secret: str) -> None:
        encoded_username_password = base64.b64encode(
            f"{client_id}:{client_secret}".encode("ascii")
        ).decode()
        assert req.headers.get("Authorization") == f"Basic {encoded_username_password}"
        assert "client_secret" not in req.text

    return validator


@pytest.fixture(scope="session")
def client_secret_jwt_auth_validator() -> RequestValidatorType:
    def validator(
        req: _RequestObjectProxy, *, client_id: str, client_secret: str, endpoint: str
    ) -> None:
        params = Query(req.text).params
        assert params.get("client_id") == client_id
        assert "client_assertion" in params
        client_assertion = params.get("client_assertion")
        jwk = SymmetricJwk.from_bytes(client_secret)
        jwt = SignedJwt(client_assertion)
        jwt.verify_signature(jwk, alg="HS256")
        claims = jwt.claims
        now = int(datetime.now().timestamp())
        assert now - 10 <= claims["iat"] <= now, "unexpected iat"
        assert now + 10 < claims["exp"] < now + 180, "unexpected exp"
        assert claims["iss"] == client_id
        assert claims["aud"] == endpoint
        assert "jti" in claims
        assert claims["sub"] == client_id

    return validator


@pytest.fixture(scope="session")
def private_key_jwt_auth_validator() -> RequestValidatorType:
    def validator(
        req: requests_mock.request._RequestObjectProxy,
        *,
        client_id: str,
        public_jwk: Jwk,
        endpoint: str,
    ) -> None:
        params = Query(req.text).params
        assert params.get("client_id") == client_id, "invalid client_id"
        client_assertion = params.get("client_assertion")
        assert client_assertion, "missing client_assertion"
        jwt = SignedJwt(client_assertion)
        jwt.verify_signature(public_jwk)
        claims = jwt.claims
        now = int(datetime.now().timestamp())
        assert now - 10 <= claims["iat"] <= now, "Unexpected iat"
        assert now + 10 < claims["exp"] < now + 180, "unexpected exp"
        assert claims["iss"] == client_id
        assert claims["aud"] == endpoint
        assert "jti" in claims
        assert claims["sub"] == client_id

    return validator


@pytest.fixture(scope="session")
def client_credentials_grant_validator() -> RequestValidatorType:
    def validator(
        req: _RequestObjectProxy, *, scope: Optional[str] = None, **kwargs: Any
    ) -> None:
        params = Query(req.text).params
        assert params.get("grant_type") == "client_credentials"
        if scope is not None and not isinstance(scope, str):
            scope = " ".join(scope)

        assert params.get("scope") == scope
        for key, val in kwargs.items():
            assert params.get(key) == val

    return validator


@pytest.fixture(scope="session")
def authorization_code_grant_validator() -> RequestValidatorType:
    def validator(req: _RequestObjectProxy, *, code: str, **kwargs: Any) -> None:
        params = Query(req.text).params
        assert params.get("grant_type") == "authorization_code"
        for key, val in kwargs.items():
            assert params.get(key) == val

    return validator


@pytest.fixture(scope="session")
def refresh_token_grant_validator() -> RequestValidatorType:
    def validator(req: _RequestObjectProxy, *, refresh_token: str, **kwargs: Any) -> None:
        params = Query(req.text).params
        assert params.get("grant_type") == "refresh_token"
        assert params.get("refresh_token") == refresh_token
        for key, val in kwargs.items():
            assert params.get(key) == val

    return validator


@pytest.fixture(scope="session")
def device_code_grant_validator() -> RequestValidatorType:
    def validator(req: _RequestObjectProxy, device_code: str, **kwargs: Any) -> None:
        params = Query(req.text).params
        assert params.get("grant_type") == "urn:ietf:params:oauth:grant-type:device_code"
        assert params.get("device_code") == device_code
        for key, val in kwargs.items():
            assert params.get(key) == val

    return validator


@pytest.fixture(scope="session")
def token_exchange_grant_validator() -> RequestValidatorType:
    def validator(req: _RequestObjectProxy, subject_token: str, **kwargs: Any) -> None:
        params = Query(req.text).params
        assert params.get("grant_type") == "urn:ietf:params:oauth:grant-type:token-exchange"
        assert params.get("subject_token") == subject_token
        for key, val in kwargs.items():
            assert params.get(key) == val

    return validator


@pytest.fixture(scope="session")
def ciba_request_validator() -> RequestValidatorType:
    def validator(req: _RequestObjectProxy, *, auth_req_id: str, **kwargs: Any) -> None:
        params = Query(req.text).params
        assert params.get("grant_type") == "urn:openid:params:grant-type:ciba"
        assert params.get("auth_req_id") == auth_req_id
        for key, val in kwargs.items():
            assert params.get(key) == val

    return validator


@pytest.fixture(scope="session")
def backchannel_auth_request_validator() -> RequestValidatorType:
    def validator(
        req: _RequestObjectProxy, *, scope: Union[None, str, List[str]], **kwargs: Any
    ) -> None:
        params = Query(req.text).params
        if scope is None:
            assert "scope" not in params
        elif isinstance(scope, str):
            assert params.get("scope") == scope
        else:
            assert params.get("scope") == " ".join(scope)
        login_hint = params.get("login_hint")
        login_hint_token = params.get("login_hint_token")
        id_token_hint = params.get("id_token_hint")
        assert login_hint or login_hint_token or id_token_hint
        assert (
            not (login_hint and login_hint_token)
            and not (login_hint and id_token_hint)
            and not (login_hint_token and id_token_hint)
        )
        for key, val in kwargs.items():
            assert params.get(key) == val

    return validator


@pytest.fixture(scope="session")
def backchannel_auth_request_jwt_validator() -> RequestValidatorType:
    def validator(
        req: _RequestObjectProxy,
        *,
        public_jwk: Jwk,
        alg: str,
        scope: str,
        **kwargs: Any,
    ) -> None:
        params = Query(req.text).params
        request = params.get("request")
        jwt = SignedJwt(request)
        jwt.verify_signature(public_jwk, alg)
        claims = jwt.claims
        if isinstance(scope, str):
            assert claims.get("scope") == scope
        elif scope is None:
            assert claims.get("scope") is None
        elif isinstance(scope, Iterable):
            assert claims.get("scope") == " ".join(scope)
        else:
            assert False, f"unexpected scope type {type(scope)}"
        login_hint = claims.get("login_hint")
        login_hint_token = claims.get("login_hint_token")
        id_token_hint = claims.get("id_token_hint")
        assert login_hint or login_hint_token or id_token_hint
        assert (
            not (login_hint and login_hint_token)
            and not (login_hint and id_token_hint)
            and not (login_hint_token and id_token_hint)
        )
        for key, val in kwargs.items():
            assert claims.get(key) == val

    return validator


@pytest.fixture(scope="session")
def revocation_request_validator() -> RequestValidatorType:
    def validator(
        req: _RequestObjectProxy,
        token: str,
        type_hint: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        params = Query(req.text).params
        assert params.get("token") == token
        if type_hint is not None:
            assert params.get("token_type_hint") == type_hint
        for key, val in kwargs.items():
            assert params.get(key) == val

    return validator


@pytest.fixture(scope="session")
def introspection_request_validator() -> RequestValidatorType:
    def validator(
        req: _RequestObjectProxy,
        token: str,
        type_hint: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        params = Query(req.text).params
        assert params.get("token") == token
        if type_hint is not None:
            assert params.get("token_type_hint") == type_hint
        for key, val in kwargs.items():
            assert params.get(key) == val

    return validator


@pytest.fixture(
    scope="session",
    params=[None, "resource", "/resource", "resource/foo", "/resource/foo"],
)
def target_path(request: FixtureRequest) -> Optional[str]:
    return request.param


@pytest.fixture(scope="session")
def target_uri(target_api: str, target_path: str) -> str:
    return join_url(target_api, target_path)


@pytest.fixture(scope="session", params=["refresh_token"])
def refresh_token(request: FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="session", params=["authorization_code"])
def authorization_code(request: FixtureRequest) -> str:
    return request.param


@pytest.fixture(
    scope="session",
    params=[
        "http://localhost/callback",
        "http://localhost:12345/callback",
        "https://example.com/callback",
        "https://example.com/callback:8443",
    ],
)
def redirect_uri(request: FixtureRequest) -> str:
    return request.param


@pytest.fixture(
    scope="session",
    params=["TEST_AUDIENCE", "https://myapi.com", "https://myapi.com/path"],
)
def audience(request: FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="session", params=["openid", "openid profile email"])
def scope(request: FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="session")
def discovery_document(
    issuer: str,
    token_endpoint: str,
    authorization_endpoint: str,
    revocation_endpoint: str,
    userinfo_endpoint: str,
    jwks_uri: str,
) -> Dict[str, str]:
    return {
        "issuer": issuer,
        "authorization_endpoint": authorization_endpoint,
        "token_endpoint": token_endpoint,
        "userinfo_endpoint": userinfo_endpoint,
        "revocation_endpoint": revocation_endpoint,
        "jwks_uri": jwks_uri,
    }


@pytest.fixture(scope="session")
def server_private_jwks() -> JwkSet:
    return JwkSet(
        {
            "keys": [
                {
                    "kty": "RSA",
                    "n": "uOzPy-lWCg14IuoKFI3rmW_Fde3H4uKEoCmUR4aNRjS7GawYN87I00DFhMcsHjjQOjEtLP4E6yt7UNAIIm2aiWWNOGmD2Uv3O_d85h-5Aj-N1BBL3G9pum2VhQQWkxwRAqZoeaj1dFJmxc1jBx0Wiu61vPEHUB0mGP0Y9UKhtRHtiMt4pf4IESa3JuVoOuE4fbyS8l1E4vPkbXE3ZXcXBKiQCXL7zbcLI38XWt3CGjZWR0zm2V65sTGEuBalWUB1btwibqudtA68qG5raJYMtn_gEXM0vUd0gns9jv8xxoem4IZeuEsO98qtxuSPn8vT92sukum8ZEmo_p0cXMDeYQ",
                    "e": "AQAB",
                    "d": "EVp3rYT6A_t7mJsp0v_2afGpMAXeShZDp9v_BC9GNp5gKGqT4zjOc7SSVIF0TGm8cJmIyb4UrBTqf4zmFoT-iYI0HGUacFvGmaQB3n5_mAxqvMnCtK7n1wzNiSv3ClsJ5ZvEFhaa4g2Rg2JgtpwuL19zQoXDz-rMVm_51ZopHpqlPyCLRhBTxD_SFaD6GKe3xUaHmJx-ycWCkHj_TNaH7ZMoAZnICXlaniDlv73k_8H-8VCcEAFDtLbcHVELu7aZdmIYwR8o10UO_aimkz66Pcemkk5_t3vJ-FqAQ-_My3Nm0jlpcFWKnGDGjvw-ERzqu4xypIMf0AD_CoaG8Yj8mQ",
                    "p": "2-_ZlCns-2gR2vGT8srj_5NH5VIwFIvvS1UVuE7KAWdNG-bUogOzWTi6nprv0xQ3PCmyKJ8csl0CEPrFksDFz0x1yTuXkXlUta0XR-xiNvObBTiNsQ32gG1utGuQqt2rV1nnD3sZHKk2GRAnR4u4RbxJvKYpJ0m2Pxjmq7Zm6F8",
                    "q": "1z9KigwxRmnTvkKtdrOY-Bq6vXq1lKXDEJACQnzqqLd0B8r2h5vVvG2o65xlSUh5NB50o7pT20oWm8bCVb-X_OzjGIuULJi47yRQt-2JmyF5B2OMxEoE4kKmxqS4LLISlGQQIUtj8Q_AKn6Cy3oaOODWGA5QAx20q8UDOHO8sT8",
                    "dp": "GGF5TCxtod0ChbPcA8EsDyvjf29h9xUgHMi81KafTBKIgLxQ-_jPC-f3ABgK1-pYySmSH2CsDLW0we8asc7-3qEKOZmKjszVcCJU_1sb9B2DJMwFIQh8N_ZpnESET_ysvs0viQ7LVNsJLTQWNp8teUWLIweEbl-EfXAkOgrJU58",
                    "dq": "XqiZyi3keZfOo6xFBp-i1PFEUFGnixB-wUjjhYPT2pCa-VZbpnV0wGHlWIA11s2FZ9NA7kPh3t0tJiJ5kiYo2_T9Re0UI6yiH6Dz0n8m9c75n7M605PNpAc1usPzrsw8-X8rzMiP0hJgKw_pyzwOThcqb_fTXhtxOdzxNqFHSRc",
                    "qi": "XIHQL8ZwQquEsHhaTPivHkJNI7Rlb7K5NrGkY-KAtEsTQFmY2M9k0EuuTD_-GvlARQ5QsgfkNNZg1UB8_KHti7lo-g0QqEOk-XMJ9tyYo6hQy28FJbP_pTsHNRaKrN4Ho0dQeKSDWqZQPhnwvH2Fd8FnyF7mclN0Do6spQCEaHI",
                },
                {
                    "kty": "RSA",
                    "n": "ncNMyXu_9tAXibmISssbSXB6IVatBZCCB8FzUnGzvxaYllt-OaAPsoUl9IGNIztwjvpPGpttr0oEtJDn-89_VB55yvOvDBEsSuE_ddQUvW1Rx360YVybbcqwQb73lUsKHoM6qj-v_fBlF0LS7sRH5FLHLLSyaJzVYC0rAlpF9CrXNLyUeNMZhMI8j427i5Yj-IbKVuoWCydMwsDH-R3Jrl2WZCxYakiK25z5blcblwya4cLw25q_teaSLWi4cLOnI6TnAknBgZsQe7emHelnguWiPQGyX0Adcf1f7k_Nxan01SyflktA1qXwSLbvwhIEOOLvFYCxeKy3Vt_-XjZJew",
                    "e": "AQAB",
                    "d": "f31Q80227pxxORIeqtqBnZJwj7p8rg9-lQfmyswpxpVbD762PZk0tj5VUsbSqJMjPdfXzxelxs7ZCJZFcj_XlMHgCHtujSDfm091uiF99Sp_uOiSmk99J3dxgl_xscrnTYsdAHHhJiR7fRW6YctqkX-3h1ArENEUudkmdYtAFrS2_3q9ZL6fQytBVzvRFu0GR-Kvb6QDUH4s53PVmR4w6y5nLmAeIbF5RDbSDnJT8Tkdf5_fGm-3MVdRe6yBfi11KnSzC4eY3YPWm0dHBiBxb7YIb-FHgxEmqkepN16sxh3v1VSfmkuCEkH3A_tlOC9c_kIn-pu9ngwG9qlQ1CnqWQ",
                    "p": "0fyWzoAxkfOv1uyFzAx7k3VZLM-NzYZXcjLcVDIBc9rqgzh9pzLqxv2oAogxo9pMuhbSMfLFPhkZ1ynmWFwWz2Vn7_s75smL5nTL6dbQ2_ES4brkEXALVQ3jfFn6qg36H6KFI02gfVC6yu-LuO6D5jHw8Z9FuQa7e6L6esYnOrU",
                    "q": "wFUqcX6MwQu3Sv7mgPglIUxLxr_V9p9_JcqdLuqdlaibQY0us66xq2F6VL10O1KOgyyL5BWYahTgjffTf8-NnWK-44bxN6RyAQbR5I4sgX7PUvsYmYNPFt1jTS_b3qxeG-FkVd2al9Y8YqUyYbLrcka8STjmsWtHPq1Oig8ooW8",
                    "dp": "tByY6dTxL8Q6ffnwJX5LfMa5z4LTmYbyeKSBccJWlp4eaqFIveIhmL83nbxd_7Id_7vVXTxjzIjRLknlJsMOWaQcS65Nyf3z_p8NzKwSB6U20eFxADf_sFuyVRYEuFo2wW2wDwDleLeHEMv5J42GGyuZBFbeAf9xTnITsL1IJsU",
                    "dq": "DR2BoG2lwYBABoAtTbweJBAk1q-8Mm4b6ILRhyJ-jncJ50VuWthdyzcBdYfZxjXR_AXsoCgM1acIzQWKSZvop0PVioRoLIgtMf66D2DWjhoMnzb6LXWzzfZY0CmkT6HnZPVQtz4-TX5RbdSgA-OEhK1oJ4IW0SBkolSFF4sDFUc",
                    "qi": "fHMZ-6wQYcB4Vsvhtx3dW_2Uj9gAzi6nskb7Ej6qTArtGcx8AewQOKaFzz9G6eRIqnnGSoHf6J4xtgGoEX6l9iqoGk-2-_mxqYrkoKIWomQwuDe65u0MMNW4EbFTiV3aTe3Gd5K0vRmGRvInjCoyJKrlpx7yGUsWBeLm3wMjTHU",
                },
            ]
        }
    )


@pytest.fixture(scope="session")
def server_public_jwks(server_private_jwks: JwkSet) -> JwkSet:
    return JwkSet(keys=[jwk.public_jwk() for jwk in server_private_jwks.jwks])


@pytest.fixture(scope="session")
def bearer_auth_validator() -> RequestValidatorType:
    def validator(req: _RequestObjectProxy, *, access_token: str) -> None:
        assert req.headers.get("Authorization") == f"Bearer {access_token}"

    return validator
