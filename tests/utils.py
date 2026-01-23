from __future__ import annotations

import base64
from collections.abc import Callable
from datetime import datetime, timezone
from typing import TYPE_CHECKING
from urllib.parse import parse_qs

import requests_mock
from furl import Query, furl  # type: ignore[import-untyped]
from jwskate import Jwk, SignedJwt, SymmetricJwk
from requests_mock import Mocker

RequestValidatorType = Callable[..., None]


if TYPE_CHECKING:
    from pytest import FixtureRequest as __FixtureRequest  # noqa: PT013
    from requests_mock.request import _RequestObjectProxy

    class FixtureRequest(__FixtureRequest):
        param: str

    class RequestsMocker(Mocker):
        def reset_mock(self) -> None: ...

else:
    RequestsMocker = Mocker


def client_secret_post_auth_validator(req: _RequestObjectProxy, *, client_id: str, client_secret: str) -> None:
    params = parse_qs(req.text)
    assert params.get("client_id") == [client_id]
    assert params.get("client_secret") == [client_secret]
    assert "Authorization" not in req.headers


def public_app_auth_validator(req: _RequestObjectProxy, *, client_id: str) -> None:
    params = parse_qs(req.text)
    assert params.get("client_id") == [client_id]
    assert "client_secret" not in params


def client_secret_basic_auth_validator(req: _RequestObjectProxy, *, client_id: str, client_secret: str) -> None:
    encoded_username_password = base64.b64encode(f"{client_id}:{client_secret}".encode("ascii")).decode()
    assert req.headers.get("Authorization") == f"Basic {encoded_username_password}"
    assert "client_secret" not in req.text


def client_secret_jwt_auth_validator(
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
    now = int(datetime.now(tz=timezone.utc).timestamp())
    assert now - 10 <= claims["iat"] <= now, "unexpected iat"
    assert now + 10 < claims["exp"] < now + 180, "unexpected exp"
    assert claims["iss"] == client_id
    assert claims["aud"] == endpoint
    assert "jti" in claims
    assert claims["sub"] == client_id


def private_key_jwt_auth_validator(
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
    now = int(datetime.now(timezone.utc).timestamp())
    assert now - 10 <= claims["iat"] <= now, "unexpected iat"
    assert now + 10 < claims["exp"] < now + 180, "unexpected exp"
    assert claims["iss"] == client_id
    assert claims["aud"] == endpoint
    assert "jti" in claims
    assert claims["sub"] == client_id


def join_url(root: str, path: str) -> str:
    if path:
        f = furl(root).add(path=path)
        f.path.normalize()
        return str(f.url)
    return root
