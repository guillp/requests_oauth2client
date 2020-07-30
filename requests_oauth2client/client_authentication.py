from __future__ import annotations

from datetime import datetime
from typing import Any, Callable
from uuid import uuid4

import furl  # type: ignore[import]
import requests
from jwcrypto.jwk import JWK  # type: ignore[import]
from jwcrypto.jwt import JWT  # type: ignore[import]
from requests.auth import _basic_auth_str

from requests_oauth2client.utils import b64u_encode


class ClientAuthenticationMethod(requests.auth.AuthBase):
    """
    Base class for the Client Authentication methods.
    """

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        if (
            request.method != "POST"
            or request.headers["Content-Type"] != "application/x-www-form-urlencoded"
        ):
            raise RuntimeError(
                "This request is not suitable to add OAuth2.0 Client Authentication"
            )
        return request


class ClientSecretBasic(ClientAuthenticationMethod):
    """
    Handles client_secret_basic authentication (client_id and client_secret passed as Basic authentication)
    """

    def __init__(self, client_id: str, client_secret: str):
        self.client_id = str(client_id)
        self.client_secret = str(client_secret)

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        request = super().__call__(request)
        request.headers["Authorization"] = _basic_auth_str(self.client_id, self.client_secret)
        return request


class ClientSecretPost(ClientAuthenticationMethod):
    """
    Handles client_secret_post client authentication method (client_id and client_secret
    passed as part of the request form data).
    """

    def __init__(self, client_id: str, client_secret: str):
        self.client_id = str(client_id)
        self.client_secret = str(client_secret)

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        request = super().__call__(request)
        data = furl.Query(request.body)
        data.set([("client_id", self.client_id), ("client_secret", self.client_secret)])
        request.prepare_body(data.params, files=None)
        return request


class ClientAssertionAuthenticationMethod(ClientAuthenticationMethod):
    """
    Base class for assertion based client authentication methods.
    """

    def __init__(self, client_id: str, alg: str, lifetime: int, jti_gen: Callable[[], str]):
        self.client_id = str(client_id)
        self.alg = alg
        self.lifetime = lifetime
        self.jti_gen = jti_gen

    def client_assertion(self, audience: str) -> str:
        raise NotImplementedError()

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        request = super().__call__(request)
        token_endpoint = request.url
        assert token_endpoint is not None
        data = furl.Query(request.body)
        client_assertion = self.client_assertion(token_endpoint)
        data.set(
            [
                ("client_id", self.client_id),
                ("client_assertion", client_assertion),
                (
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ),
            ]
        )
        request.prepare_body(data.params, files=None)
        return request


class ClientSecretJWT(ClientAssertionAuthenticationMethod):
    """
    Handles client_secret_jwt client authentication method (client_assertion symmetrically signed with the client_secet).
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        alg: str = "HS256",
        lifetime: int = 60,
        jti_gen: Callable[[], Any] = lambda: uuid4(),
    ) -> None:
        super().__init__(client_id, alg, lifetime, jti_gen)
        self.client_secret = str(client_secret)

    def client_assertion(self, audience: str) -> str:
        iat = int(datetime.now().timestamp())
        exp = iat + self.lifetime
        jti = str(self.jti_gen())

        jwk = JWK(kty="oct", k=b64u_encode(self.client_secret))

        jwt = JWT(
            header={"alg": self.alg},
            claims={
                "iss": self.client_id,
                "sub": self.client_id,
                "aud": audience,
                "iat": iat,
                "exp": exp,
                "jti": jti,
            },
        )
        jwt.make_signed_token(jwk)
        assertion: str = jwt.serialize()
        return assertion


class PrivateKeyJWT(ClientAssertionAuthenticationMethod):
    """
    Handles private_key_jwt client authentication method (client_assertion asymmetrically signed with a private key).
    """

    def __init__(
        self,
        client_id: str,
        private_jwk: dict,
        alg: str = "RS256",
        lifetime: int = 60,
        kid: str = None,
        jti_gen: Callable[[], Any] = lambda: uuid4(),
    ):
        alg = private_jwk.get("alg", alg)
        if not alg:
            raise ValueError(
                "Asymmetric signing requires an alg, either as part of the private JWK, or passed as parameter"
            )
        kid = private_jwk.get("kid", kid)
        if not kid:
            raise ValueError(
                "Asymmetric signing requires a kid, either as part of the private JWK, or passed as parameter"
            )

        super().__init__(client_id, alg, lifetime, jti_gen)
        self.private_jwk = JWK(**private_jwk)
        self.kid = kid

    def client_assertion(self, audience: str, lifetime: int = 60, jti: str = None) -> str:
        iat = int(datetime.now().timestamp())
        exp = iat + lifetime
        if jti is None:
            jti = str(uuid4())
        elif callable(jti):
            jti = jti()

        if not isinstance(jti, str):
            jti = str(jti)

        jwt = JWT(
            header={"alg": self.alg, "kid": self.kid},
            claims={
                "iss": self.client_id,
                "sub": self.client_id,
                "aud": audience,
                "iat": iat,
                "exp": exp,
                "jti": jti,
            },
        )
        jwt.make_signed_token(self.private_jwk)
        assertion: str = jwt.serialize()
        return assertion


class PublicApp(ClientAuthenticationMethod):
    """
    Handles the "none" authentication method (client only sends its client_id).
    """

    def __init__(self, client_id: str) -> None:
        self.client_id = client_id

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        request = super().__call__(request)
        data = furl.Query(request.body)
        data.set([("client_id", self.client_id)])
        request.prepare_body(data.params, files=None)
        return request
