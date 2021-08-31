from datetime import datetime
from typing import Any, Callable, Optional, Tuple, Type, Union
from uuid import uuid4

import furl  # type: ignore[import]
import requests

from .jwskate import Jwk, Jwt, SymetricJwk
from .utils import b64_encode


class ClientAuthenticationMethod(requests.auth.AuthBase):
    """
    Base class for the Client Authentication methods.
    """

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        if request.method != "POST" or request.headers.get("Content-Type") not in (
            "application/x-www-form-urlencoded",
            None,
        ):
            raise RuntimeError(
                "This request is not suitable for OAuth2.0 Client Authentication"
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
        b64encoded_credentials = b64_encode(":".join((self.client_id, self.client_secret)))
        request.headers["Authorization"] = f"Basic {b64encoded_credentials}"
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
        raise NotImplementedError()  # pragma: no cover

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
    Handles client_secret_jwt client authentication method (client_assertion symmetrically signed with the client_secret).
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

        jwk = SymetricJwk.from_bytes(self.client_secret.encode())

        jwt = Jwt.sign(
            claims={
                "iss": self.client_id,
                "sub": self.client_id,
                "aud": audience,
                "iat": iat,
                "exp": exp,
                "jti": jti,
            },
            jwk=jwk,
            alg=self.alg,
        )
        return str(jwt)


class PrivateKeyJWT(ClientAssertionAuthenticationMethod):
    """
    Handles private_key_jwt client authentication method (client_assertion asymmetrically signed with a private key).
    """

    def __init__(
        self,
        client_id: str,
        private_jwk: Jwk,
        alg: str = "RS256",
        lifetime: int = 60,
        kid: Optional[str] = None,
        jti_gen: Callable[[], Any] = lambda: uuid4(),
    ) -> None:
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
        self.private_jwk = private_jwk
        self.kid = kid

    def client_assertion(self, audience: str) -> str:
        iat = int(datetime.now().timestamp())
        exp = iat + self.lifetime
        jti = str(self.jti_gen())

        jwt = Jwt.sign(
            claims={
                "iss": self.client_id,
                "sub": self.client_id,
                "aud": audience,
                "iat": iat,
                "exp": exp,
                "jti": jti,
            },
            jwk=self.private_jwk,
            alg=self.alg,
            kid=self.kid,
        )
        return str(jwt)


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


def client_auth_factory(
    auth: Union[requests.auth.AuthBase, Tuple[str, str], str],
    default_auth_handler: Union[
        Type[ClientSecretPost], Type[ClientSecretBasic]
    ] = ClientSecretPost,
) -> requests.auth.AuthBase:
    if isinstance(auth, requests.auth.AuthBase):
        return auth
    elif isinstance(auth, tuple) and len(auth) == 2:
        client_id, credential = auth
        if isinstance(credential, Jwk):
            private_jwk = credential
            return PrivateKeyJWT(str(client_id), private_jwk)
        else:
            return default_auth_handler(str(client_id), credential)
    elif isinstance(auth, str):
        client_id = auth
        return PublicApp(client_id)
    else:
        raise ValueError(
            """Parameter 'auth' is required to define the Authentication Method that this Client will use when sending requests to the Token Endpoint.
'auth' can be:
- an instance of a requests.auth.AuthBase subclass, including ClientSecretPost, ClientSecretBasic, ClientSecretJWT, PrivateKeyJWT, PublicApp, 
- a (client_id, client_secret) tuple, both as str, for ClientSecretPost,
- a (client_id, private_key) tuple, with client_id as str and private_key as a dict in JWK format, for PrivateKeyJWT,
- a client_id, as str, for PublicApp.
"""
        )
