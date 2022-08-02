"""This modules implements OAuth 2.0 Client Authentication Methods.

An OAuth 2.0 Client must authenticate to the AS whenever it sends a request to the Token
Endpoint, by including appropriate credentials. This module contains helper classes and methods
that implement the standardised and commonly used Client Authentication Methods.
"""

from datetime import datetime
from typing import Any, Callable, Dict, Tuple, Type, Union
from uuid import uuid4

import furl  # type: ignore[import]
import requests
from binapy import BinaPy
from jwskate import Jwk, Jwt, SymmetricJwk


class BaseClientAuthenticationMethod(requests.auth.AuthBase):
    """Base class for all Client Authentication methods. This extends [requests.auth.AuthBase].

    This base class only checks that requests are suitable to add Client Authentication
    parameters to, and doesn't modify the request.
    """

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        """Check that the request is suitable for Client Authentication.

        It checks:
        * that the method is `POST`
        * that the Content-Type is "application/x-www-form-urlencoded" or None

        Args:
            request: a [requests.PreparedRequest][]

        Returns:
            a [requests.PreparedRequest][], unmodified

        Raises:
            RuntimeError: if the request is not suitable for OAuth 2.0 Client Authentication
        """
        if request.method != "POST" or request.headers.get("Content-Type") not in (
            "application/x-www-form-urlencoded",
            None,
        ):
            raise RuntimeError(
                "This request is not suitable for OAuth 2.0 Client Authentication"
            )
        return request


class ClientSecretBasic(BaseClientAuthenticationMethod):
    """Implement `client_secret_basic` authentication.

    With this method, the client sends its Client ID and Secret, in the Auhtorization header, with the "Basic" scheme,
    in each authenticated request to the AS.

    Args:
        client_id: `client_id` to use.
        client_secret: `client_secret` to use.
    """

    def __init__(self, client_id: str, client_secret: str):
        self.client_id = str(client_id)
        self.client_secret = str(client_secret)

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        """Add the appropriate `Authorization` header in each request.

        The Authorization header is formatted as such:
        `Authorization: Basic BASE64('<client_id:client_secret>')`

        Args:
            request: a [requests.PreparedRequest][].

        Returns:
            a [requests.PreparedRequest][] with the added Authorization header.
        """
        request = super().__call__(request)
        b64encoded_credentials = (
            BinaPy(f"{self.client_id}:{self.client_secret}").to("b64").ascii()
        )
        request.headers["Authorization"] = f"Basic {b64encoded_credentials}"
        return request


class ClientSecretPost(BaseClientAuthenticationMethod):
    """Implement `client_secret_post` client authentication method.

     With this method, the client inserts its client_id and client_secret in each authenticated request to the AS.

    Args:
        client_id: `client_id` to use.
        client_secret: `client_secret` to use.
    """

    def __init__(self, client_id: str, client_secret: str) -> None:
        self.client_id = str(client_id)
        self.client_secret = str(client_secret)

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        """Add the `client_id` and `client_secret` parameters in the request body.

        Args:
            request: a [requests.PreparedRequest][].

        Returns:
            a [requests.PreparedRequest][] with the added client credentials fields.
        """
        request = super().__call__(request)
        data = furl.Query(request.body)
        data.set([("client_id", self.client_id), ("client_secret", self.client_secret)])
        request.prepare_body(data.params, files=None)
        return request


class ClientAssertionAuthenticationMethod(BaseClientAuthenticationMethod):
    """Base class for assertion based client authentication methods.

    Args:
        client_id: the client_id to use
        alg: the alg to use to sign generated Client Assertions.
        lifetime: the lifetime to use for generated Client Assertions.
        jti_gen: a function to generate JWT Token Ids (`jti`) for generated Client Assertions.
    """

    def __init__(
        self, client_id: str, alg: str, lifetime: int, jti_gen: Callable[[], str]
    ) -> None:
        self.client_id = str(client_id)
        self.alg = alg
        self.lifetime = lifetime
        self.jti_gen = jti_gen

    def client_assertion(self, audience: str) -> str:
        """Generate a Client Assertion for a specific audience.

        Args:
            audience: the audience to use for the `aud` claim of the generated Client Assertion.

        Returns:
            a Client Assertion, as `str`.
        """
        raise NotImplementedError()  # pragma: no cover

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        """Add a `client_assertion` field in the request body.

        Args:
            request: a [requests.PreparedRequest][].

        Returns:
            a [requests.PreparedRequest][] with the added `client_assertion` field.
        """
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


class ClientSecretJwt(ClientAssertionAuthenticationMethod):
    """Implement `client_secret_jwt` client authentication method.

     With this method, client generates and signs a client assertion that is symmetrically signed with its Client Secret.
     The assertion is then sent to the AS in a `client_assertion` field with each authenticated request.

    Args:
        client_id: the `client_id` to use.
        client_secret: the `client_secret` to use to sign generated Client Assertions.
        alg: the alg to use to sign generated Client Assertions.
        lifetime: the lifetime to use for generated Client Assertions.
        jti_gen: a function to generate JWT Token Ids (`jti`) for generated Client Assertions.
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
        """Generate a  symmetrically signed Client Assertion.

        Assertion is signed with the `client_secret` as key and the `alg` passed at init time.

        Args:
            audience: the audience to use for the generated Client Assertion.

        Returns:
            a Client Assertion, as `str`.
        """
        iat = int(datetime.now().timestamp())
        exp = iat + self.lifetime
        jti = str(self.jti_gen())

        jwk = SymmetricJwk.from_bytes(self.client_secret.encode())

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


class PrivateKeyJwt(ClientAssertionAuthenticationMethod):
    """Implement `private_key_jwt` client authentication method.

    With this method, the client generates and sends a client_assertion, that is
    asymmetrically signed with a private key, on each direct request to the Authorization Server.

    Args:
        client_id: the `client_id` to use.
        private_jwk: the private JWK to use to sign generated Client Assertions.
        alg: the alg to use to sign generated Client Assertions.
        lifetime: the lifetime to use for generated Client Assertions.
        jti_gen: a function to generate JWT Token Ids (`jti`) for generated Client Assertions.
    """

    def __init__(
        self,
        client_id: str,
        private_jwk: Union[Jwk, Dict[str, Any]],
        alg: str = "RS256",
        lifetime: int = 60,
        jti_gen: Callable[[], Any] = lambda: uuid4(),
    ) -> None:
        if not isinstance(private_jwk, Jwk):
            private_jwk = Jwk(private_jwk)

        if not private_jwk.is_private or isinstance(private_jwk, SymmetricJwk):
            raise ValueError("Asymmetric signing requires a private key")

        alg = private_jwk.alg or alg
        if not alg:
            raise ValueError(
                "Asymmetric signing requires an alg, either as part of the private JWK, or passed as parameter"
            )
        kid = private_jwk.get("kid")
        if not kid:
            raise ValueError(
                "Asymmetric signing requires a kid, either as part of the private JWK, or passed as parameter"
            )

        super().__init__(client_id, alg, lifetime, jti_gen)
        self.private_jwk = private_jwk

    def client_assertion(self, audience: str) -> str:
        """Generate a Client Assertion, asymetrically signed with `private_jwk` as key.

        Args:
            audience: the audience to use for the generated Client Assertion.

        Returns:
            a Client Assertion.
        """
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
        )
        return str(jwt)


class PublicApp(BaseClientAuthenticationMethod):
    """Implement the `none` authentication method for public apps.

    This scheme is used for Public Clients, which do not have any secret credentials. Those only
    send their client_id to the Authorization Server.

    Args:
        client_id: the client_id to use.
    """

    def __init__(self, client_id: str) -> None:
        self.client_id = client_id

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        """Add the `client_id` field in the request body.

        Args:
            request: a [requests.PreparedRequest][].

        Returns:
            a [requests.PreparedRequest][] with the added `client_id` field.
        """
        request = super().__call__(request)
        data = furl.Query(request.body)
        data.set([("client_id", self.client_id)])
        request.prepare_body(data.params, files=None)
        return request


def client_auth_factory(
    auth: Union[
        requests.auth.AuthBase,
        Tuple[str, str],
        Tuple[str, Jwk],
        Tuple[str, Dict[str, Any]],
        str,
    ],
    default_auth_handler: Union[
        Type[ClientSecretPost], Type[ClientSecretBasic], Type[ClientSecretJwt]
    ] = ClientSecretPost,
) -> requests.auth.AuthBase:
    """Initialize the appropriate Auth Handler based on the provided parameters.

    This initializes a `ClientAuthenticationMethod` subclass based on the provided parameters.

    Args:
        auth: Can be a :class:`requests.auth.AuthBase` instance (which will be used directly), or a tuple
            of (client_id, client_secret) which will initialize, by default, an instance of `default_auth_handler`,
            a (client_id, jwk) to initialize a :class:`PrivateKeyJWK`, or a `client_id` which will use :class:`PublicApp`
            authentication.
        default_auth_handler: if auth is a tuple of two string, consider that they are a client_id and client_secret,
            and initialize an instance of this class with those 2 parameters.

    Returns:
        an Auth Handler that will manage client authentication to the AS Token Endpoint or other backend endpoints.
    """
    if isinstance(auth, requests.auth.AuthBase):
        return auth
    elif isinstance(auth, tuple) and len(auth) == 2:
        client_id, credential = auth
        if isinstance(credential, (Jwk, dict)):
            private_jwk = credential
            return PrivateKeyJwt(str(client_id), private_jwk)
        else:
            return default_auth_handler(str(client_id), credential)
    elif isinstance(auth, str):
        client_id = auth
        return PublicApp(client_id)
    else:
        raise ValueError(
            """Parameter 'auth' is required to define the Authentication Method that this Client will use when sending requests to the Token Endpoint.
'auth' can be:
- an instance of a requests.auth.AuthBase subclass, including ClientSecretPost, ClientSecretBasic, ClientSecretJwt, PrivateKeyJwt, PublicApp,
- a (client_id, client_secret) tuple, both as str, for ClientSecretPost,
- a (client_id, private_key) tuple, with client_id as str and private_key as a dict in JWK format, for PrivateKeyJwt,
- a client_id, as str, for PublicApp.
"""
        )
