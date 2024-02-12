"""This module implements OAuth 2.0 Client Authentication Methods.

An OAuth 2.0 Client must authenticate to the AS whenever it sends a request to the Token Endpoint,
by including appropriate credentials. This module contains helper classes and methods that implement
the standardized and commonly used Client Authentication Methods.

"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import parse_qs
from uuid import uuid4

import requests
from binapy import BinaPy
from jwskate import Jwk, Jwt, SignatureAlgs, SymmetricJwk


class BaseClientAuthenticationMethod(requests.auth.AuthBase):
    """Base class for all Client Authentication methods. This extends [requests.auth.AuthBase].

    This base class only checks that requests are suitable to add Client Authentication parameters
    to, and doesn't modify the request.

    """

    def __init__(self, client_id: str):
        self.client_id = str(client_id)

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
            msg = "This request is not suitable for OAuth 2.0 Client Authentication"
            raise RuntimeError(msg)
        return request


class ClientSecretBasic(BaseClientAuthenticationMethod):
    """Implement `client_secret_basic` authentication.

    With this method, the client sends its Client ID and Secret, in the Authorization header, with
    the "Basic" scheme, in each authenticated request to the AS.

    Args:
        client_id: `client_id` to use.
        client_secret: `client_secret` to use.

    """

    def __init__(self, client_id: str, client_secret: str):
        super().__init__(client_id)
        self.client_secret = str(client_secret)

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        """Add the appropriate `Authorization` header in each request.

        The Authorization header is formatted as such: `Authorization: Basic
        BASE64('<client_id:client_secret>')`

        Args:
            request: a [requests.PreparedRequest][].

        Returns:
            a [requests.PreparedRequest][] with the added Authorization header.

        """
        request = super().__call__(request)
        b64encoded_credentials = BinaPy(f"{self.client_id}:{self.client_secret}").to("b64").ascii()
        request.headers["Authorization"] = f"Basic {b64encoded_credentials}"
        return request


class ClientSecretPost(BaseClientAuthenticationMethod):
    """Implement `client_secret_post` client authentication method.

     With this method, the client inserts its client_id and client_secret in each authenticated
     request to the AS.

    Args:
        client_id: `client_id` to use.
        client_secret: `client_secret` to use.

    """

    def __init__(self, client_id: str, client_secret: str) -> None:
        super().__init__(client_id)
        self.client_secret = str(client_secret)

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        """Add the `client_id` and `client_secret` parameters in the request body.

        Args:
            request: a [requests.PreparedRequest][].

        Returns:
            a [requests.PreparedRequest][] with the added client credentials fields.

        """
        request = super().__call__(request)
        params = (
            parse_qs(request.body, strict_parsing=True, keep_blank_values=True)  # type: ignore[type-var]
            if isinstance(request.body, (str, bytes))
            else {}
        )
        params[b"client_id"] = [self.client_id.encode()]
        params[b"client_secret"] = [self.client_secret.encode()]
        request.prepare_body(params, files=None)
        return request


class ClientAssertionAuthenticationMethod(BaseClientAuthenticationMethod):
    """Base class for assertion-based client authentication methods.

    Args:
        client_id: the client_id to use
        alg: the alg to use to sign generated Client Assertions.
        lifetime: the lifetime to use for generated Client Assertions.
        jti_gen: a function to generate JWT Token Ids (`jti`) for generated Client Assertions.
        aud: the audience value to use. If `None` (default), the endpoint URL will be used.

    """

    def __init__(
        self,
        client_id: str,
        alg: str,
        lifetime: int,
        jti_gen: Callable[[], str],
        aud: str | None = None,
    ) -> None:
        super().__init__(client_id)
        self.alg = alg
        self.lifetime = lifetime
        self.jti_gen = jti_gen
        self.aud = aud

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
        audience = self.aud or request.url
        if audience is None:
            msg = "No url defined for this request. This should never happen..."  # pragma: no cover
            raise ValueError(msg)  # pragma: no cover
        params = (
            parse_qs(request.body, strict_parsing=True, keep_blank_values=True)  # type: ignore[type-var]
            if request.body
            else {}
        )
        client_assertion = self.client_assertion(audience)
        params[b"client_id"] = [self.client_id.encode()]
        params[b"client_assertion"] = [client_assertion.encode()]
        params[b"client_assertion_type"] = [b"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"]
        request.prepare_body(params, files=None)
        return request


class ClientSecretJwt(ClientAssertionAuthenticationMethod):
    """Implement `client_secret_jwt` client authentication method.

    With this method, the client generates and signs a client assertion that is symmetrically
    signed with its Client Secret. The assertion is then sent to the AS in a `client_assertion`
    field with each authenticated request.

    Args:
        client_id: the `client_id` to use.
        client_secret: the `client_secret` to use to sign generated Client Assertions.
        alg: the alg to use to sign generated Client Assertions.
        lifetime: the lifetime to use for generated Client Assertions.
        jti_gen: a function to generate JWT Token Ids (`jti`) for generated Client Assertions.
        aud: the audience value to use. If `None` (default), the endpoint URL will be used.

    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        alg: str = "HS256",
        lifetime: int = 60,
        jti_gen: Callable[[], Any] = lambda: uuid4(),
        aud: str | None = None,
    ) -> None:
        super().__init__(client_id, alg, lifetime, jti_gen, aud)
        self.client_secret = str(client_secret)

    def client_assertion(self, audience: str) -> str:
        """Generate a symmetrically signed Client Assertion.

        Assertion is signed with the `client_secret` as key and the `alg` passed at init time.

        Args:
            audience: the audience to use for the generated Client Assertion.

        Returns:
            a Client Assertion, as `str`.

        """
        iat = int(datetime.now(tz=timezone.utc).timestamp())
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
            key=jwk,
            alg=self.alg,
        )
        return str(jwt)


class PrivateKeyJwt(ClientAssertionAuthenticationMethod):
    """Implement `private_key_jwt` client authentication method.

    With this method, the client generates and sends a client_assertion, that is asymmetrically
    signed with a private key, on each direct request to the Authorization Server.

    Args:
        client_id: the `client_id` to use.
        private_jwk: the private JWK to use to sign generated Client Assertions.
        alg: the alg to use to sign generated Client Assertions.
        lifetime: the lifetime to use for generated Client Assertions.
        jti_gen: a function to generate JWT Token Ids (`jti`) for generated Client Assertions.
        aud: the audience value to use. If `None` (default), the endpoint URL will be used.k

    """

    def __init__(
        self,
        client_id: str,
        private_jwk: Jwk | dict[str, Any],
        alg: str = SignatureAlgs.RS256,
        lifetime: int = 60,
        jti_gen: Callable[[], Any] = lambda: uuid4(),
        aud: str | None = None,
    ) -> None:
        if not isinstance(private_jwk, Jwk):
            private_jwk = Jwk(private_jwk)

        if not private_jwk.is_private or private_jwk.is_symmetric:
            msg = "Private Key JWT client authentication method uses asymmetric signing thus requires a private key."
            raise ValueError(msg)

        alg = private_jwk.alg or alg
        if not alg:
            msg = "An asymmetric signing alg is required, either as part of the private JWK, or passed as parameter."
            raise ValueError(msg)
        kid = private_jwk.get("kid")
        if not kid:
            msg = "Asymmetric signing requires the private JWK to have a Key ID (kid)."
            raise ValueError(msg)

        super().__init__(client_id, alg, lifetime, jti_gen, aud)
        self.private_jwk = private_jwk

    def client_assertion(self, audience: str) -> str:
        """Generate a Client Assertion, asymmetrically signed with `private_jwk` as key.

        Args:
            audience: the audience to use for the generated Client Assertion.

        Returns:
            a Client Assertion.

        """
        iat = int(datetime.now(tz=timezone.utc).timestamp())
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
            key=self.private_jwk,
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
        params = (
            parse_qs(request.body, strict_parsing=True, keep_blank_values=True)  # type: ignore[type-var]
            if request.body
            else {}
        )
        params[b"client_id"] = [self.client_id.encode()]
        request.prepare_body(params, files=None)
        return request


def client_auth_factory(
    auth: requests.auth.AuthBase | tuple[str, str] | tuple[str, Jwk] | tuple[str, dict[str, Any]] | str | None,
    *,
    client_id: str | None = None,
    client_secret: str | None = None,
    private_key: Jwk | dict[str, Any] | None = None,
    default_auth_handler: type[ClientSecretPost] | type[ClientSecretBasic] | type[ClientSecretJwt] = ClientSecretPost,
) -> requests.auth.AuthBase:
    """Initialize the appropriate Auth Handler based on the provided parameters.

    This initializes a `ClientAuthenticationMethod` subclass based on the provided parameters.

    Args:
        auth: can be:

            - a `requests.auth.AuthBase` instance (which will be used directly)
            - a tuple of (client_id, client_secret) which will be used to initialize an instance of
              `default_auth_handler`,
            - a tuple of (client_id, jwk), used to initialize a `PrivateKeyJwk` (`jwk` being an
              instance of `jwskate.Jwk` or a `dict`),
            - a `client_id`, as `str`,
            - or `None`, to pass `client_id` and other credentials as dedicated parameters, see
              below.
        client_id: the Client ID to use for this client
        client_secret: the Client Secret to use for this client, if any (for clients using
            an authentication method based on a secret)
        private_key: the private key to use for private_key_jwt authentication method
        default_auth_handler: if a client_id and client_secret are provided, initialize an
            instance of this class with those 2 parameters.
            You can choose between `ClientSecretBasic`, `ClientSecretPost`, or `ClientSecretJwt`.

    Returns:
        an Auth Handler that will manage client authentication to the AS Token Endpoint or other
        backend endpoints.

    """
    if auth is not None and (client_id is not None or client_secret is not None or private_key is not None):
        msg = (
            "Please use either `auth` parameter to provide an authentication method, or use"
            " `client_id` and one of `client_secret` or `private_key`."
        )
        raise ValueError(msg)

    if isinstance(auth, str):
        client_id = auth
    elif isinstance(auth, requests.auth.AuthBase):
        return auth
    elif isinstance(auth, tuple) and len(auth) == 2:  # noqa: PLR2004
        client_id, credential = auth
        if isinstance(credential, (Jwk, dict)):
            private_key = credential
        elif isinstance(credential, str):
            client_secret = credential
        else:
            msg = "This credential type is not supported:"
            raise TypeError(msg, type(credential), credential)

    if client_id is None:
        msg = "A client_id must be provided."
        raise ValueError(msg)

    if private_key is not None:
        return PrivateKeyJwt(str(client_id), private_key)
    elif client_secret is None:
        return PublicApp(str(client_id))
    else:
        return default_auth_handler(str(client_id), str(client_secret))
