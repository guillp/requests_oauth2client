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
from attr import field, frozen
from binapy import BinaPy
from jwskate import Jwk, Jwt, SignatureAlgs, SymmetricJwk, to_jwk


class InvalidRequestForClientAuthentication(RuntimeError):
    """Raised when a request is not suitable for OAuth 2.0 client authentication."""

    def __init__(self, request: requests.PreparedRequest) -> None:
        super().__init__("This request is not suitabe for OAuth 2.0 client authentication.")
        self.request = request


@frozen
class BaseClientAuthenticationMethod(requests.auth.AuthBase):
    """Base class for all Client Authentication methods. This extends [requests.auth.AuthBase][].

    This base class checks that requests are suitable to add Client Authentication parameters to,
    and does not modify the request.

    """

    client_id: str

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
            raise InvalidRequestForClientAuthentication(request)
        return request


@frozen(init=False)
class ClientSecretBasic(BaseClientAuthenticationMethod):
    """Implement `client_secret_basic` authentication.

    With this method, the client sends its Client ID and Secret, in the HTTP `Authorization` header, with
    the `Basic` scheme, in each authenticated request to the Authorization Server.

    Args:
        client_id: Client ID
        client_secret: Client Secret

    Example:
        ```python
        from requests_oauth2client import ClientSecretBasic, OAuth2Client

        auth = ClientSecretBasic("my_client_id", "my_client_secret")
        client = OAuth2Client("https://url.to.the/token_endpoint", auth=auth)
        ```

    """

    client_secret: str

    def __init__(self, client_id: str, client_secret: str) -> None:
        self.__attrs_init__(
            client_id=client_id,
            client_secret=client_secret,
        )

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        """Add the appropriate `Authorization` header in each request.

        The Authorization header is formatted as such:
        `Authorization: Basic BASE64('<client_id:client_secret>')`

        Args:
            request: the request

        Returns:
            a [requests.PreparedRequest][] with the added Authorization header.

        """
        request = super().__call__(request)
        b64encoded_credentials = BinaPy(f"{self.client_id}:{self.client_secret}").to("b64").ascii()
        request.headers["Authorization"] = f"Basic {b64encoded_credentials}"
        return request


@frozen(init=False)
class ClientSecretPost(BaseClientAuthenticationMethod):
    """Implement `client_secret_post` client authentication method.

    With this method, the client inserts its client_id and client_secret in each authenticated
    request to the AS.

    Args:
        client_id: Client ID
        client_secret: Client Secret

    Example:
        ```python
        from requests_oauth2client import ClientSecretPost, OAuth2Client

        auth = ClientSecretPost("my_client_id", "my_client_secret")
        client = OAuth2Client("https://url.to.the/token_endpoint", auth=auth)
        ```

    """

    client_secret: str

    def __init__(self, client_id: str, client_secret: str) -> None:
        self.__attrs_init__(
            client_id=client_id,
            client_secret=client_secret,
        )

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


@frozen
class BaseClientAssertionAuthenticationMethod(BaseClientAuthenticationMethod):
    """Base class for assertion-based client authentication methods."""

    lifetime: int
    jti_gen: Callable[[], str]
    aud: str | None

    def client_assertion(self, audience: str) -> str:
        """Generate a Client Assertion for a specific audience.

        Args:
            audience: the audience to use for the `aud` claim of the generated Client Assertion.

        Returns:
            a Client Assertion, as `str`.

        """
        raise NotImplementedError

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
            raise InvalidRequestForClientAuthentication(request)  # pragma: no cover
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


@frozen(init=False)
class ClientSecretJwt(BaseClientAssertionAuthenticationMethod):
    """Implement `client_secret_jwt` client authentication method.

    With this method, the client generates a client assertion, then symmetrically signs it with its Client Secret.
    The assertion is then sent to the AS in a `client_assertion` field with each authenticated request.

    Args:
        client_id: the `client_id` to use.
        client_secret: the `client_secret` to use to sign generated Client Assertions.
        alg: the alg to use to sign generated Client Assertions.
        lifetime: the lifetime to use for generated Client Assertions.
        jti_gen: a function to generate JWT Token Ids (`jti`) for generated Client Assertions.
        aud: the audience value to use. If `None` (default), the endpoint URL will be used.

    Example:
        ```python
        from requests_oauth2client import OAuth2Client, ClientSecretJwt

        auth = ClientSecretJwt("my_client_id", "my_client_secret")
        client = OAuth2Client("https://url.to.the/token_endpoint", auth=auth)
        ```

    """

    client_secret: str
    alg: str

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        lifetime: int = 60,
        alg: str = SignatureAlgs.HS256,
        jti_gen: Callable[[], str] = lambda: str(uuid4()),
        aud: str | None = None,
    ) -> None:
        self.__attrs_init__(
            client_id=client_id,
            client_secret=client_secret,
            lifetime=lifetime,
            alg=alg,
            jti_gen=jti_gen,
            aud=aud,
        )

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


class InvalidClientAssertionSigningKeyOrAlg(ValueError):
    """Raised when the client assertion signing alg is not specified or invalid."""

    def __init__(self, alg: str | None) -> None:
        super().__init__("""\
An asymmetric private signing key, and an alg that is supported by the signing key is required.
It can be provided either:
- as part of the private `Jwk`, in the parameter 'alg'
- or passed as parameter `alg` when initializing a `PrivateKeyJwt`.
Examples of valid `alg` values and matching key type:
- 'RS256', 'RS512' (with a key of type RSA)
- 'ES256', 'ES512' (with a key of type EC)
The private key must include a Key ID (in its 'kid' parameter).
""")
        self.alg = alg


@frozen(init=False)
class PrivateKeyJwt(BaseClientAssertionAuthenticationMethod):
    """Implement `private_key_jwt` client authentication method.

    With this method, the client generates and sends a client_assertion, that is asymmetrically
    signed with a private key, on each direct request to the Authorization Server.

    The private key must be supplied as a [`jwskate.Jwk`][jwskate.jwk.Jwk] instance,
    or any key material that can be used to initialize one.

    Args:
        client_id: the `client_id` to use.
        private_jwk: the private key to use to sign generated Client Assertions.
        alg: the alg to use to sign generated Client Assertions.
        lifetime: the lifetime to use for generated Client Assertions.
        jti_gen: a function to generate JWT Token Ids (`jti`) for generated Client Assertions.
        aud: the audience value to use. If `None` (default), the endpoint URL will be used.k

    Example:
        ```python
        from jwskate import Jwk
        from requests_oauth2client import OAuth2Client, PrivateKeyJwt

        # load your private key from wherever it is stored:
        with open("my_private_key.pem") as f:
            my_private_key = Jwk.from_pem(f.read(), password="my_private_key_password")

        auth = PrivateKeyJwt("my_client_id", my_private_key, alg="RS256")
        client = OAuth2Client("https://url.to.the/token_endpoint", auth=auth)
        ```

    """

    private_jwk: Jwk = field(converter=to_jwk)
    alg: str | None

    def __init__(
        self,
        client_id: str,
        private_jwk: Jwk | dict[str, Any] | Any,
        *,
        alg: str | None = None,
        lifetime: int = 60,
        jti_gen: Callable[[], str] = lambda: str(uuid4()),
        aud: str | None = None,
    ) -> None:
        self.__attrs_init__(
            client_id=client_id,
            private_jwk=private_jwk,
            alg=alg,
            lifetime=lifetime,
            jti_gen=jti_gen,
            aud=aud,
        )

        alg = self.private_jwk.alg or alg
        if not alg:
            raise InvalidClientAssertionSigningKeyOrAlg(alg)

        if alg not in self.private_jwk.supported_signing_algorithms():
            raise InvalidClientAssertionSigningKeyOrAlg(alg)

        if not self.private_jwk.is_private or self.private_jwk.is_symmetric:
            raise InvalidClientAssertionSigningKeyOrAlg(alg)

        kid = self.private_jwk.get("kid")
        if not kid:
            raise InvalidClientAssertionSigningKeyOrAlg(alg)

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


@frozen
class PublicApp(BaseClientAuthenticationMethod):
    """Implement the `none` authentication method for public apps.

    This scheme is used for Public Clients, which do not have any secret credentials. Those only
    send their client_id to the Authorization Server.

    Example:
        ```python
        from requests_oauth2client import OAuth2Client, PublicApp

        auth = PublicApp("my_client_id")
        client = OAuth2Client("https://url.to.the/token_endpoint", auth=auth)
        ```

    """

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        """Add the `client_id` field in the request body.

        Args:
            request: a request.

        Returns:
            the request with the added `client_id` form field.

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


class UnsupportedClientCredentials(TypeError, ValueError):
    """Raised when unsupported client credentials are provided."""


def client_auth_factory(
    auth: requests.auth.AuthBase | tuple[str, str] | tuple[str, Jwk] | tuple[str, dict[str, Any]] | str | None,
    *,
    client_id: str | None = None,
    client_secret: str | None = None,
    private_key: Jwk | dict[str, Any] | None = None,
    default_auth_handler: type[ClientSecretPost | ClientSecretBasic | ClientSecretJwt] = ClientSecretPost,
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
        msg = """\
Please use either `auth` parameter to provide an authentication method,
or use `client_id` and one of `client_secret` or `private_key`.
"""
        raise UnsupportedClientCredentials(msg)

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
            raise UnsupportedClientCredentials(msg, type(credential), credential)

    if client_id is None:
        msg = "A client_id must be provided."
        raise UnsupportedClientCredentials(msg)

    if private_key is not None:
        return PrivateKeyJwt(client_id, private_jwk=private_key)
    if client_secret is None:
        return PublicApp(str(client_id))

    return default_auth_handler(str(client_id), str(client_secret))
