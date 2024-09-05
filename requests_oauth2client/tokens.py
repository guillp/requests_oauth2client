"""This module contains classes that represent Tokens used in OAuth2.0 / OIDC."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum
from math import ceil
from typing import TYPE_CHECKING, Any, Callable, ClassVar, Sequence

import jwskate
import requests
from attrs import Factory, asdict, frozen
from binapy import BinaPy
from typing_extensions import Self

from .utils import accepts_expires_in

if TYPE_CHECKING:
    from .authorization_request import AuthorizationResponse
    from .client import OAuth2Client


class TokenType(str, Enum):
    """An enum of standardised `token_type` values."""

    ACCESS_TOKEN = "access_token"
    REFRESH_TOKEN = "refresh_token"
    ID_TOKEN = "id_token"


class AccessTokenType(str, Enum):
    """An enum of standardised `access_token` types."""

    BEARER = "Bearer"


class UnsupportedTokenType(ValueError):
    """Raised when an unsupported token_type is provided."""

    def __init__(self, token_type: str) -> None:
        super().__init__(f"Unsupported token_type: {token_type}")
        self.token_type = token_type


class IdToken(jwskate.SignedJwt):
    """Represent an ID Token.

    An ID Token is actually a Signed JWT. If the ID Token is encrypted, it must be decoded
    beforehand.

    """

    @property
    def authorized_party(self) -> str | None:
        """The Authorized Party (azp)."""
        azp = self.claims.get("azp")
        if azp is None or isinstance(azp, str):
            return azp
        msg = "`azp` attribute must be a string."
        raise AttributeError(msg)

    @property
    def auth_datetime(self) -> datetime | None:
        """The last user authentication time (auth_time)."""
        auth_time = self.claims.get("auth_time")
        if auth_time is None:
            return None
        if isinstance(auth_time, int) and auth_time > 0:
            return self.timestamp_to_datetime(auth_time)
        msg = "`auth_time` must be a positive integer"
        raise AttributeError(msg)

    @classmethod
    def hash_method(cls, key: jwskate.Jwk, alg: str | None = None) -> Callable[[str], str]:
        """Returns a callable that generates valid OIDC hashes, such as `at_hash`, `c_hash`, etc.

        Args:
            key: the ID token signature verification public key
            alg: the ID token signature algorithm

        Returns:
            a callable that takes a string as input and produces a valid hash as a str output

        """
        alg_class = jwskate.select_alg_class(key.SIGNATURE_ALGORITHMS, jwk_alg=key.alg, alg=alg)
        if alg_class == jwskate.EdDsa:
            if key.crv == "Ed25519":

                def hash_method(token: str) -> str:
                    return BinaPy(token).to("sha512")[:32].to("b64u").decode()

            elif key.crv == "Ed448":

                def hash_method(token: str) -> str:
                    return BinaPy(token).to("shake256", 456).to("b64u").decode()

        else:
            hash_alg = alg_class.hashing_alg.name
            hash_size = alg_class.hashing_alg.digest_size

            def hash_method(token: str) -> str:
                return BinaPy(token).to(hash_alg)[: hash_size // 2].to("b64u").decode()

        return hash_method


class InvalidIdToken(ValueError):
    """Raised when trying to validate an invalid ID Token value."""

    def __init__(self, message: str, token: TokenResponse, id_token: IdToken | None = None) -> None:
        super().__init__(f"Invalid ID Token: {message}")
        self.token = token
        self.id_token = id_token


class MissingIdToken(InvalidIdToken):
    """Raised when the Authorization Endpoint does not return a mandatory ID Token.

    This happens when the Authorization Endpoint does not return an error, but does not return an ID
    Token either.

    """

    def __init__(self, token: TokenResponse) -> None:
        super().__init__("An expected `id_token` is missing in the response.", token, None)


class MismatchingIdTokenIssuer(InvalidIdToken):
    """Raised on mismatching `iss` value in an ID Token.

    This happens when the expected `issuer` value is different from the `iss` value in an obtained ID Token.

    """

    def __init__(self, iss: str | None, expected: str, token: TokenResponse, id_token: IdToken) -> None:
        super().__init__(f"`iss` from token '{iss}' does not match expected value '{expected}'", token, id_token)
        self.received = iss
        self.expected = expected


class MismatchingIdTokenNonce(InvalidIdToken):
    """Raised on mismatching `nonce` value in an ID Token.

    This happens when the authorization request includes a `nonce` but the returned ID Token include
    a different value.

    """

    def __init__(self, nonce: str, expected: str, token: TokenResponse, id_token: IdToken) -> None:
        super().__init__(f"nonce from token '{nonce}' does not match expected value '{expected}'", token, id_token)
        self.received = nonce
        self.expected = expected


class MismatchingIdTokenAcr(InvalidIdToken):
    """Raised when the returned ID Token doesn't contain one of the requested ACR Values.

    This happens when the authorization request includes an `acr_values` parameter but the returned
    ID Token includes a different value.

    """

    def __init__(self, acr: str, expected: Sequence[str], token: TokenResponse, id_token: IdToken) -> None:
        super().__init__(f"token contains acr '{acr}' while client expects one of '{expected}'", token, id_token)
        self.received = acr
        self.expected = expected


class MismatchingIdTokenAudience(InvalidIdToken):
    """Raised when the ID Token audience does not include the requesting Client ID."""

    def __init__(self, audiences: Sequence[str], client_id: str, token: TokenResponse, id_token: IdToken) -> None:
        super().__init__(
            f"token audience (`aud`) '{audiences}' does not match client_id '{client_id}'", token, id_token
        )
        self.received = audiences
        self.expected = client_id


class MismatchingIdTokenAzp(InvalidIdToken):
    """Raised when the ID Token Authorized Presenter (azp) claim is not the Client ID."""

    def __init__(self, azp: str, client_id: str, token: TokenResponse, id_token: IdToken) -> None:
        super().__init__(
            f"token Authorized Presenter (`azp`) claim '{azp}' does not match client_id '{client_id}'", token, id_token
        )
        self.received = azp
        self.expected = client_id


class MismatchingIdTokenAlg(InvalidIdToken):
    """Raised when the returned ID Token is signed with an unexpected alg."""

    def __init__(self, token_alg: str, client_alg: str, token: TokenResponse, id_token: IdToken) -> None:
        super().__init__(f"token is signed with alg {token_alg}, client expects {client_alg}", token, id_token)
        self.received = token_alg
        self.expected = client_alg


class ExpiredIdToken(InvalidIdToken):
    """Raised when the returned ID Token is expired."""

    def __init__(self, token: TokenResponse, id_token: IdToken) -> None:
        super().__init__("token is expired", token, id_token)
        self.received = id_token.expires_at
        self.expected = datetime.now(tz=timezone.utc)


class UnsupportedIdTokenAlg(InvalidIdToken):
    """Raised when the return ID Token is signed with an unsupported alg."""

    def __init__(self, token: TokenResponse, id_token: IdToken, alg: str) -> None:
        super().__init__(f"token is signed with an unsupported alg {alg}", token, id_token)
        self.alg = alg


class TokenResponse:
    """Base class for Token Endpoint Responses."""

    TOKEN_TYPE: ClassVar[str]


class ExpiredAccessToken(RuntimeError):
    """Raised when an expired access token is used."""


@frozen(init=False)
class BearerToken(TokenResponse, requests.auth.AuthBase):
    """Represents a Bearer Token as returned by a Token Endpoint.

    This is a wrapper around a Bearer Token and associated parameters, such as expiration date and
    refresh token, as returned by an OAuth 2.x or OIDC 1.0 Token Endpoint.

    All parameters are as returned by a Token Endpoint. The token expiration date can be passed as
    datetime in the `expires_at` parameter, or an `expires_in` parameter, as number of seconds in
    the future, can be passed instead.

    Args:
        access_token: an `access_token`, as returned by the AS.
        expires_at: an expiration date. This method also accepts an `expires_in` hint as
            returned by the AS, if any.
        scope: a `scope`, as returned by the AS, if any.
        refresh_token: a `refresh_token`, as returned by the AS, if any.
        token_type: a `token_type`, as returned by the AS.
        id_token: an `id_token`, as returned by the AS, if any.
        **kwargs: additional parameters as returned by the AS, if any.

    """

    TOKEN_TYPE: ClassVar[str] = AccessTokenType.BEARER.value
    AUTHORIZATION_HEADER: ClassVar[str] = "Authorization"

    access_token: str
    expires_at: datetime | None = None
    scope: str | None = None
    refresh_token: str | None = None
    token_type: str = TOKEN_TYPE
    id_token: IdToken | jwskate.JweCompact | None = None
    kwargs: dict[str, Any] = Factory(dict)

    @accepts_expires_in
    def __init__(
        self,
        access_token: str,
        *,
        expires_at: datetime | None = None,
        scope: str | None = None,
        refresh_token: str | None = None,
        token_type: str = TOKEN_TYPE,
        id_token: str | bytes | IdToken | jwskate.JweCompact | None = None,
        **kwargs: Any,
    ) -> None:
        if token_type.title() != self.TOKEN_TYPE.title():
            raise UnsupportedTokenType(token_type)
        id_token_jwt: IdToken | jwskate.JweCompact | None
        if isinstance(id_token, (str, bytes)):
            try:
                id_token_jwt = IdToken(id_token)
            except jwskate.InvalidJwt:
                try:
                    id_token_jwt = jwskate.JweCompact(id_token)
                except jwskate.InvalidJwe:
                    msg = "token is neither a JWT or a JWE."
                    raise InvalidIdToken(msg, self) from None
        else:
            id_token_jwt = id_token
        self.__attrs_init__(
            access_token=access_token,
            expires_at=expires_at,
            scope=scope,
            refresh_token=refresh_token,
            token_type=token_type,
            id_token=id_token_jwt,
            kwargs=kwargs,
        )

    def is_expired(self, leeway: int = 0) -> bool | None:
        """Check if the access token is expired.

        Args:
            leeway: If the token expires in the next given number of seconds,
                then consider it expired already.

        Returns:
            One of:

            - `True` if the access token is expired
            - `False` if it is still valid
            - `None` if there is no expires_in hint.

        """
        if self.expires_at:
            return datetime.now(tz=timezone.utc) + timedelta(seconds=leeway) > self.expires_at
        return None

    def authorization_header(self) -> str:
        """Return the appropriate Authorization Header value for this token.

        The value is formatted correctly according to RFC6750.

        Returns:
            the value to use in an HTTP Authorization Header

        """
        return f"Bearer {self.access_token}"

    def validate_id_token(  # noqa: PLR0915, C901
        self, client: OAuth2Client, azr: AuthorizationResponse, exp_leeway: int = 0, auth_time_leeway: int = 10
    ) -> Self:
        """Validate the ID Token, and return a new instance with the decrypted ID Token.

        If the ID Token was not encrypted, the returned instance will contain the same ID Token.

        This will validate the id_token as described in [OIDC 1.0
        $3.1.3.7](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation).

        Args:
            client: the `OAuth2Client` that was used to obtain this token
            azr: the `AuthorizationResponse`, as obtained by a call to `AuthorizationRequest.validate()`
            exp_leeway: a leeway, in seconds, applied to the ID Token expiration date
            auth_time_leeway: a leeway, in seconds, applied to the `auth_time` validation

        Raises:
            MissingIdToken: if the ID Token is missing
            InvalidIdToken: this is a base exception class, which is raised:

                - if the ID Token is not a JWT
                - or is encrypted while a clear-text token is expected
                - or is clear-text while an encrypted token is expected
                - if token is encrypted but client does not have a decryption key
                - if the token does not contain an `alg` header
            MismatchingIdTokenAlg: if the `alg` header from the ID Token does not match
                the expected `client.id_token_signed_response_alg`.
            MismatchingIdTokenIssuer: if the `iss` claim from the ID Token does not match
                the expected `azr.issuer`.
            MismatchingIdTokenAcr: if the `acr` claim from the ID Token does not match
                on of the expected `azr.acr_values`.
            MismatchingIdTokenAudience: if the `aud` claim from the ID Token does not match
                the expected `client.client_id`.
            MismatchingIdTokenAzp: if the `azp` claim from the ID Token does not match
                the expected `client.client_id`.
            MismatchingIdTokenNonce: if the `nonce` claim from the ID Token does not match
                the expected `azr.nonce`.
            ExpiredIdToken: if the ID Token is expired at the time of the check.
            UnsupportedIdTokenAlg: if the signature alg for the ID Token is not supported.

        """
        if not self.id_token:
            raise MissingIdToken(self)

        raw_id_token = self.id_token

        if isinstance(raw_id_token, jwskate.JweCompact) and client.id_token_encrypted_response_alg is None:
            msg = "token is encrypted while it should be clear-text"
            raise InvalidIdToken(msg, self)
        if isinstance(raw_id_token, IdToken) and client.id_token_encrypted_response_alg is not None:
            msg = "token is clear-text while it should be encrypted"
            raise InvalidIdToken(msg, self)

        if isinstance(raw_id_token, jwskate.JweCompact):
            enc_jwk = client.id_token_decryption_key
            if enc_jwk is None:
                msg = "token is encrypted but client does not have a decryption key"
                raise InvalidIdToken(msg, self)
            nested_id_token = raw_id_token.decrypt(enc_jwk)
            id_token = IdToken(nested_id_token)
        else:
            id_token = raw_id_token

        id_token_alg = id_token.get_header("alg")
        if id_token_alg is None:
            id_token_alg = client.id_token_signed_response_alg
        if id_token_alg is None:
            msg = """
token does not contain an `alg` parameter to specify the signature algorithm,
and no algorithm has been configured for the client (using param `id_token_signed_response_alg`).
"""
            raise InvalidIdToken(msg, self, id_token)
        if client.id_token_signed_response_alg is not None and id_token_alg != client.id_token_signed_response_alg:
            raise MismatchingIdTokenAlg(id_token.alg, client.id_token_signed_response_alg, self, id_token)

        verification_jwk: jwskate.Jwk

        if id_token_alg in jwskate.SignatureAlgs.ALL_SYMMETRIC:
            if not client.client_secret:
                msg = "token is symmetrically signed but this client does not have a Client Secret."
                raise InvalidIdToken(msg, self, id_token)
            verification_jwk = jwskate.SymmetricJwk.from_bytes(client.client_secret, alg=id_token_alg)
            id_token.verify_signature(verification_jwk, alg=id_token_alg)
        elif id_token_alg in jwskate.SignatureAlgs.ALL_ASYMMETRIC:
            if not client.authorization_server_jwks:
                msg = "token is asymmetrically signed but the Authorization Server JWKS is not available."
                raise InvalidIdToken(msg, self, id_token)

            if id_token.get_header("kid") is None:
                msg = """
token does not contain a Key ID (kid) to specify the asymmetric key
to use for signature verification."""
                raise InvalidIdToken(msg, self, id_token)
            try:
                verification_jwk = client.authorization_server_jwks.get_jwk_by_kid(id_token.kid)
            except KeyError:
                msg = f"""\
token is asymmetrically signed but there is no key
with kid='{id_token.kid}' in the Authorization Server JWKS."""
                raise InvalidIdToken(msg, self, id_token) from None

            if id_token_alg not in verification_jwk.supported_signing_algorithms():
                msg = "token is asymmetrically signed but its algorithm is not supported by the verification key."
                raise InvalidIdToken(msg, self, id_token)
        else:
            raise UnsupportedIdTokenAlg(self, id_token, id_token_alg)

        id_token.verify(verification_jwk, alg=id_token_alg)

        if azr.issuer and id_token.issuer != azr.issuer:
            raise MismatchingIdTokenIssuer(id_token.issuer, azr.issuer, self, id_token)

        if id_token.audiences and client.client_id not in id_token.audiences:
            raise MismatchingIdTokenAudience(id_token.audiences, client.client_id, self, id_token)

        if id_token.authorized_party is not None and id_token.authorized_party != client.client_id:
            raise MismatchingIdTokenAzp(id_token.azp, client.client_id, self, id_token)

        if id_token.is_expired(leeway=exp_leeway):
            raise ExpiredIdToken(self, id_token)

        if azr.nonce and id_token.nonce != azr.nonce:
            raise MismatchingIdTokenNonce(id_token.nonce, azr.nonce, self, id_token)

        if azr.acr_values and id_token.acr not in azr.acr_values:
            raise MismatchingIdTokenAcr(id_token.acr, azr.acr_values, self, id_token)

        hash_function = IdToken.hash_method(verification_jwk, id_token_alg)

        at_hash = id_token.get_claim("at_hash")
        if at_hash is not None:
            expected_at_hash = hash_function(self.access_token)
            if expected_at_hash != at_hash:
                msg = f"mismatching 'at_hash' value (expected '{expected_at_hash}', got '{at_hash}')"
                raise InvalidIdToken(msg, self, id_token)

        c_hash = id_token.get_claim("c_hash")
        if c_hash is not None:
            expected_c_hash = hash_function(azr.code)
            if expected_c_hash != c_hash:
                msg = f"mismatching 'c_hash' value (expected '{expected_c_hash}', got '{c_hash}')"
                raise InvalidIdToken(msg, self, id_token)

        s_hash = id_token.get_claim("s_hash")
        if s_hash is not None:
            if azr.state is None:
                msg = "token has a 's_hash' claim but no state was included in the request."
                raise InvalidIdToken(msg, self, id_token)
            expected_s_hash = hash_function(azr.state)
            if expected_s_hash != s_hash:
                msg = f"mismatching 's_hash' value (expected '{expected_s_hash}', got '{s_hash}')"
                raise InvalidIdToken(msg, self, id_token)

        if azr.max_age is not None:
            auth_time = id_token.auth_datetime
            if auth_time is None:
                msg = """
a `max_age` parameter was included in the authorization request,
but the ID Token does not contain an `auth_time` claim.
"""
                raise InvalidIdToken(msg, self, id_token) from None
            auth_age = datetime.now(tz=timezone.utc) - auth_time
            if auth_age.total_seconds() > azr.max_age + auth_time_leeway:
                msg = f"""
user authentication happened too far in the past.
The `auth_time` parameter from the ID Token indicate that
the last Authentication Time was at {auth_time} ({auth_age.total_seconds()} sec ago),
but the authorization request `max_age` parameter specified that it must
be a maximum of {azr.max_age} sec ago.
"""
                raise InvalidIdToken(msg, self, id_token)

        return self.__class__(
            access_token=self.access_token,
            expires_at=self.expires_at,
            scope=self.scope,
            refresh_token=self.refresh_token,
            token_type=self.token_type,
            id_token=id_token,
            **self.kwargs,
        )

    def __str__(self) -> str:
        """Return the access token value, as a string.

        Returns:
            the access token string

        """
        return self.access_token

    def as_dict(self) -> dict[str, Any]:
        """Return a dict of parameters.

        That is suitable for serialization or to init another BearerToken.

        """
        d = asdict(self)
        d.pop("expires_at")
        d["expires_in"] = self.expires_in
        d.update(**d.pop("kwargs", {}))
        return {key: val for key, val in d.items() if val is not None}

    @property
    def expires_in(self) -> int | None:
        """Number of seconds until expiration."""
        if self.expires_at:
            return ceil((self.expires_at - datetime.now(tz=timezone.utc)).total_seconds())
        return None

    def __getattr__(self, key: str) -> Any:
        """Return custom attributes from this BearerToken.

        Args:
            key: a key

        Returns:
            the associated value in this token response

        Raises:
            AttributeError: if the attribute is not found in this response.

        """
        return self.kwargs.get(key) or super().__getattribute__(key)

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        """Implement the usage of Bearer Tokens in requests.

        This will add a properly formatted `Authorization: Bearer <token>` header in the request.

        If the configured token is an instance of BearerToken with an expires_at attribute, raises
        [ExpiredAccessToken][requests_oauth2client.exceptions.ExpiredAccessToken] once the access
        token is expired.

        Args:
            request: the request

        Returns:
            the same request with an Access Token added in `Authorization` Header

        Raises:
            ExpiredAccessToken: if the token is expired

        """
        if self.access_token is None:
            return request  # pragma: no cover
        if self.is_expired():
            raise ExpiredAccessToken(self)
        request.headers[self.AUTHORIZATION_HEADER] = self.authorization_header()
        return request


class BearerTokenSerializer:
    """A helper class to serialize Token Response returned by an AS.

    This may be used to store BearerTokens in session or cookies.

    It needs a `dumper` and a `loader` functions that will respectively serialize and deserialize
    BearerTokens. Default implementations are provided with use gzip and base64url on the serialized
    JSON representation.

    Args:
        dumper: a function to serialize a token into a `str`.
        loader: a function to deserialize a serialized token representation.

    """

    def __init__(
        self,
        dumper: Callable[[BearerToken], str] | None = None,
        loader: Callable[[str], BearerToken] | None = None,
    ) -> None:
        self.dumper = dumper or self.default_dumper
        self.loader = loader or self.default_loader

    @staticmethod
    def default_dumper(token: BearerToken) -> str:
        """Serialize a token as JSON, then compress with deflate, then encodes as base64url.

        Args:
            token: the `BearerToken` to serialize

        Returns:
            the serialized value

        """
        d = asdict(token)
        d.update(**d.pop("kwargs", {}))
        return (
            BinaPy.serialize_to("json", {k: w for k, w in d.items() if w is not None}).to("deflate").to("b64u").ascii()
        )

    def default_loader(self, serialized: str, token_class: type[BearerToken] = BearerToken) -> BearerToken:
        """Deserialize a BearerToken.

        This does the opposite operations than `default_dumper`.

        Args:
            serialized: the serialized token
            token_class: class to use to deserialize the Token

        Returns:
            a BearerToken

        """
        attrs = BinaPy(serialized).decode_from("b64u").decode_from("deflate").parse_from("json")
        expires_at = attrs.get("expires_at")
        if expires_at:
            attrs["expires_at"] = datetime.fromtimestamp(expires_at, tz=timezone.utc)
        return token_class(**attrs)

    def dumps(self, token: BearerToken) -> str:
        """Serialize and compress a given token for easier storage.

        Args:
            token: a BearerToken to serialize

        Returns:
            the serialized token, as a str

        """
        return self.dumper(token)

    def loads(self, serialized: str) -> BearerToken:
        """Deserialize a serialized token.

        Args:
            serialized: the serialized token

        Returns:
            the deserialized token

        """
        return self.loader(serialized)
