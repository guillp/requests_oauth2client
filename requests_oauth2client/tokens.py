"""This modules contain classes that represent Tokens used in OAuth2.0 / OIDC."""

import pprint
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Callable, Dict, Optional, Type, Union

from binapy import BinaPy
from jwskate import (
    InvalidJwe,
    InvalidJwt,
    JweCompact,
    Jwt,
    SignatureAlgs,
    SignedJwt,
    SymmetricJwk,
)

from .exceptions import (
    ExpiredIdToken,
    InvalidIdToken,
    MismatchingAcr,
    MismatchingAudience,
    MismatchingAzp,
    MismatchingIdTokenAlg,
    MismatchingIssuer,
    MismatchingNonce,
    MissingIdToken,
)
from .utils import accepts_expires_in

if TYPE_CHECKING:
    from .authorization_request import AuthorizationResponse
    from .client import OAuth2Client


class IdToken(SignedJwt):
    """Represent an ID Token.

    An ID Token is actually a Signed JWT. If the ID Token is encrypted, it must be decoded
    beforehand.
    """


class BearerToken:
    """Represents a Bearer Token as returned by a Token Endpoint.

    This is a wrapper around a Bearer Token and associated parameters,
    such as expiration date and refresh token, as returned by an OAuth 2.x or OIDC 1.0 Token Endpoint.

    All parameters are as returned by a Token Endpoint. The token expiration date can be passed as datetime
    in the `expires_at` parameter, or an `expires_in` parameter, as number of seconds in the future, can be passed instead.

    Args:
        access_token: an `access_token`, as returned by the AS.
        expires_at: an expiration date. This method also accepts an `expires_in` hint as returned by the AS, if any.
        scope: a `scope`, as returned by the AS, if any.
        refresh_token: a `refresh_token`, as returned by the AS, if any.
        token_type: a `token_type`, as returned by the AS.
        id_token: an `id_token`, as returned by the AS, if any.
        **kwargs: additional parameters as returned by the AS, if any.
    """

    @accepts_expires_in
    def __init__(
        self,
        access_token: str,
        *,
        expires_at: Optional[datetime] = None,
        scope: Optional[str] = None,
        refresh_token: Optional[str] = None,
        token_type: str = "Bearer",
        id_token: Optional[str] = None,
        **kwargs: Any,
    ):
        if token_type.title() != "Bearer":
            raise ValueError("This is not a Bearer Token!", token_type)
        self.access_token = access_token
        self.expires_at = expires_at
        self.scope = scope
        self.refresh_token = refresh_token
        self.id_token: Union[IdToken, JweCompact, None] = None
        if id_token:
            try:
                self.id_token = IdToken(id_token)
            except InvalidJwt:
                try:
                    self.id_token = JweCompact(id_token)
                except InvalidJwe:
                    raise InvalidIdToken(
                        "ID Token is invalid because it is  neither a JWT or a JWE."
                    )
        self.other = kwargs

    def is_expired(self, leeway: int = 0) -> Optional[bool]:
        """Check if the access token is expired.

        Args:
            leeway: If the token expires in the next given number of seconds, then consider it expired already.

        Returns:
            `True` if the access token is expired, `False` if it is still valid, `None` if there is no expires_in hint.
        """
        if self.expires_at:
            return datetime.now() - timedelta(seconds=leeway) > self.expires_at
        return None

    def authorization_header(self) -> str:
        """Return the appropriate Authorization Header value for this token.

        The value is formatted correctly according to RFC6750.

        Returns:
            the value to use in a HTTP Authorization Header
        """
        return f"Bearer {self.access_token}"

    def validate_id_token(  # noqa: C901
        self, client: "OAuth2Client", azr: "AuthorizationResponse"
    ) -> IdToken:
        """Validate that a token response is valid, and return the ID Token.

        This will validate the id_token as described
        in [OIDC 1.0 $3.1.3.7](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation).

        If the ID Token was encrypted, this decrypts it and returns the clear-text ID Token.
        """
        if not self.id_token:
            raise MissingIdToken()

        id_token = self.id_token

        id_token_encrypted_response_alg = client.extra_metadata.get(
            "id_token_encrypted_response_alg"
        )
        if isinstance(id_token, JweCompact):
            if id_token_encrypted_response_alg is None:
                raise InvalidIdToken(
                    "ID Token is encrypted while it should be clear-text", self
                )
        else:
            if id_token_encrypted_response_alg is not None:
                raise InvalidIdToken(
                    "ID Token is clear-text while it should be encrypted", self
                )

        if isinstance(id_token, JweCompact):
            enc_jwk = client.id_token_decryption_key
            if enc_jwk is None:
                raise InvalidIdToken(
                    "ID Token is encrypted but client does not have a decryption key", self
                )
            nested_id_token = id_token.decrypt(enc_jwk)
            id_token = IdToken(nested_id_token)

        if azr.issuer:
            if id_token.issuer != azr.issuer:
                raise MismatchingIssuer(id_token.issuer, azr.issuer, self)

        if id_token.audiences and client.client_id not in id_token.audiences:
            raise MismatchingAudience(id_token.audiences, client.client_id, self)

        if id_token.get_claim("azp") is not None and id_token.azp != client.client_id:
            raise MismatchingAzp(id_token.azp, client.client_id, self)

        id_token_signed_response_alg = client.extra_metadata.get("id_token_signed_response_alg")
        if (
            id_token_signed_response_alg is not None
            and id_token.alg != id_token_signed_response_alg
        ):
            raise MismatchingIdTokenAlg(id_token.alg, id_token_signed_response_alg)

        if id_token.alg in SignatureAlgs.ALL_SYMMETRIC:
            if not client.client_secret:
                raise InvalidIdToken(
                    "Returned ID Token is symmetrically signed but this client does not have a Client ID."
                )
            id_token.verify_signature(SymmetricJwk.from_bytes(client.client_secret))

        if id_token.is_expired():
            raise ExpiredIdToken(id_token)

        if azr.nonce:
            if id_token.nonce != azr.nonce:
                raise MismatchingNonce()

        if azr.acr_values:
            if id_token.acr not in azr.acr_values:
                raise MismatchingAcr(id_token.acr, azr.acr_values)

        if id_token.get_claim("at_hash"):
            pass
            # TODO

        return id_token

    def __str__(self) -> str:
        """Return the access token value, as a string.

        Returns:
            the access token string
        """
        return self.access_token

    def __contains__(self, key: str) -> bool:
        """Check existence of a key in the token response.

        Allows testing like `assert "refresh_token" in token_response`.

        Args:
            key: a key

        Returns:
            `True` if the key exists in the token response, `False` otherwise
        """
        if key == "access_token":
            return True
        elif key == "refresh_token":
            return self.refresh_token is not None
        elif key == "scope":
            return self.scope is not None
        elif key == "token_type":
            return True
        elif key == "expires_in":
            return self.expires_at is not None
        else:
            return key in self.other

    def __getattr__(self, key: str) -> Any:
        """Return attributes from this BearerToken.

        Allows `token_response.expires_in` or `token_response.any_custom_attribute`.

        Args:
            key: a key

        Returns:
            the associated value in this token response

        Raises:
            AttributeError: if the attribute is not found in this response.
        """
        if key == "expires_in":
            if self.expires_at is None:
                return None
            return int(self.expires_at.timestamp() - datetime.now().timestamp())
        elif key == "token_type":
            return "Bearer"
        return self.other.get(key) or super().__getattribute__(key)

    def __getitem__(self, key: str) -> Any:
        """Allow subscription access to any attribute from this BearerToken.

        This is useful is some key name returned by the AS is not valid as
        attribute name (e.g. it contains special characters).

        Args:
            key: a key

        Returns:
            the associated value in this token response

        Raises:
            KeyError: if the attribute is not found in this response.
        """
        try:
            return self.__getattr__(key)
        except AttributeError as exc:
            raise KeyError(key) from exc

    def as_dict(self, expires_at: bool = False) -> Dict[str, Any]:
        """Return all attributes from this BearerToken as a `dict`.

        Args:
            expires_at: if `True`, the dict will contain an extra `expires_at` field with the token expiration date.

        Returns
            a `dict` containing this BearerToken attributes.
        """
        r: Dict[str, Any] = {
            "access_token": self.access_token,
            "token_type": "Bearer",
        }
        if self.expires_at:
            r["expires_in"] = self.expires_in
            if expires_at:
                r["expires_at"] = self.expires_at
        if self.scope:
            r["scope"] = self.scope
        if self.refresh_token:
            r["refresh_token"] = self.refresh_token
        if self.other:
            r.update(self.other)
        return r

    def __repr__(self) -> str:
        """Return a representation of this BearerToken.

        This representation is a pretty formatted `dict` that looks like a Token Endpoint response.

        Returns:
            a `str` representation of this BearerToken.
        """
        return pprint.pformat(self.as_dict())

    def __eq__(self, other: object) -> bool:
        """Check if this BearerToken is equal to another.

        It supports comparison with another BearerToken, or with an `access_token` as `str`.

        Args:
            other: another token to compare to

        Returns:
            `True` if equal, `False` otherwise
        """
        if isinstance(other, BearerToken):
            return (
                self.access_token == other.access_token
                and self.refresh_token == other.refresh_token
                and self.expires_at == other.expires_at
                and self.token_type == other.token_type
            )
        elif isinstance(other, str):
            return self.access_token == other
        return super().__eq__(other)


class BearerTokenSerializer:
    """An helper class to serialize Token Response returned by an AS.

    This may be used to store BearerTokens in session or cookies.

    It needs a `dumper` and a `loader` functions that will respectively serialize and deserialize BearerTokens.
    Default implementations are provided with use gzip and base64url on the serialized JSON representation.

    Args:
        dumper: a function to serialize a token into a `str`.
        loader: a function do deserialize a serialized token representation.
    """

    def __init__(
        self,
        dumper: Optional[Callable[[BearerToken], str]] = None,
        loader: Optional[Callable[[str], BearerToken]] = None,
    ):
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
        return BinaPy.serialize_to("json", token.as_dict(True)).to("deflate").to("b64u").ascii()

    def default_loader(
        self, serialized: str, token_class: Type[BearerToken] = BearerToken
    ) -> BearerToken:
        """Deserialize a BearerToken.

        This does the opposite operations than `default_dumper`.

        Args:
            serialized: the serialized token

        Returns:
            a BearerToken
        """
        attrs = BinaPy(serialized).decode_from("b64u").decode_from("deflate").parse_from("json")
        expires_at = attrs.get("expires_at")
        if expires_at:
            attrs["expires_at"] = datetime.fromtimestamp(expires_at)
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
