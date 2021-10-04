import json
import pprint
import zlib
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, Optional, Type

from .jwskate import SignedJwt
from .utils import accepts_expires_in, b64u_decode, b64u_encode


class BearerToken:
    """
    A wrapper around a Bearer Token and associated expiration date and refresh token,
    as returned by an OAuth 2.x or OIDC 1.0 Token Endpoint.
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
        self.id_token = IdToken(id_token) if id_token else None
        self.other = kwargs

    def is_expired(self, leeway: int = 0) -> Optional[bool]:
        """
        Returns `True` if the access token is expired at the time of the call.
        :param leeway: If the token expires in the next given number of seconds, then consider it expired already.
        :return: `True` if the access token is expired, `False` if it is still valid, `None` if there is no expires_in
        hint.
        """
        if self.expires_at:
            return datetime.now() - timedelta(seconds=leeway) > self.expires_at
        return None

    def authorization_header(self) -> str:
        """
        Returns the Authorization Header value containing this access token, correctly formatted according to RFC6750.
        :return: the value to use in a HTTP Authorization Header
        """
        return f"Bearer {self.access_token}"

    def __str__(self) -> str:
        """
        Returns the access token value, as a string
        :return: the access token string
        """
        return self.access_token

    def __contains__(self, key: str) -> bool:
        """
        Check existence of a key in the token response.
        Allows testing like `assert "refresh_token" in token_response`.
        :param key: a key
        :return: True if the key exists in the token response, False otherwise
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
        """
        Returns items from this BearerToken.
        Allows `token_response.expires_in` or `token_response.any_custom_attribute`
        :param key: a key
        :return: the associated value in this token response
        :raises AttributeError: if the attribute is not found in this response.
        """
        if key == "expires_in":
            if self.expires_at is None:
                return None
            return int(self.expires_at.timestamp() - datetime.now().timestamp())
        elif key == "token_type":
            return "Bearer"
        return self.other.get(key) or super().__getattribute__(key)

    def as_dict(self, expires_at: bool = False) -> Dict[str, Any]:
        r: Dict[str, Any] = {
            "access_token": self.access_token,
            "token_type": "Bearer",
        }
        if self.expires_at:
            if expires_at:
                r["expires_at"] = self.expires_at
            else:
                r["expires_in"] = self.expires_in
        if self.scope:
            r["scope"] = self.scope
        if self.refresh_token:
            r["refresh_token"] = self.refresh_token
        if self.other:
            r.update(self.other)
        return r

    def __repr__(self) -> str:
        return pprint.pformat(self.as_dict())

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, BearerToken)
            and self.access_token == other.access_token
            and self.refresh_token == other.refresh_token
            and self.expires_at == other.expires_at
            and self.token_type == other.token_type
        )


class BearerTokenSerializer:
    """
    An helper class to serialize Tokens. This may be used to store BearerTokens in session or cookies.
    """

    def __init__(
        self,
        dumper: Optional[Callable[[BearerToken], str]] = None,
        loader: Optional[Callable[[str], BearerToken]] = None,
        token_class: Type[BearerToken] = BearerToken,
    ):
        self.token_class = token_class
        self.dumper = dumper or self.default_dumper
        self.loader = loader or self.default_loader

    @staticmethod
    def default_dumper(token: BearerToken) -> str:
        """
        Serializes as JSON, encodes as base64url of zlib compression of JSON representation of the Access Token,
        with expiration date represented as expires_at.
        :param token: the :class:`BearerToken` to serialize
        :return: the serialized value
        """
        return b64u_encode(
            zlib.compress(
                json.dumps(
                    token.as_dict(True), default=lambda d: d.timestamp()
                ).encode()
            )
        )

    def default_loader(
        self, serialized: str, token_class: Type[BearerToken] = BearerToken
    ) -> BearerToken:
        """
        Default deserializer for tokens.
        :param serialized: the serialized token
        :return: a BearerToken
        """
        attrs = json.loads(zlib.decompress(b64u_decode(serialized)))
        expires_at = attrs.get("expires_at")
        if expires_at:
            attrs["expires_at"] = datetime.fromtimestamp(expires_at)
        return token_class(**attrs)

    def dumps(self, token: BearerToken) -> str:
        """
        Serialize and compress a given token for easier storage
        :param token: a BearerToken to serialize
        :return: the serialized token, as a str
        """
        return self.dumper(token)

    def loads(self, serialized: str) -> BearerToken:
        """
        Deserialize a serialized token
        :param serialized: the serialized token
        :return: the deserialized token
        """
        return self.loader(serialized)


class IdToken(SignedJwt):
    pass
