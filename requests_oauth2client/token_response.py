import base64
import json
import pprint
import zlib
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, Optional, Type


class BearerToken:
    """
    A wrapper around a Bearer Token and associated expiration date and refresh token,
    as returned by an OAuth20 or OIDC Token Endpoint.
    """

    def __init__(
        self,
        access_token: str,
        expires_in: Optional[int] = None,
        expires_at: Optional[datetime] = None,
        scope: Optional[str] = None,
        refresh_token: Optional[str] = None,
        token_type: str = "Bearer",
        **kwargs: Any,
    ):
        if token_type != "Bearer":
            raise ValueError("This is not a Bearer Token!", token_type)
        self.access_token = access_token
        self.expires_at: Optional[datetime]
        if expires_at:
            self.expires_at = expires_at
        elif expires_in:
            self.expires_at = datetime.now() + timedelta(seconds=expires_in)
        else:
            self.expires_at = None
        self.scope = scope
        self.refresh_token = refresh_token
        self.other = kwargs

    def is_expired(self) -> Optional[bool]:
        """
        Returns true if the access token is expired at the time of the call.
        :return:
        """
        if self.expires_at:
            return datetime.now() > self.expires_at
        return None

    def authorization_header(self) -> str:
        """
        Returns the Authorization Header value containing this access token, correctly formatted as per RFC6750.
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
            raise ValueError("token_type is always Bearer, explicitly or implicitly")
        elif key == "expires_in":
            return self.expires_at is not None
        elif key is None:
            return False
        else:
            return key in self.other

    def __getattr__(self, key: str) -> Any:
        """
        Returns items from this Token Response.
        Allows `token_response.expires_in` or `token_response.any_custom_attribute`
        :param key: a key
        :return: the associated value in this token response
        :raises:
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


class TokenSerializer:
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
        return base64.urlsafe_b64encode(
            zlib.compress(
                json.dumps(
                    token.as_dict(True), default=lambda d: d.strftime("%Y-%m-%dT%H:%M:%S")
                ).encode()
            )
        ).decode()

    def default_loader(
        self, serialized: str, token_class: Type[BearerToken] = BearerToken
    ) -> BearerToken:
        """
        Default deserializer for tokens.
        :param serialized: the serialized token
        :return: a
        """
        attrs = json.loads(zlib.decompress(base64.urlsafe_b64decode(serialized)).decode())
        expires_at = attrs.get("expires_at")
        if expires_at:
            attrs["expires_at"] = datetime.strptime(expires_at, "%Y-%m-%dT%H:%M:%S")
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
