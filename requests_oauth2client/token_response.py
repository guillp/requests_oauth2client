import base64
import json
import pprint
import zlib
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Callable, Dict, Optional, Union

if TYPE_CHECKING:
    from .client import OAuth2Client


class BearerToken:
    """
    A wrapper around a Bearer Token and associated expiration date and refresh token,
    as returned by an OAuth20 or OIDC Token Endpoint.
    """

    def __init__(
        self,
        access_token: str,
        expires_at: datetime = None,
        scope: str = None,
        refresh_token: str = None,
        token_type: str = "Bearer",
        **kwargs: Any,
    ):
        if token_type != "Bearer":
            raise ValueError("This is not Bearer Token!", token_type)
        self.access_token = access_token
        self.expires_at = expires_at
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

    def as_dict(self, expires_at: bool = False) -> Dict[str, Any]:
        r: Dict[str, Any] = {
            "access_token": self.access_token,
            "token_type": "Bearer",
        }
        if self.expires_at:
            if expires_at:
                r["expires_at"] = self.expires_at
            else:
                r["expires_in"] = int(self.expires_at.timestamp() - datetime.now().timestamp())
        if self.scope:
            r["scope"] = self.scope
        if self.refresh_token:
            r["refresh_token"] = self.refresh_token
        if self.other:
            r.update(self.other)
        return r

    def __repr__(self) -> str:
        return pprint.pformat(self.as_dict())


class BearerTokenEndpointResponse(BearerToken):
    """
    Like a BearerToken, but includes all the attributes returned by the token endpoint (id_token, etc.)
    """

    def __init__(
        self,
        access_token: str,
        expires_in: int = None,
        token_type: str = "Bearer",
        scope: str = None,
        refresh_token: str = None,
        id_token: str = None,
        client: "OAuth2Client" = None,
        **kwargs: Union[str, int, bool],
    ) -> None:
        if token_type != "Bearer":
            raise ValueError("token types other than Bearer are not supported")
        expires_at = None
        if expires_in:
            expires_at = datetime.now() + timedelta(seconds=expires_in)
        super().__init__(access_token, expires_at, scope, refresh_token, token_type, **kwargs)
        self.client = client
        self._id_token = id_token

    def as_dict(self, expires_at: bool = False) -> Dict[str, Any]:
        r = super().as_dict(expires_at)
        if self._id_token:
            r["id_token"] = self._id_token
        return r

    @classmethod
    def from_requests_response(cls, client, resp):
        return cls(client=client, **resp.json())


class TokenSerializer:
    def __init__(
        self,
        dumper: Callable[[BearerToken], str] = None,
        loader: Callable[[str], BearerToken] = None,
        token_class=BearerToken,
    ):
        self.token_class = token_class
        self.dumper = dumper or self._default_dumper
        self.loader = loader or self._default_loader

    def _default_dumper(self, token: BearerToken) -> str:
        return base64.urlsafe_b64encode(
            zlib.compress(
                json.dumps(
                    token.as_dict(True), default=lambda d: d.strftime("%Y-%m-%dT%H:%M:%S")
                ).encode()
            )
        ).decode()

    def _default_loader(self, serialized: str) -> BearerToken:
        attrs = json.loads(zlib.decompress(base64.urlsafe_b64decode(serialized)).decode())
        expires_at = attrs.get("expires_at")
        if expires_at:
            attrs["expires_at"] = datetime.strptime(expires_at, "%Y-%m-%dT%H:%M:%S")
        return self.token_class(**attrs)

    def dumps(self, token: BearerToken) -> str:
        """Serialize and compress a given token for easier storage"""
        return self.dumper(token)

    def loads(self, serialized: str) -> BearerToken:
        return self.loader(serialized)
