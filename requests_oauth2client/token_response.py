from __future__ import annotations

import pprint
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Union


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
        Returns the access token
        :return: the access token string
        """
        return self.access_token

    def as_dict(self) -> Dict[str, Any]:
        r: Dict[str, Any] = {
            "access_token": self.access_token,
            "token_type": "Bearer",
        }
        if self.expires_at:
            r["expires_in"] = int(self.expires_at.timestamp() - datetime.now().timestamp())
        if self.scope:
            r["scope"] = self.scope
        if self.refresh_token:
            r["refresh_token"] = self.refresh_token
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
        **kwargs: Union[str, int, bool],
    ) -> None:
        if token_type != "Bearer":
            raise ValueError("token types other than Bearer are not supported")
        if expires_in:
            expires_at = datetime.now() + timedelta(seconds=expires_in)
        super().__init__(access_token, expires_at, scope, refresh_token, token_type, **kwargs)
        self._id_token = id_token

    def id_token(self):
        # TODO: parse the id token
        return self._id_token

    def as_dict(self) -> Dict[str, Any]:
        r = super().as_dict()
        if self._id_token:
            r["id_token"] = self._id_token
        if self.other:
            r.update(self.other)
        return r
