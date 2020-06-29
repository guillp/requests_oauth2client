from datetime import datetime, timedelta

from .auth import BearerToken


class TokenResponse:
    def __init__(
            self,
            access_token,
            expires_in=None,
            token_type="Bearer",
            scope=None,
            refresh_token=None,
            id_token=None,
            **kwargs,
    ):
        self._access_token = access_token
        self.expires_at = None
        if expires_in:
            self.expires_at = datetime.now() + timedelta(seconds=expires_in)
        self.token_type = token_type
        self.scope = scope
        self.refresh_token = refresh_token
        self._id_token = id_token
        self.other = kwargs

    def access_token(self):
        if self.token_type == "Bearer":
            return BearerToken(
                self._access_token,
                expires_at=self.expires_at,
                refresh_token=self.refresh_token,
            )
        raise ValueError("Unsupported token type!", self._token_type)

    def id_token(self):
        return self._id_token
