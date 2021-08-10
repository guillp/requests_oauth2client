from typing import Any, Optional

from flask import session

from ..auth import OAuth2ClientCredentialsAuth
from ..client import OAuth2Client
from ..token_response import BearerToken, TokenSerializer


class FlaskSessionAuthMixin:
    """
    A Mixin for auth handlers to store their tokens in Flask session.
    This way, each user of a Flask application has a different access token.
    """

    def __init__(self, session_key: str, serializer: Optional[TokenSerializer] = None):
        self.serializer = serializer or TokenSerializer()
        self.session_key = session_key

    @property
    def token(self) -> Optional[BearerToken]:
        serialized_token = session.get(self.session_key)
        if serialized_token is None:
            return None
        return self.serializer.loads(serialized_token)

    @token.setter
    def token(self, token: Optional[BearerToken]) -> None:
        if token:
            serialized_token = self.serializer.dumps(token)
            session[self.session_key] = serialized_token
        else:
            session.pop(self.session_key, None)


class FlaskOAuth2ClientCredentialsAuth(FlaskSessionAuthMixin, OAuth2ClientCredentialsAuth):
    """
    A Requests Authentication handler that automatically gets access tokens from an OAuth20 Token Endpoint
    with the Client Credentials grant (and can get a new one once it is expired),
    and stores the retrieved token in Flask `session`, so that each user has a different access token.
    """

    def __init__(
        self,
        client: OAuth2Client,
        session_key: str,
        serializer: Optional[TokenSerializer] = None,
        **token_kwargs: Any,
    ) -> None:
        super().__init__(session_key, serializer)
        self.client = client
        self.token_kwargs = token_kwargs
