"""Helper classes for the [Flask](https://flask.palletsprojects.com) framework."""

from typing import Any, Optional

from flask import session

from ..auth import OAuth2ClientCredentialsAuth
from ..client import OAuth2Client
from ..tokens import BearerToken, BearerTokenSerializer


class FlaskSessionAuthMixin:
    """A Mixin for auth handlers to store their tokens in Flask session.

    Storing tokens in Flask session does ensure that each user of a Flask application has a different access token, and that tokens will be persisted between multiple requests to the front-end Flask app.

    Args:
        session_key: the key that will be used to store the access token in session.
        serializer: the serializer that will be used to store the access token in session.
    """

    def __init__(self, session_key: str, serializer: Optional[BearerTokenSerializer] = None):
        self.serializer = serializer or BearerTokenSerializer()
        self.session_key = session_key

    @property
    def token(self) -> Optional[BearerToken]:
        """Return the Access Token stored in session.

        Returns:
            The current BearerToken for this session, if any.
        """
        serialized_token = session.get(self.session_key)
        if serialized_token is None:
            return None
        return self.serializer.loads(serialized_token)

    @token.setter
    def token(self, token: Optional[BearerToken]) -> None:
        """Store an Access Token in session.

        Args:
            token: the token to store
        """
        if token:
            serialized_token = self.serializer.dumps(token)
            session[self.session_key] = serialized_token
        else:
            session.pop(self.session_key, None)


class FlaskOAuth2ClientCredentialsAuth(FlaskSessionAuthMixin, OAuth2ClientCredentialsAuth):
    """A `requests` Auth handler for CC that stores its token in Flask session.

    It will automatically gets access tokens from an OAuth 2.x Token Endpoint
    with the Client Credentials grant (and can get a new one once it is expired),
    and stores the retrieved token in Flask `session`, so that each user has a different access token.

    Args:
        client: an OAuth2Client that will be used to retrieve tokens.
        session_key: the key that will be used to store the access token in Flask session
        serializer: a serializer that will be used to serialize the access token in Flask session
        **token_kwargs: additional kwargs for the Token Request
    """

    def __init__(
        self,
        client: OAuth2Client,
        session_key: str,
        serializer: Optional[BearerTokenSerializer] = None,
        **token_kwargs: Any,
    ) -> None:
        super().__init__(session_key, serializer)
        self.client = client
        self.token_kwargs = token_kwargs
