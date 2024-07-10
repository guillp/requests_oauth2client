"""Helper classes for the [Flask](https://flask.palletsprojects.com) framework."""

from __future__ import annotations

from typing import Any

from flask import session

from requests_oauth2client.auth import OAuth2ClientCredentialsAuth
from requests_oauth2client.tokens import BearerToken, BearerTokenSerializer


class FlaskSessionAuthMixin:
    """A Mixin for auth handlers to store their tokens in Flask session.

    Storing tokens in Flask session does ensure that each user of a Flask application has a
    different access token, and that tokens used for backend API access will be persisted between
    multiple requests to the front-end Flask app.

    Args:
        session_key: the key that will be used to store the access token in session.
        serializer: the serializer that will be used to store the access token in session.

    """

    def __init__(
        self,
        session_key: str,
        serializer: BearerTokenSerializer | None = None,
        *args: Any,
        **token_kwargs: Any,
    ) -> None:
        super().__init__(*args, **token_kwargs)
        self.serializer = serializer or BearerTokenSerializer()
        self.session_key = session_key

    @property
    def token(self) -> BearerToken | None:
        """Return the Access Token stored in session.

        Returns:
            The current `BearerToken` for this session, if any.

        """
        serialized_token = session.get(self.session_key)
        if serialized_token is None:
            return None
        return self.serializer.loads(serialized_token)

    @token.setter
    def token(self, token: BearerToken | str | None) -> None:
        """Store an Access Token in session.

        Args:
            token: the token to store

        """
        if isinstance(token, str):
            token = BearerToken(token)  # pragma: no cover
        if token:
            serialized_token = self.serializer.dumps(token)
            session[self.session_key] = serialized_token
        elif session and self.session_key in session:
            session.pop(self.session_key, None)


class FlaskOAuth2ClientCredentialsAuth(FlaskSessionAuthMixin, OAuth2ClientCredentialsAuth):  # type: ignore[misc]
    """A `requests` Auth handler for CC grant that stores its token in Flask session.

    It will automatically get Access Tokens from an OAuth 2.x AS with the Client Credentials grant
    (and can get a new one once the first one is expired), and stores the retrieved token,
    serialized in Flask `session`, so that each user has a different access token.

    """
