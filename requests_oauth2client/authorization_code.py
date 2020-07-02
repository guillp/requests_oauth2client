from __future__ import annotations

import base64
import hashlib
import re
import secrets
from collections import Iterable
from typing import Any, Union

from furl import furl  # type: ignore[import]


class PkceHelper:
    """
    Contains helper methods for PKCE
    """

    code_verifier_re = re.compile(r"([a-zA-Z1-9_\-~\.]){43,128}")

    @classmethod
    def generate_code_verifier(cls) -> str:
        """
        Generate a valid code_verifier
        :return:
        """
        return secrets.token_urlsafe(64)

    @classmethod
    def derive_challenge_S256(cls, verifier: Union[str, bytes]) -> str:
        """
        Derives the code_challenge from a given code_verifier
        :param verifier:
        :return:
        """
        if not isinstance(verifier, bytes):
            verifier = verifier.encode()
        return base64.urlsafe_b64encode(hashlib.sha256(verifier).digest()).rstrip(b"=").decode()


class AuthorizationCodeHandler:
    """
    A state machine for the Authorization Request and response.
    It generates a valid Authorization Requests (possibly with a state, none, PKCE, and custom args),
    and validates the response received as callback.
    """

    def __init__(
        self,
        authorization_endpoint: str,
        client_id: str,
        redirect_uri: str,
        scope: str,
        response_type: str = "code",
        state: Union[str, bool] = True,
        nonce: str = None,
        code_verifier: str = None,
        code_challenge_S256: bool = True,
        **kwargs: Any,
    ) -> None:
        if state is True:
            state = secrets.token_urlsafe(32)
        if nonce is True:
            nonce = secrets.token_urlsafe(32)
        if not isinstance(scope, str):
            if isinstance(scope, Iterable):
                scope = "+".join(scope)
        args = dict(
            client_id=client_id,
            redirect_uri=redirect_uri,
            response_type=response_type,
            state=state,
            nonce=nonce,
            scope=scope,
            **kwargs,
        )
        if code_verifier:
            if code_challenge_S256 is True:
                code_challenge = PkceHelper.derive_challenge_S256(code_verifier)
                args["code_challenge"] = code_challenge
                args["code_challenge_method"] = "S256"
            else:
                args["code_challenge"] = code_verifier
                args["code_challenge_method"] = "plain"
        self.request = furl(
            authorization_endpoint,
            args={key: value for key, value in args.items() if value is not None},
        )

    def validate_callback(self, response: str) -> str:
        response_url = furl(response)
        requested_state = self.request.args["state"]
        if requested_state:
            received_state = response_url.args.get("state")
            if requested_state != received_state:
                raise ValueError(
                    f"mismatching state values! (expected '{requested_state}', got '{received_state}')"
                )
        code: str = response_url.args.get("code")
        if code is None:
            raise ValueError("missing code in callback!")
        return code
