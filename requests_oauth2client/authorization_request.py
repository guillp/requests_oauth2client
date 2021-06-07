import hashlib
import re
import secrets
from collections.abc import Iterable
from typing import Any, Optional, Union

from furl import furl  # type: ignore[import]

from requests_oauth2client.utils import b64u_encode


class PkceUtils:
    """
    Contains helper methods for PKCE
    """

    code_verifier_re = re.compile(r"^[a-zA-Z0-9_\-~\.]{43,128}$")

    @classmethod
    def generate_code_verifier(cls) -> str:
        """
        Generate a valid code_verifier
        :return: a code_verifier to use
        """
        return secrets.token_urlsafe(96)

    @classmethod
    def derive_challenge(cls, verifier: Union[str, bytes], method="S256") -> str:
        """
        Derives the code_challenge from a given code_verifier
        :param verifier: a code verifier
        :return: a code_challenge derived from the given verifier
        """
        if not isinstance(verifier, bytes):
            if not cls.code_verifier_re.match(verifier):
                raise ValueError(
                    f"Invalid code verifier, does not match {cls.code_verifier_re}", verifier
                )
            verifier = verifier.encode()
        else:
            if not cls.code_verifier_re.match(verifier.decode()):
                raise ValueError(
                    f"Invalid code verifier, does not match {cls.code_verifier_re}", verifier
                )
        if method == "S256":
            return b64u_encode(hashlib.sha256(verifier).digest())
        elif method == "plain":
            return b64u_encode(verifier)
        else:
            raise ValueError("Unsupported code_challenge_method", method)

    @classmethod
    def generate_code_verifier_and_challenge(cls, method="S256") -> (str, str):
        """
        Generate a valid code_verifier
        :return:
        """
        verifier = cls.generate_code_verifier()
        challenge = cls.derive_challenge(verifier, method)
        return verifier, challenge

    @classmethod
    def validate_code_verifier(cls, verifier, challenge, method="S256") -> bool:
        """
        Validates a verifier against a challenge
        :param verifier: the code_verifier, exactly as submitted by the client on toker request
        :param challenge: the code_challenge, exactly as submitted by the client on authorization request
        :return: True if verifier is valid, False, otherwise
        """
        return (
            cls.code_verifier_re.match(verifier)
            and cls.derive_challenge(verifier, method) == challenge
        )


class AuthorizationRequest:
    """
    A state machine for the Authorization Request and response.
    It generates a valid Authorization Requests (possibly with a state, none, PKCE, and custom args),
    stores all OAuth/OIDC related request specific values (state, nonce, code_verifier, code_challenge,
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
        code_challenge_method: Optional[str] = "S256",
        **kwargs: Any,
    ) -> None:
        if state is True:
            state = secrets.token_urlsafe(32)
        if nonce is True:
            nonce = secrets.token_urlsafe(32)
        if not isinstance(scope, str):
            if isinstance(scope, Iterable):
                scope = "+".join(scope)

        if not code_challenge_method:
            code_verifier = code_challenge = code_challenge_method = None
        else:
            if not code_verifier:
                code_verifier = PkceUtils.generate_code_verifier()
            code_challenge = PkceUtils.derive_challenge(code_verifier, code_challenge_method)

        self.state = state
        self.nonce = nonce
        self.code_verifier = code_verifier
        self.code_challenge = code_challenge
        self.code_challenge_method = code_challenge_method

        args = dict(
            client_id=client_id,
            redirect_uri=redirect_uri,
            response_type=response_type,
            state=state,
            nonce=nonce,
            scope=scope,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            **kwargs,
        )

        self.request = furl(
            authorization_endpoint,
            args={key: value for key, value in args.items() if value is not None},
        )

    def validate_callback(self, response: str) -> str:
        response_url = furl(response)
        requested_state = self.state
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

    def __repr__(self):
        return str(self.request)
