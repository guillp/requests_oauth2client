import hashlib
import re
import secrets
from typing import Any, Dict, Iterable, Optional, Tuple, Type, Union

from furl import furl  # type: ignore[import]

from .exceptions import (AuthorizationResponseError, ConsentRequired,
                         InteractionRequired, LoginRequired, MismatchingState,
                         MissingAuthCode, SessionSelectionRequired)
from .jwskate import Jwk, Jwt
from .utils import b64u_encode


class PkceUtils:
    """
    Contains helper methods for PKCE
    """

    code_verifier_re = re.compile(r"^[a-zA-Z0-9_\-~.]{43,128}$")

    @classmethod
    def generate_code_verifier(cls) -> str:
        """
        Generate a valid code_verifier
        :return: a code_verifier to use
        """
        return secrets.token_urlsafe(96)

    @classmethod
    def derive_challenge(cls, verifier: Union[str, bytes], method: str = "S256") -> str:
        """
        Derives the code_challenge from a given code_verifier
        :param verifier: a code verifier
        :return: a code_challenge derived from the given verifier
        """
        if isinstance(verifier, bytes):
            verifier = verifier.decode()

        if not cls.code_verifier_re.match(verifier):
            raise ValueError(
                f"Invalid code verifier, does not match {cls.code_verifier_re}", verifier
            )

        if method == "S256":
            return b64u_encode(hashlib.sha256(verifier.encode()).digest())
        elif method == "plain":
            return verifier
        else:
            raise ValueError("Unsupported code_challenge_method", method)

    @classmethod
    def generate_code_verifier_and_challenge(cls, method: str = "S256") -> Tuple[str, str]:
        """
        Generate a valid code_verifier
        :return:
        """
        verifier = cls.generate_code_verifier()
        challenge = cls.derive_challenge(verifier, method)
        return verifier, challenge

    @classmethod
    def validate_code_verifier(
        cls, verifier: str, challenge: str, method: str = "S256"
    ) -> bool:
        """
        Validates a verifier against a challenge
        :param verifier: the code_verifier, exactly as submitted by the client on toker request
        :param challenge: the code_challenge, exactly as submitted by the client on authorization request
        :return: True if verifier is valid, False, otherwise
        """
        return (
            cls.code_verifier_re.match(verifier) is not None
            and cls.derive_challenge(verifier, method) == challenge
        )


class AuthorizationRequest:
    """
    A state machine for the Authorization Request and response.
    It generates a valid Authorization Requests (possibly with a state, none, PKCE, and custom args),
    stores all OAuth/OIDC related request specific values (state, nonce, code_verifier, code_challenge,
    and validates the response received as callback.
    """

    exception_classes: Dict[str, Type[Exception]] = {
        "interaction_required": InteractionRequired,
        "login_required": LoginRequired,
        "session_selection_required": SessionSelectionRequired,
        "consent_required": ConsentRequired,
    }

    default_exception_class = AuthorizationResponseError

    def __init__(
        self,
        authorization_endpoint: str,
        client_id: str,
        redirect_uri: str,
        scope: Union[str, Iterable[str]],
        response_type: str = "code",
        state: Union[str, bool] = True,
        nonce: Union[str, bool, None] = None,
        code_verifier: Optional[str] = None,
        code_challenge_method: Optional[str] = "S256",
        **kwargs: Any,
    ) -> None:

        if state is True:
            state = secrets.token_urlsafe(32)

        if nonce is None or nonce is True:
            nonce = secrets.token_urlsafe(32)
        elif nonce is False:
            nonce = None

        if scope is not None and not isinstance(scope, str):
            scope = "+".join(str(s) for s in scope)

        if not code_challenge_method:
            code_verifier = code_challenge = code_challenge_method = None
        else:
            if not code_verifier:
                code_verifier = PkceUtils.generate_code_verifier()
            code_challenge = PkceUtils.derive_challenge(code_verifier, code_challenge_method)

        self.authorization_endpoint = authorization_endpoint
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.response_type = response_type
        self.scope = scope
        self.state = state
        self.nonce = nonce
        self.code_verifier = code_verifier
        self.code_challenge = code_challenge
        self.code_challenge_method = code_challenge_method
        self.kwargs = kwargs

        self.args = dict(
            client_id=client_id,
            redirect_uri=redirect_uri,
            response_type=response_type,
            scope=scope,
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            **kwargs,
        )

    def sign(
        self, jwk: Jwk, alg: Optional[str] = None, kid: Optional[str] = None
    ) -> "AuthorizationRequest":
        request = Jwt.sign(
            claims={key: val for key, val in self.args.items() if val is not None},
            jwk=jwk,
            alg=alg,
            kid=kid,
        )
        self.args = {"request": str(request)}
        return self

    def sign_and_encrypt(
        self,
        sign_private_jwk: Jwk,
        enc_public_jwk: Jwk,
        sign_alg: Optional[str] = None,
        enc_alg: Optional[str] = None,
    ) -> "AuthorizationRequest":
        enc_request = Jwt.sign_and_encrypt(
            claims={key: val for key, val in self.args.items() if val is not None},
            sign_jwk=sign_private_jwk,
            sign_alg=sign_alg,
            enc_jwk=enc_public_jwk,
            enc_alg=enc_alg,
        )
        self.args = {"request": str(enc_request)}
        return self

    def validate_callback(self, response: str) -> str:
        try:
            response_url = furl(response)
        except ValueError:
            return self.on_response_error(response)

        error = response_url.args.get("error")
        if error:
            return self.on_response_error(response)

        requested_state = self.state
        if requested_state:
            received_state = response_url.args.get("state")
            if requested_state != received_state:
                raise MismatchingState(requested_state, received_state)
        code: str = response_url.args.get("code")
        if code is None:
            raise MissingAuthCode()
        return code

    def on_response_error(self, response: str) -> str:
        response_url = furl(response)
        error = response_url.args.get("error")
        error_description = response_url.args.get("error_description")
        error_uri = response_url.args.get("error_uri")
        exception_class = self.exception_classes.get(error, self.default_exception_class)
        raise exception_class(error, error_description, error_uri)

    @property
    def request(self) -> str:
        return str(
            furl(
                self.authorization_endpoint,
                args={key: value for key, value in self.args.items() if value is not None},
            ).url
        )

    def __repr__(self) -> str:
        return str(self.request)
