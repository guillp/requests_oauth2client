"""Implementation of OAuth 2.0 Demonstrating Proof of Possession (DPoP) (RFC9449)."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from functools import cached_property
from typing import TYPE_CHECKING, Any, Callable, ClassVar, Sequence
from uuid import uuid4

import jwskate
from attrs import define, field, frozen, setters
from binapy import BinaPy
from furl import furl  # type: ignore[import-untyped]
from requests import codes
from typing_extensions import Self

from .tokens import AccessTokenTypes, BearerToken, IdToken, id_token_converter
from .utils import accepts_expires_in

if TYPE_CHECKING:
    import requests


class InvalidDPoPAccessToken(ValueError):
    """Raised when an access token contains invalid characters."""

    def __init__(self, access_token: str) -> None:
        super().__init__("""\
This DPoP token contains invalid characters. DPoP tokens are limited to a set of 68 characters,
to avoid encoding inconsistencies when doing the token value hashing for the DPoP proof.""")
        self.access_token = access_token


class InvalidDPoPKey(ValueError):
    """Raised when a DPoPToken is initialized with a non-suitable key."""

    def __init__(self, key: Any) -> None:
        super().__init__("The key you are trying to use with DPoP is not an asymmetric private key.")
        self.key = key


class InvalidDPoPAlg(ValueError):
    """Raised when an invalid or unsupported DPoP alg is given."""

    def __init__(self, alg: str) -> None:
        super().__init__("DPoP proofing require an asymmetric signing alg.")
        self.alg = alg


class InvalidDPoPProof(ValueError):
    """Raised when a DPoP proof does not verify."""

    def __init__(self, proof: bytes, message: str) -> None:
        super().__init__(f"Invalid DPoP proof: {message}")
        self.proof = proof


class InvalidUseDPoPNonceResponse(Exception):
    """Base class for invalid Responses with a `use_dpop_nonce` error."""

    def __init__(self, response: requests.Response, message: str) -> None:
        super().__init__(message)
        self.response = response


class MissingDPoPNonce(InvalidUseDPoPNonceResponse):
    """Raised when a server requests a DPoP nonce but none is provided in its response."""

    def __init__(self, response: requests.Response) -> None:
        super().__init__(
            response,
            "Server requested client to use a DPoP `nonce`, but the `DPoP-Nonce` HTTP header is missing.",
        )


class RepeatedDPoPNonce(InvalidUseDPoPNonceResponse):
    """Raised when the server requests a DPoP nonce value that is the same as already included in the request."""

    def __init__(self, response: requests.Response) -> None:
        super().__init__(
            response,
            """\
Server requested client to use a DPoP `nonce`,
but provided the same value for that nonce that was already included in the DPoP proof.""",
        )


token68_pattern = re.compile(r"^[a-zA-Z0-9\-._~+\/]+=*$")


@frozen(init=False)
class DPoPToken(BearerToken):  # type: ignore[override]
    """Represent a DPoP token (RFC9449).

    A DPoP is very much like a BearerToken, with an additional private key bound to it.

    """

    TOKEN_TYPE = AccessTokenTypes.DPOP.value
    AUTHORIZATION_SCHEME = AccessTokenTypes.DPOP.value
    DPOP_HEADER: ClassVar[str] = "DPoP"

    dpop_key: DPoPKey = field(kw_only=True)

    @accepts_expires_in
    def __init__(
        self,
        access_token: str,
        *,
        _dpop_key: DPoPKey,
        expires_at: datetime | None = None,
        scope: str | None = None,
        refresh_token: str | None = None,
        token_type: str = TOKEN_TYPE,
        id_token: str | bytes | IdToken | jwskate.JweCompact | None = None,
        **kwargs: Any,
    ) -> None:
        if not token68_pattern.match(access_token):
            raise InvalidDPoPAccessToken(access_token)

        id_token = id_token_converter(id_token)

        self.__attrs_init__(
            access_token=access_token,
            expires_at=expires_at,
            scope=scope,
            refresh_token=refresh_token,
            token_type=token_type,
            id_token=id_token,
            dpop_key=_dpop_key,
            kwargs=kwargs,
        )

    def _response_hook(self, response: requests.Response, **kwargs: Any) -> requests.Response:
        """Handles a Resource Server provided DPoP nonce."""
        if response.status_code == codes.unauthorized and response.headers.get("WWW-Authenticate", "").startswith(
            "DPoP"
        ):
            self.dpop_key.handle_rs_provided_dpop_nonce(response)
            new_request = response.request.copy()
            # remove the previously registered hook to avoid registering it multiple times
            new_request.deregister_hook("response", self._response_hook)  # type: ignore[no-untyped-call]
            new_request = self(new_request)  # another hook will be re-registered here in the __call__() method

            return response.connection.send(new_request, **kwargs)

        return response

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        """Add a DPoP proof in each request."""
        request = super().__call__(request)
        add_dpop_proof(request, dpop_key=self.dpop_key, access_token=self.access_token, header_name=self.DPOP_HEADER)
        request.register_hook("response", self._response_hook)  # type: ignore[no-untyped-call]
        return request


def add_dpop_proof(
    request: requests.PreparedRequest,
    dpop_key: DPoPKey,
    access_token: str,
    header_name: str = "DPoP",
) -> None:
    """Add a valid DPoP proof to a request, in-place.

    Args:
        request: the request to add the proof to.
        dpop_key: the DPoP key to use for the proof.
        access_token: the access token to hash in the proof.
        header_name: the name of the header to add the proof to.

    """
    htu = request.url
    htm = request.method
    ath = BinaPy(access_token).to("sha256").to("b64u").decode()
    if htu is None or htm is None:  # pragma: no cover
        msg = "Request has no 'method' or 'url'! This should not happen."
        raise RuntimeError(msg)
    proof = dpop_key.proof(htm=htm, htu=htu, ath=ath)
    request.headers[header_name] = str(proof)


@define(init=False)
class DPoPKey:
    """Wrapper around a DPoP proof signature key.

    This handles DPoP proof generation. It also keeps track of a nonce, if provided
    by the Resource Server.
    Its behavior follows the standard DPoP specifications.
    You may subclass or otherwise customize this class to implement custom behavior,
    like adding or modifying claims to the proofs.

    Args:
        private_key: the private key to use for DPoP proof signatures.
        alg: the alg to use for signatures, if not specified of the `private_key`.
        jti_generator: a callable that generates unique JWT Token ID (jti) values to include in proofs.
        iat_generator: a callable that generates the Issuer Date (iat) to include in proofs.
        jwt_typ: the token type (`typ`) header to include in the generated proofs.
        dpop_token_class: the class to use to represent DPoP tokens.
        rs_nonce: an initial DPoP `nonce` to include in requests, for testing purposes. You should leave `None`.

    """

    alg: str = field(on_setattr=setters.frozen)
    private_key: jwskate.Jwk = field(on_setattr=setters.frozen, repr=False)
    jti_generator: Callable[[], str] = field(on_setattr=setters.frozen, repr=False)
    iat_generator: Callable[[], int] = field(on_setattr=setters.frozen, repr=False)
    jwt_typ: str = field(on_setattr=setters.frozen, repr=False)
    dpop_token_class: type[DPoPToken] = field(on_setattr=setters.frozen, repr=False)
    as_nonce: str | None
    rs_nonce: str | None

    def __init__(
        self,
        private_key: Any,
        alg: str | None = None,
        jti_generator: Callable[[], str] = lambda: str(uuid4()),
        iat_generator: Callable[[], int] = lambda: jwskate.Jwt.timestamp(),
        jwt_typ: str = "dpop+jwt",
        dpop_token_class: type[DPoPToken] = DPoPToken,
        as_nonce: str | None = None,
        rs_nonce: str | None = None,
    ) -> None:
        try:
            private_key = jwskate.to_jwk(private_key).check(is_private=True, is_symmetric=False)
        except ValueError as exc:
            raise InvalidDPoPKey(private_key) from exc

        alg_name = jwskate.select_alg_class(private_key.SIGNATURE_ALGORITHMS, jwk_alg=private_key.alg, alg=alg).name

        self.__attrs_init__(
            alg=alg_name,
            private_key=private_key,
            jti_generator=jti_generator,
            iat_generator=iat_generator,
            jwt_typ=jwt_typ,
            dpop_token_class=dpop_token_class,
            as_nonce=as_nonce,
            rs_nonce=rs_nonce,
        )

    @classmethod
    def generate(
        cls,
        alg: str = jwskate.SignatureAlgs.ES256,
        jwt_typ: str = "dpop+jwt",
        jti_generator: Callable[[], str] = lambda: str(uuid4()),
        iat_generator: Callable[[], int] = lambda: jwskate.Jwt.timestamp(),
        dpop_token_class: type[DPoPToken] = DPoPToken,
        as_nonce: str | None = None,
        rs_nonce: str | None = None,
    ) -> Self:
        """Generate a new DPoPKey with a new private key that is suitable for the given `alg`."""
        if alg not in jwskate.SignatureAlgs.ALL_ASYMMETRIC:
            raise InvalidDPoPAlg(alg)
        key = jwskate.Jwk.generate(alg=alg)
        return cls(
            private_key=key,
            jti_generator=jti_generator,
            iat_generator=iat_generator,
            jwt_typ=jwt_typ,
            dpop_token_class=dpop_token_class,
            as_nonce=as_nonce,
            rs_nonce=rs_nonce,
        )

    @cached_property
    def public_jwk(self) -> jwskate.Jwk:
        """The public JWK key that matches the private key."""
        return self.private_key.public_jwk()

    @cached_property
    def dpop_jkt(self) -> str:
        """The key thumbprint, used for Authorization Code DPoP binding."""
        return self.private_key.thumbprint()

    def proof(self, htm: str, htu: str, ath: str | None = None, nonce: str | None = None) -> jwskate.SignedJwt:
        """Generate a DPoP proof.

        Proof will contain the following claims:

            - The HTTP method (`htm`), target URI (`htu`), and Access Token hash (`ath`) that are passed as parameters.
            - The `iat` claim will be generated by the configured `iat_generator`, which defaults to current datetime.
            - The `jti` claim will be generated by the configured `jti_generator`, which defaults to a random UUID4.
            - The `nonce` claim will be the value stored in the `nonce` attribute. This attribute is updated
              automatically when using a `DPoPToken` or one of the provided Authentication handlers as a `requests`
              auth handler.

        The proof will be signed with the private key of this DPoPKey, using the configured `alg` signature algorithm.

        Args:
            htm: The HTTP method value of the request to which the proof is attached.
            htu: The HTTP target URI of the request to which the proof is attached. Query and Fragment parts will
                be automatically removed before being used as `htu` value in the generated proof.
            ath: The Access Token hash value.
            nonce: A recent nonce provided via the DPoP-Nonce HTTP header, from either the AS or RS.  If `None`, the
                value stored in `rs_nonce` will be used instead.
                In typical cases, you should never have to use this parameter. It is only used internally when
                requesting the AS token endpoint.

        Returns:
            the proof value (as a signed JWT)

        """
        htu = furl(htu).remove(query=True, fragment=True).url
        proof_claims = {"jti": self.jti_generator(), "htm": htm, "htu": htu, "iat": self.iat_generator()}
        if nonce:
            proof_claims["nonce"] = nonce
        elif self.rs_nonce:
            proof_claims["nonce"] = self.rs_nonce
        if ath:
            proof_claims["ath"] = ath
        return jwskate.SignedJwt.sign(
            proof_claims,
            key=self.private_key,
            alg=self.alg,
            typ=self.jwt_typ,
            extra_headers={"jwk": self.public_jwk},
        )

    def handle_as_provided_dpop_nonce(self, response: requests.Response) -> None:
        """Handle an Authorization Server response containing a `use_dpop_nonce` error.

        Args:
            response: the response from the AS.

        """
        nonce = response.headers.get("DPoP-Nonce")
        if not nonce:
            raise MissingDPoPNonce(response)
        if self.as_nonce == nonce:
            raise RepeatedDPoPNonce(response)
        self.as_nonce = nonce

    def handle_rs_provided_dpop_nonce(self, response: requests.Response) -> None:
        """Handle a Resource Server response containing a `use_dpop_nonce` error.

        Args:
            response: the response from the AS.

        """
        nonce = response.headers.get("DPoP-Nonce")
        if not nonce:
            raise MissingDPoPNonce(response)
        if self.rs_nonce == nonce:
            raise RepeatedDPoPNonce(response)
        self.rs_nonce = nonce


def validate_dpop_proof(  # noqa: C901
    proof: str | bytes,
    *,
    htm: str,
    htu: str,
    ath: str | None = None,
    nonce: str | None = None,
    leeway: int = 60,
    alg: str | None = None,
    algs: Sequence[str] = (),
) -> jwskate.SignedJwt:
    """Validate a DPoP proof.

    Args:
        proof: The serialized DPoP proof.
        htm: The value of the HTTP method of the request to which the JWT is attached.
        htu: The HTTP target URI of the request to which the JWT is attached, without query and fragment parts.
        ath: The Hash of the access token.
        nonce: A recent nonce provided via the DPoP-Nonce HTTP header, from either the AS or RS.
        leeway: A leeway, in number of seconds, to validate the proof `iat` claim.
        alg: Allowed signature alg, if there is only one. Use this or `algs`.
        algs: Allowed signature algs, if there is several. Use this or `alg`.

    Returns:
        The validated DPoP proof, as a `SignedJwt`.

    """
    if not isinstance(proof, bytes):
        proof = proof.encode()
    try:
        proof_jwt = jwskate.SignedJwt(proof)
    except jwskate.InvalidJwt as exc:
        raise InvalidDPoPProof(proof, "not a syntactically valid JWT") from exc
    if proof_jwt.typ != "dpop+jwt":
        raise InvalidDPoPProof(proof, f"typ '{proof_jwt.typ}' is not the expected 'dpop+jwt'.")
    if "jwk" not in proof_jwt.headers:
        raise InvalidDPoPProof(proof, "'jwk' header is missing")
    try:
        public_jwk = jwskate.Jwk(proof_jwt.headers["jwk"])
    except jwskate.InvalidJwk as exc:
        raise InvalidDPoPProof(proof, "'jwk' header is not a valid JWK key.") from exc
    if public_jwk.is_private or public_jwk.is_symmetric:
        raise InvalidDPoPProof(proof, "'jwk' header is a private or symmetric key.")

    if not proof_jwt.verify_signature(public_jwk, alg=alg, algs=algs):
        raise InvalidDPoPProof(proof, "signature does not verify.")

    if proof_jwt.issued_at is None:
        raise InvalidDPoPProof(proof, "a Issued At (iat) claim is missing.")
    now = datetime.now(tz=timezone.utc)
    if not now - timedelta(seconds=leeway) < proof_jwt.issued_at < now + timedelta(seconds=leeway):
        msg = f"""\
Issued At timestamp (iat) is too far away in the past or future (received: {proof_jwt.issued_at}, now: {now})."""
        raise InvalidDPoPProof(
            proof,
            msg,
        )
    if proof_jwt.jwt_token_id is None:
        raise InvalidDPoPProof(proof, "a Unique Identifier (jti) claim is missing.")
    if "htm" not in proof_jwt.claims:
        raise InvalidDPoPProof(proof, "the HTTP method (htm) claim is missing.")
    if proof_jwt.htm != htm:
        raise InvalidDPoPProof(proof, f"HTTP Method (htm) '{proof_jwt.htm}' does not matches expected '{htm}'.")
    if "htu" not in proof_jwt.claims:
        raise InvalidDPoPProof(proof, "the HTTP URI (htu) claim is missing.")
    if proof_jwt.htu != htu:
        raise InvalidDPoPProof(proof, f"HTTP URI (htu) '{proof_jwt.htu}' does not matches expected '{htu}'.")
    if ath:
        if "ath" not in proof_jwt.claims:
            raise InvalidDPoPProof(proof, "the Access Token hash (ath) claim is missing.")
        if proof_jwt.ath != ath:
            raise InvalidDPoPProof(
                proof, f"Access Token Hash (ath) value '{proof_jwt.ath}' does not match expected '{ath}'."
            )
    if nonce:
        if "nonce" not in proof_jwt.claims:
            raise InvalidDPoPProof(proof, "the DPoP Nonce (nonce) claim is missing.")
        if proof_jwt.nonce != nonce:
            raise InvalidDPoPProof(
                proof, f"DPoP Nonce (nonce) value '{proof_jwt.nonce}' does not match expected '{nonce}'."
            )

    return proof_jwt
