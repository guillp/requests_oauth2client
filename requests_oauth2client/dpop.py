"""Implementation of OAuth 2.0 Demonstrating Proof of Possession (DPoP) (RFC9449)."""

from __future__ import annotations

import re
from functools import cached_property
from typing import TYPE_CHECKING, Any, Callable
from uuid import uuid4

import jwskate
from attrs import field, frozen
from binapy import BinaPy
from furl import furl  # type: ignore[import-untyped]
from typing_extensions import Self

from .tokens import AccessTokenTypes, BearerToken, IdToken
from .utils import accepts_expires_in

if TYPE_CHECKING:
    from datetime import datetime

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


token68_pattern = re.compile(r"^[a-zA-Z0-9\-._~+\/]+=*$")


@frozen(init=False)
class DPoPToken(BearerToken):  # type: ignore[override]
    """Represent a DPoP token (RFC9449).

    A DPoP is very much like a BearerToken, with an additional private key bound to it.

    """

    TOKEN_TYPE = AccessTokenTypes.DPOP.value
    AUTHORIZATION_SCHEME = AccessTokenTypes.DPOP.value

    dpop_key: DPoPKey = field(kw_only=True)

    @cached_property
    def access_token_hash(self) -> str:
        """The Access Token Hash, for use in DPoP proofs."""
        return BinaPy(self.access_token).to("sha256").to("b64u").decode()

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

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        """Add a DPoP proof in each requests."""
        request = super().__call__(request)
        htu = furl(request.url).remove(query=True, fragment=True).url
        htm = request.method
        if htm is None:  # pragma: no cover
            msg = "request has no 'method'"
            raise RuntimeError(msg)
        proof = self.dpop_key.proof(htm=htm, htu=htu, ath=self.access_token_hash)
        request.headers["DPoP"] = str(proof)
        return request


@frozen(init=False)
class DPoPKey:
    """Implementation of a DPoP proof generator.

    Args:
        private_key: the private key to use for DPoP proof signatures.
        alg: the alg to use for signatures, if not specified of the `private_key`.
        jti_generator: a callable that generates unique JWT Token ID (jti) values to include in proofs.
        iat_generator: a callable that generates the Issuer Date (iat) to include in proofs.
        dpop_token_class: the class to use to represent DPoP tokens.

    """

    private_key: jwskate.Jwk = field(repr=False)
    alg: str
    jti_generator: Callable[[], str]
    iat_generator: Callable[[], int]
    jwt_typ: str
    dpop_token_class: type[DPoPToken]

    def __init__(
        self,
        private_key: Any,
        alg: str | None = None,
        jti_generator: Callable[[], str] = lambda: str(uuid4()),
        iat_generator: Callable[[], int] = lambda: jwskate.Jwt.timestamp(),
        jwt_typ: str = "dpop+jwt",
        dpop_token_class: type[DPoPToken] = DPoPToken,
    ) -> None:
        try:
            private_key = jwskate.to_jwk(private_key).check(is_private=True, is_symmetric=False)
        except ValueError as exc:
            raise InvalidDPoPKey(private_key) from exc
        self.__attrs_init__(
            private_key=private_key,
            alg=jwskate.select_alg_class(private_key.SIGNATURE_ALGORITHMS, jwk_alg=private_key.alg, alg=alg).name,
            jti_generator=jti_generator,
            iat_generator=iat_generator,
            jwt_typ=jwt_typ,
            dpop_token_class=dpop_token_class,
        )

    @classmethod
    def generate(
        cls,
        alg: str = jwskate.SignatureAlgs.ES256,
        jwt_typ: str = "dpop+jwt",
        jti_generator: Callable[[], str] = lambda: str(uuid4()),
        iat_generator: Callable[[], int] = lambda: jwskate.Jwt.timestamp(),
        dpop_token_class: type[DPoPToken] = DPoPToken,
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
        )

    def proof(self, htm: str, htu: str, ath: str | None = None, nonce: str | None = None) -> jwskate.SignedJwt:
        """Generate a DPoP proof.

        Args:
            htm: The value of the HTTP method of the request to which the JWT is attached.
            htu: The HTTP target URI of the request to which the JWT is attached, without query and fragment parts.
            ath: The Hash of the access token.
            nonce: A recent nonce provided via the DPoP-Nonce HTTP header, from either the AS or RS.

        Returns:
            the proof value (as a signed JWT)

        """
        proof_claims = {"jti": self.jti_generator(), "htm": htm, "htu": htu, "iat": self.iat_generator()}
        if nonce:
            proof_claims["nonce"] = nonce
        if ath:
            proof_claims["ath"] = ath
        return jwskate.SignedJwt.sign(
            proof_claims,
            key=self.private_key,
            alg=self.alg,
            typ=self.jwt_typ,
            extra_headers={"jwk": self.private_key.public_jwk()},
        )
