"""
Implements the various Json Web Crypto-related standards like JWA, JWK, JWKS, JWE, JWT.
This doesn't implement any actual cryptographic operations, it just provides a set of convenient wrappers
around the `cryptography` module.
"""

import hashlib
import json
import secrets
import uuid
from collections import UserDict
from datetime import datetime
from typing import (TYPE_CHECKING, Any, Callable, Dict,
                    Iterable, List, Optional, Type, Union, cast)

import cryptography
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import (ec, ed448, ed25519,
                                                       padding, rsa, x448, x25519)

from .utils import b64u_decode, b64u_encode, json_encode


class ExpiredJwt(ValueError):
    pass


class InvalidSignature(ValueError):
    pass


class InvalidClaim(ValueError):
    pass


class InvalidJwk(ValueError):
    pass


class PrivateKeyRequired(AttributeError):
    pass


# see https://github.com/python/typing/issues/60#issuecomment-869757075
if TYPE_CHECKING:
    _BaseJwk = UserDict[str, Any]
else:
    _BaseJwk = UserDict


class Jwk(_BaseJwk):
    """
    Represents a Json Web Key (JWK), as specified in RFC7517.
    A JWK is a JSON object that represents a cryptographic key.  The members of the object
    represent properties of the key, including its value.
    """

    kty: str
    """The Key Type associated with this JWK."""

    subclasses: Dict[str, Type["Jwk"]] = {}
    """A dict of subclasses implementing each specific Key Type"""

    def __init_subclass__(cls) -> None:
        """Automatically add subclasses to the registry. This allows __new__ to pick the appropriate subclass when creating a Jwk"""
        Jwk.subclasses[cls.kty] = cls

    def __new__(cls, jwk: Dict[str, Any]):  # type: ignore
        if cls == Jwk:
            if jwk.get("keys"):  # if this is a JwkSet
                jwks = JwkSet(jwk)
                return jwks
            kty = jwk.get("kty")
            if not isinstance(kty, str):
                raise TypeError("kty must be a str")
            subclass = Jwk.subclasses.get(kty)
            if subclass is None:
                raise ValueError("Unsupported Key Type", kty)
            return super().__new__(subclass)
        return super().__new__(cls)

    def __init__(self, params: Dict[str, Any], kid: str = None):
        self.data = dict(params)
        self.is_private = False
        self._validate()
        if self.kid is None:
            self.data["kid"] = kid or self.thumbprint()

    def __getattr__(self, item: str) -> Any:
        return self.data.get(item)

    def __getitem__(self, item: str) -> Any:
        return getattr(self, item)

    def public_jwk(self) -> "Jwk":
        params = {
            name: self.data.get(name)
            for name, (description, private, required, kind) in self.PARAMS.items()
            if not private
        }
        return Jwk(
            dict(
                kty=self.kty,
                kid=self.kid,
                alg=self.alg,
                use=self.use,
                key_ops=self.key_ops,
                **params,
            )
        )

    def thumbprint(self, alg: str = "SHA256") -> str:
        """Returns the key thumbprint as specified by RFC 7638.

        :param hashalg: A hash function (defaults to SHA256)
        """

        digest = hashlib.new(alg)

        t = {"kty": self.get("kty")}
        for name, (description, private, required, kind) in self.PARAMS.items():
            if required and not private:
                t[name] = self.get(name)

        intermediary = json.dumps(t, separators=(",", ":"), sort_keys=True)
        digest.update(intermediary.encode("utf8"))
        return b64u_encode(digest.digest())

    def _validate(self) -> None:
        is_private = False
        for name, (description, private, required, kind) in self.PARAMS.items():

            value = getattr(self, name)

            if private and value is not None:
                is_private = True

            if not private and required and value is None:
                raise InvalidJwk(f"Missing required public param {description} ({name})")

            if kind == "b64u":
                try:
                    b64u_decode(value)
                except ValueError:
                    InvalidJwk(
                        f"Parameter {description} ({name}) must be a Base64URL-encoded value"
                    )
            elif kind == "unsupported":
                if value is not None:
                    raise InvalidJwk(f"Unsupported JWK param {name}")
            elif kind == "name":
                pass
            else:
                assert False, f"Unsupported param {name} type {kind}"

        # if at least one of the supplied parameter was private, then all required private parameters must be provided
        if is_private:
            for name, (description, private, required, kind) in self.PARAMS.items():
                value = self.data.get(name)
                if private and required and value is None:
                    raise InvalidJwk(f"Missing required private param {description} ({name})")

        self.is_private = is_private

    def sign(self, data: bytes, alg: Optional[str]) -> bytes:
        raise NotImplementedError

    def verify(
        self, data: bytes, signature: bytes, alg: Union[str, Iterable[str], None]
    ) -> bool:
        raise NotImplementedError

    def encrypt(self, data: bytes, alg: Optional[str]) -> bytes:
        raise NotImplementedError

    def decrypt(self, data: bytes, alg: Optional[str]) -> bytes:
        raise NotImplementedError


class SymetricJwk(Jwk):
    kty = "oct"
    PARAMS = {
        # name: ("Description", private, required, kind),
        "k": ("Key Value", True, True, "b64u"),
    }

    ALGORITHMS = {
        # name: (MAC, alg)
        "HS256": (hmac.HMAC, hashes.SHA256()),
        "HS384": (hmac.HMAC, hashes.SHA384()),
        "HS512": (hmac.HMAC, hashes.SHA512()),
    }

    @classmethod
    def from_bytes(cls, k: bytes, **params: str) -> "SymetricJwk":
        return cls(dict(key="oct", k=b64u_encode(k), **params))

    @classmethod
    def generate(cls, size: int, **params: str) -> "SymetricJwk":
        key = secrets.token_bytes(size)
        return cls.from_bytes(key, **params)

    @property
    def key(self) -> bytes:
        return cast(bytes, b64u_decode(self.k, encoding=None))

    def sign(self, data: bytes, alg: Optional[str] = "HS256") -> bytes:
        alg = self.alg or alg
        if alg is None:
            raise ValueError("a signing alg is required")
        try:
            mac, hashalg = self.ALGORITHMS[alg]
        except KeyError:
            raise ValueError("Unsupported signing alg", alg)

        m = mac(self.key, hashalg)
        m.update(data)
        signature = m.finalize()
        return signature

    def verify(
        self, data: bytes, signature: bytes, alg: Union[str, Iterable[str], None] = None
    ) -> bool:
        if isinstance(alg, str):
            algs = [alg]
        elif alg is None:
            algs = [self.alg]
        else:
            algs = list(alg)

        if not algs:
            raise ValueError("a signing alg is required")

        for alg in algs:
            try:
                mac, hashalg = self.ALGORITHMS[alg]
            except KeyError:
                raise ValueError("Unsupported signing alg", alg)

            m = mac(self.key, hashalg)
            m.update(data)
            candidate_signature = m.finalize()
            if signature == candidate_signature:
                return True

        return False


class RSAJwk(Jwk):
    kty = "RSA"

    PARAMS = {
        # name: ("Description", private, required, kind),
        "n": ("Modulus", False, True, "b64u"),
        "e": ("Exponent", False, True, "b64u"),
        "d": ("Private Exponent", True, True, "b64u"),
        "p": ("First Prime Factor", True, False, "b64u"),
        "q": ("Second Prime Factor", True, False, "b64u"),
        "dp": ("First Factor CRT Exponent", True, False, "b64u"),
        "dq": ("Second Factor CRT Exponent", True, False, "b64u"),
        "qi": ("First CRT Coefficient", True, False, "b64u"),
        "oth": ("Other Primes Info", True, False, "unsupported"),
    }

    ALGORITHMS = {
        # name : (description, padding_alg, hash_alg)
        "RS256": ("RSASSA-PKCS1-v1_5 using SHA-256", padding.PKCS1v15(), hashes.SHA256())
    }

    @property
    def modulus(self) -> int:
        return b64u_to_int(self.n)

    @property
    def exponent(self) -> int:
        return b64u_to_int(self.e)

    @property
    def private_exponent(self) -> int:
        return b64u_to_int(self.d)

    @property
    def first_prime_factor(self) -> int:
        return b64u_to_int(self.p)

    @property
    def second_prime_factor(self) -> int:
        return b64u_to_int(self.q)

    @property
    def first_factor_crt_exponent(self) -> int:
        return b64u_to_int(self.dp)

    @property
    def second_factor_crt_exponent(self) -> int:
        return b64u_to_int(self.dq)

    @property
    def first_crt_coefficient(self) -> int:
        return b64u_to_int(self.qi)

    @classmethod
    def public(cls, n: int, e: int, **params: str) -> "RSAJwk":
        return cls(dict(kty="RSA", n=int_to_b64u(n), e=int_to_b64u(e), **params))

    @classmethod
    def private(
        cls, n: int, e: int, d: int, p: int, q: int, dp: int, dq: int, qi: int, **params: str
    ) -> "RSAJwk":
        return cls(
            dict(
                kty="RSA",
                n=int_to_b64u(n),
                e=int_to_b64u(e),
                d=int_to_b64u(d),
                p=int_to_b64u(p),
                q=int_to_b64u(q),
                dp=int_to_b64u(dp),
                dq=int_to_b64u(dq),
                qi=int_to_b64u(qi),
                **params,
            )
        )

    @classmethod
    def generate(cls, key_size: int = 4096, **params: str) -> "RSAJwk":
        private_key = rsa.generate_private_key(65537, key_size=key_size)
        pn = private_key.private_numbers()
        return cls.private(
            n=pn.public_numbers.n,
            e=pn.public_numbers.e,
            d=pn.d,
            p=pn.p,
            q=pn.q,
            dp=pn.dmp1,
            dq=pn.dmq1,
            qi=pn.iqmp,
            **params,
        )

    def sign(self, data: bytes, alg: Optional[str] = "RS256") -> bytes:
        alg = self.alg or alg
        if alg is None:
            raise ValueError("a signing alg is required")

        if not self.is_private:
            raise PrivateKeyRequired("A private key is required for signing")

        key = rsa.RSAPrivateNumbers(
            self.first_prime_factor,
            self.second_prime_factor,
            self.private_exponent,
            self.first_factor_crt_exponent,
            self.second_factor_crt_exponent,
            self.first_crt_coefficient,
            rsa.RSAPublicNumbers(self.exponent, self.modulus),
        ).private_key()
        try:
            description, padding, hashing = self.ALGORITHMS[alg]
        except KeyError:
            raise ValueError("Unsupported signing alg", alg)

        return key.sign(data, padding, hashing)

    def verify(
        self, data: bytes, signature: bytes, alg: Union[str, Iterable[str], None] = "RS256"
    ) -> bool:
        if isinstance(alg, str):
            algs = [alg]
        elif alg is None:
            algs = [self.alg]
        else:
            algs = list(alg)

        if not algs:
            raise ValueError("a signing alg is required")

        public_key = rsa.RSAPublicNumbers(self.exponent, self.modulus).public_key()

        for alg in algs:
            try:
                description, padding, hashing = self.ALGORITHMS[alg]
            except KeyError:
                raise ValueError("Unsupported signing alg", alg)

            try:
                public_key.verify(
                    signature,
                    data,
                    padding,
                    hashing,
                )
                return True
            except cryptography.exceptions.InvalidSignature:
                continue

        return False


class ECJwk(Jwk):
    kty = "EC"

    PARAMS = {
        # name : (description, private, required, kind),
        "crv": ("Curve", False, True, "name"),
        "x": ("X Coordinate", False, True, "b64u"),
        "y": ("Y Coordinate", False, True, "b64u"),
        "d": ("ECC Private Key", True, True, "b64u"),
    }
    CURVES = {
        "P-256": ec.SECP256R1(),
        "P-384": ec.SECP384R1(),
        "P-521": ec.SECP521R1(),
        "secp256k1": ec.SECP256K1(),
    }

    @classmethod
    def public(cls, crv: str, x: str, y: str, **params: str) -> "ECJwk":
        return cls(dict(key="EC", crv=crv, x=x, y=y, **params))

    @classmethod
    def private(cls, crv: str, x: str, y: str, d: str, **params: str) -> "ECJwk":
        return cls(dict(key="EC", crv=crv, x=x, y=y, d=d, **params))

    @classmethod
    def generate(cls, crv: str = "P-256", **params: str) -> "ECJwk":
        curve = cls.CURVES.get(crv)
        if curve is None:
            raise ValueError("Unsupported curve", crv)
        key = ec.generate_private_key(curve)
        pn = key.private_numbers()
        key_size = pn.public_numbers.curve.key_size
        x = int_to_b64u(pn.public_numbers.x, key_size)
        y = int_to_b64u(pn.public_numbers.y, key_size)
        d = int_to_b64u(pn.private_value, key_size)
        return cls.private(crv=crv, x=x, y=y, d=d, **params)


class OKPJwk(Jwk):
    kty = "OKP"
    PARAMS = {
        "crv": ("Curve", False, True, "name"),
        "x": ("Public Key", False, True, "b64u"),
        "d": ("Private Key", True, False, "b64u"),
    }
    CURVES: Dict[str, Callable[[], Any]] = {
        # curve: generator
        "Ed25519": ed25519.Ed25519PrivateKey.generate,
        "Ed448": ed448.Ed448PrivateKey.generate,
        "X25519": x25519.X25519PrivateKey.generate,
        "X448": x448.X448PrivateKey.generate,
    }

    @classmethod
    def public(cls, crv: str, x: str, **params: str) -> "OKPJwk":
        return cls(dict(crv=crv, x=x, **params))

    @classmethod
    def private(cls, crv: str, x: bytes, d: bytes, **params: str) -> "OKPJwk":
        return cls(dict(crv=crv, x=b64u_encode(x), d=b64u_encode(d), **params))

    @classmethod
    def generate(cls, crv: str, **params: str) -> "OKPJwk":
        generator = cls.CURVES.get(crv)
        if generator is None:
            raise ValueError("Unsupported Curve", crv)
        key = generator()
        x = key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        d = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return cls.private(crv=crv, x=x, d=d, **params)


def int_to_b64u(i: int, length: Optional[int] = None) -> str:
    if length is None:
        length = (i.bit_length() + 7) // 8
    data = i.to_bytes(length, "big", signed=False)
    return b64u_encode(data)


def b64u_to_int(b: str) -> int:
    return int.from_bytes(cast(bytes, b64u_decode(b, encoding=None)), "big", signed=False)


class JwkSet(_BaseJwk):
    """
    A set of JWK keys, with methods for easy management of keys.
    """

    def __init__(
        self, jwks: Optional[Dict[str, Any]] = None, keys: Optional[Iterable[Jwk]] = None
    ):
        if jwks is not None and keys is not None:
            raise ValueError("Please supply either `jwks` or `keys`")
        if jwks is not None:
            keys = jwks.pop("keys", [])
            super().__init__(jwks)  # init the dict with all the dict content that is not keys
        else:
            super().__init__()

        if keys is not None:
            for jwk in keys:
                self.add_jwk(jwk)

    @property
    def jwks(self) -> List[Jwk]:
        return self.data.get("keys", [])

    def get_jwk_by_kid(self, kid: str) -> Optional[Jwk]:
        jwk = next(filter(lambda jwk: jwk.get("kid") == kid, self.jwks), None)
        if isinstance(jwk, Jwk):
            return jwk
        return None

    def __len__(self) -> int:
        return len(self.jwks)

    def add_jwk(
        self,
        jwk: Union[Jwk, Dict[str, Any]],
        kid: Optional[str] = None,
        use: Optional[str] = None,
    ) -> str:
        if not isinstance(jwk, Jwk):
            jwk = Jwk(jwk)

        if "keys" not in self:
            self["keys"] = []

        kid = jwk.get("kid") or kid
        if not kid:
            kid = jwk.thumbprint()
        jwk["kid"] = kid
        use = jwk.use or use
        if use:
            jwk["use"] = use
        self.jwks.append(jwk)
        return kid

    def remove_jwk(self, kid: str) -> None:
        jwk = self.get_jwk_by_kid(kid)
        if jwk is not None:
            self.jwks.remove(jwk)

    def verify(
        self,
        data: bytes,
        signature: bytes,
        alg: Union[str, Iterable[str]],
        kid: Optional[str] = None,
    ) -> bool:
        if kid is not None:
            jwk = self.get_jwk_by_kid(kid)
            if jwk is not None:
                return jwk.verify(data, signature, alg)

        algs = [alg] if isinstance(alg, str) else alg

        if algs:
            for jwk in filter(lambda jwk: jwk.alg in algs, self.jwks):
                if jwk.verify(data, signature, alg):
                    return True

        for jwk in filter(lambda jwk: jwk.use == "verify", self.jwks):
            if jwk.verify(data, signature, alg):
                return True

        for jwk in filter(lambda jwk: jwk.use is None, self.jwks):
            if jwk.verify(data, signature, alg):
                return True

        return False


class InvalidJws(ValueError):
    pass


class JwsCompact:
    """
    Represents a a Json Web Signature (JWS), using compact serialization, as defined in RFC7515.
    """

    def __init__(self, value: str):
        if value.count(".") != 2:
            raise InvalidJws(
                "A JWS must contain a header, a payload and a signature, separated by dots"
            )

        header, payload, signature = value.split(".")
        try:
            self.headers = json.loads(b64u_decode(header))
        except ValueError:
            raise InvalidJws("Invalid JWS header: it must be a Base64URL-encoded JSON object")

        try:
            self.payload = b64u_decode(payload, encoding=None)
        except ValueError:
            raise InvalidJws(
                "Invalid JWS payload: it must be a Base64URL-encoded binary data (bytes)"
            )

        try:
            self.signature = cast(bytes, b64u_decode(signature, encoding=None))
        except ValueError:
            raise InvalidJws(
                "Invalid JWS signature: it must be a Base64URL-encoded binary data (bytes)"
            )

        self.value = value

    def get_header(self, name: str) -> Any:
        return self.headers.get(name)

    @classmethod
    def sign(
        cls,
        payload: bytes,
        jwk: Union[Jwk, Dict[str, Any]],
        extra_headers: Optional[Dict[str, Any]] = None,
        alg: Optional[str] = None,
        kid: Optional[str] = None,
    ) -> "JwsCompact":
        if not isinstance(jwk, Jwk):
            jwk = Jwk(jwk)

        if not jwk.is_private:
            raise ValueError("Signing requires a private JWK")

        alg = alg or jwk.get("alg")
        kid = kid or jwk.get("kid")

        if alg is None:
            raise ValueError("a signing alg is required")

        headers = dict(extra_headers or {}, alg=alg)
        if kid:
            headers["kid"] = kid

        header = b64u_encode(json.dumps(headers, separators=(",", ":")))
        signed_value = ".".join((header, b64u_encode(payload)))
        signature = b64u_encode(jwk.sign(signed_value.encode(), alg=alg))
        return cls(".".join((signed_value, signature)))

    def __str__(self) -> str:
        return self.value

    @property
    def signed_part(self) -> str:
        return ".".join(self.value.split(".", 2)[:2])

    def verify_signature(self, jwk: Union[Jwk, Dict[str, Any]], alg: str) -> bool:
        if not isinstance(jwk, Jwk):
            jwk = Jwk(jwk)
        return jwk.verify(self.signed_part.encode(), self.signature, alg)


class InvalidJwt(ValueError):
    pass


class Jwt:
    def __new__(cls, value: str):  # type: ignore
        if cls == Jwt:
            if value.count(".") == 2:
                return super().__new__(SignedJwt)
            elif value.count(".") == 3:
                return super().__new__(EncryptedJwt)
        return super().__new__(cls)

    def __init__(self, value: str):
        self.value = value
        self.headers: Dict[str, Any] = {}

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, Jwt):
            return self.value == other.value
        if isinstance(other, str):
            return self.value == other
        if isinstance(other, bytes):
            return self.value.encode() == other
        return super().__eq__(other)

    def get_header(self, name: str) -> Any:
        return self.headers.get(name)

    @classmethod
    def sign(
        cls,
        claims: Dict[str, Any],
        jwk: Union[Jwk, Dict[str, Any]],
        alg: Optional[str] = None,
        kid: Optional[str] = None,
        extra_headers: Optional[Dict[str, Any]] = None,
    ) -> "SignedJwt":
        if not isinstance(jwk, Jwk):
            jwk = Jwk(jwk)

        if not jwk.is_private:
            raise ValueError("Signing requires a private JWK")

        alg = alg or jwk.get("alg")
        kid = kid or jwk.get("kid")

        if alg is None:
            raise ValueError("a signing alg is required")

        headers = dict(extra_headers or {}, alg=alg)
        if kid:
            headers["kid"] = kid

        header = b64u_encode(json.dumps(headers, separators=(",", ":")))
        signed_value = ".".join((header, b64u_encode(json_encode(claims))))
        signature = b64u_encode(jwk.sign(signed_value.encode(), alg=alg))
        return SignedJwt(".".join((signed_value, signature)))

    @classmethod
    def sign_and_encrypt(
        cls,
        claims: Dict[str, Any],
        sign_jwk: Union[Jwk, Dict[str, Any]],
        sign_alg: Optional[str],
        enc_jwk: Union[Jwk, Dict[str, Any]],
        enc_alg: Optional[str],
    ) -> "EncryptedJwt":
        raise NotImplementedError


class SignedJwt(Jwt):
    """
    Represents a Signed Json Web Token (JWT), as defined in RFC7519.
    """

    def __init__(self, value: str):
        if value.count(".") != 2:
            raise InvalidJwt(
                "A JWT must contain a header, a payload and a signature, separated by dots",
                value,
            )

        header, payload, signature = value.split(".")
        try:
            self.headers = json.loads(b64u_decode(header))
        except ValueError:
            raise InvalidJwt("Invalid JWT header: it must be a Base64URL-encoded JSON object")

        try:
            self.claims = json.loads(b64u_decode(payload))
        except ValueError:
            raise InvalidJwt("Invalid JWT payload: it must be a Base64URL-encoded JSON object")

        try:
            self.signature = cast(bytes, b64u_decode(signature, encoding=None))
        except ValueError:
            raise InvalidJwt(
                "Invalid JWT signature: it must be a Base64URL-encoded binary data (bytes)"
            )

        self.value = value

    @property
    def signed_part(self) -> str:
        return ".".join(self.value.split(".", 2)[:2])

    def verify_signature(
        self, jwk: Union[Jwk, Dict[str, Any]], alg: Optional[Union[str, Iterable[str]]] = None
    ) -> bool:
        if not isinstance(jwk, Jwk):
            jwk = Jwk(jwk)

        return jwk.verify(self.signed_part.encode(), self.signature, alg)

    def is_expired(self) -> Optional[bool]:
        exp = self.expires_at
        if exp is None:
            return None
        return exp < datetime.now()

    @property
    def expires_at(self) -> Optional[datetime]:
        exp = self.get_claim("exp")
        if not exp:
            return None
        exp_dt = datetime.fromtimestamp(exp)
        return exp_dt

    @property
    def issued_at(self) -> Optional[datetime]:
        iat = self.get_claim("iat")
        if not iat:
            return None
        iat_dt = datetime.fromtimestamp(iat)
        return iat_dt

    @property
    def not_before(self) -> Optional[datetime]:
        nbf = self.get_claim("nbf")
        if not nbf:
            return None
        nbf_dt = datetime.fromtimestamp(nbf)
        return nbf_dt

    @property
    def issuer(self) -> Optional[str]:
        try:
            iss = self.iss
            if isinstance(iss, str):
                return iss
            raise AttributeError("iss has an unexpected type", type(iss))
        except AttributeError:
            return None

    @property
    def audience(self) -> Optional[str]:
        try:
            aud = self.aud
            if isinstance(aud, str):
                return [aud]
            elif isinstance(aud, list):
                return aud
            raise AttributeError("aud has an unexpected type", type(aud))
        except AttributeError:
            return None

    @property
    def subject(self) -> Optional[str]:
        try:
            sub = self.sub
            if isinstance(sub, (str, list)):
                return sub
            raise AttributeError("sub has an unexpected type", type(sub))
        except AttributeError:
            return None

    @property
    def jwt_token_id(self) -> Optional[str]:
        try:
            jti = self.jti
            if isinstance(jti, str):
                return jti
            raise AttributeError("jti has an unexpected type", type(jti))
        except AttributeError:
            return None

    @property
    def alg(self) -> str:
        return self.get_header("alg")  # type: ignore

    @property
    def kid(self) -> str:
        return self.get_header("kid")  # type: ignore

    def get_claim(self, key: str) -> Any:
        return self.claims.get(key)

    def __getattr__(self, item: str) -> Any:
        value = self.get_claim(item)
        if value is None:
            raise AttributeError(item)
        return value

    def __str__(self) -> str:
        return self.value

    def validate(
        self,
        jwk: Union[Jwk, Dict[str, Any]],
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
        check_exp: bool = True,
        **kwargs: Any,
    ) -> None:
        if not self.verify_signature(jwk):
            raise InvalidSignature("Signature is not valid.")

        if issuer is not None:
            if self.issuer != issuer:
                raise InvalidClaim("iss", "Unexpected issuer", self.issuer)

        if audience is not None:
            if isinstance(audience, str):
                audience = [audience]
            if self.audience != audience:
                raise InvalidClaim("aud", "Unexpected audience", self.audience)

        if check_exp:
            if self.is_expired():
                raise ExpiredJwt(f"This token expired at {self.expires_at}")

        for key, value in kwargs.items():
            if self.get_claim(key) != value:
                raise InvalidClaim(
                    key, f"unexpected value for claim {key}", self.get_claim(key)
                )


class EncryptedJwt(Jwt):
    pass


class JwtSigner:
    def __init__(
        self,
        issuer: str,
        jwk: Jwk,
        alg: Optional[str] = None,
        default_lifetime: int = 60,
        default_leeway: Optional[int] = None,
    ):
        self.issuer = issuer
        self.jwk = jwk
        self.alg = jwk.alg or alg
        self.default_lifetime = default_lifetime
        self.default_leeway = default_leeway

    def sign(
        self,
        subject: str = None,
        audience: Union[str, Iterable[str], None] = None,
        extra_claims: Optional[Dict[str, Any]] = None,
        extra_headers: Optional[Dict[str, Any]] = None,
        lifetime: int = None,
        leeway: int = None,
    ) -> Jwt:
        now = datetime.now().timestamp()
        exp = now + lifetime or self.default_lifetime
        leeway = leeway or self.default_leeway
        nbf = (now - leeway) if leeway is not None else None
        jti = self.generate_jti()
        extra_claims = extra_claims or {}
        claims = {
            key: value
            for key, value in dict(
                extra_claims,
                iss=self.issuer,
                aud=audience,
                sub=subject,
                iat=now,
                exp=exp,
                nbf=nbf,
                jti=jti,
            )
            if value is not None
        }
        return Jwt.sign(claims, jwk=self.jwk, alg=self.alg, extra_headers=extra_headers)

    def generate_jti(self) -> str:
        return str(uuid.uuid4())
