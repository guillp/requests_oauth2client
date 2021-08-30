"""
Implements the various Json Web Crypto-related standards like JWA, JWK, JWKS, JWE, JWT.
This doesn't implement any actual cryptographic operations, it just provides a set of convenient wrappers
around the `cryptography` module.
"""

import hashlib
import hmac
import json
import secrets
from collections import UserDict, defaultdict
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Type, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (ec, ed448, ed25519,
                                                       padding, rsa, x448, x25519)

from requests_oauth2client import b64u_decode, b64u_encode
from requests_oauth2client.utils import json_encode


class InvalidJwk(ValueError):
    pass


class PrivateKeyRequired(AttributeError):
    pass


class Jwk(UserDict):
    """
    Represents a Json Web Key (JWK), as specified in RFC7517.
    A JWK is a JSON object that represents a cryptographic key.  The members of the object
    represent properties of the key, including its value.
    """

    subclasses: Dict[str, Type["Jwt"]] = {}

    def __init_subclass__(cls, **kwargs):
        Jwk.subclasses[cls.kty] = cls

    def __new__(cls, params: Dict[str, Any]):
        if cls == Jwk:
            kty = params.get("kty")
            if not isinstance(kty, str):
                raise TypeError("kty must be a str")
            subclass = Jwk.subclasses.get(kty)
            if subclass is None:
                raise ValueError("Unsupported Key Type", kty)
            return super().__new__(subclass)
        return super().__new__(cls)

    def __init__(self, params: Dict[str, Any]):
        self.data = dict(params)
        self.is_private = False
        self._validate()
        if self.kid is None:
            self.data["kid"] = self.thumbprint()

    def __getattr__(self, item):
        return self.data.get(item)

    def __getitem__(self, item):
        return getattr(self, item)

    def public_jwk(self):
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

    def _validate(self):
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

    def verify(self, data: bytes, signature: bytes, alg: Optional[str]) -> bool:
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
    def from_bytes(cls, k: bytes, **params):
        return cls(dict(key="oct", k=b64u_encode(k), **params))

    @classmethod
    def generate(cls, size, **params):
        key = secrets.token_bytes(size)
        return cls.from_bytes(key, **params)

    @property
    def key(self):
        return b64u_decode(self.k)

    def sign(self, data: bytes, alg: str = "HS256") -> bytes:
        try:
            mac, hashalg = self.ALGORITHMS[alg]
        except KeyError:
            raise ValueError("Unsupported signing alg", alg)

        m = mac(self.key, hashalg)
        m.update(data)
        signature = m.finalize()
        return signature

    def verify(self, data: bytes, signature: bytes, alg: str = "HS256") -> bool:
        try:
            mac, hashalg = self.ALGORITHMS[alg]
        except KeyError:
            raise ValueError("Unsupported signing alg", alg)

        m = mac(self.key, hashalg)
        m.update(data)
        candidate_signature = m.finalize()
        return signature == candidate_signature


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
    def modulus(self):
        return b64u_to_int(self.n)

    @property
    def exponent(self):
        return b64u_to_int(self.e)

    @property
    def private_exponent(self):
        return b64u_to_int(self.d)

    @property
    def first_prime_factor(self):
        return b64u_to_int(self.p)

    @property
    def second_prime_factor(self):
        return b64u_to_int(self.q)

    @property
    def first_factor_crt_exponent(self):
        return b64u_to_int(self.dp)

    @property
    def second_factor_crt_exponent(self):
        return b64u_to_int(self.dq)

    @property
    def first_crt_coefficient(self):
        return b64u_to_int(self.qi)

    @classmethod
    def public(cls, n: int, e: int, **params):
        return cls(dict(kty="RSA", n=int_to_b64u(n), e=int_to_b64u(e), **params))

    @classmethod
    def private(
        cls, n: int, e: int, d: int, p: int, q: int, dp: int, dq: int, qi: int, **params
    ):
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
    def generate(cls, key_size: int = 4096, **params):
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

    def sign(self, data: bytes, alg: str = "RS256") -> bytes:
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

    def verify(self, data: bytes, signature: bytes, alg: Optional[str] = None) -> bool:
        alg = self.alg or alg
        if alg is None:
            raise ValueError("A signing alg is required")

        public_key = rsa.RSAPublicNumbers(self.exponent, self.modulus).public_key()
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
        except InvalidSignature:
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
    def public(
        cls,
        crv: str,
        x: str,
        y: str,
        kid: str = None,
        alg: str = None,
        use: str = None,
        key_ops: Iterable[str] = None,
    ):
        return cls(
            dict(key="EC", crv=crv, x=x, y=y, kid=kid, alg=alg, use=use, key_ops=key_ops)
        )

    @classmethod
    def private(
        cls,
        crv: str,
        x: str,
        y: str,
        d: str,
        kid: str = None,
        alg: str = None,
        use: str = None,
        key_ops: Iterable[str] = None,
    ):
        return cls(
            dict(key="EC", crv=crv, x=x, y=y, d=d, kid=kid, alg=alg, use=use, key_ops=key_ops)
        )

    @classmethod
    def generate(cls, crv: str = "P-256", **params):
        curve = cls.CURVES.get(crv)
        key = ec.generate_private_key(curve)
        pn = key.private_numbers()
        key_size = pn.public_numbers.curve.key_size
        x = (int_to_b64u(pn.public_numbers.x, key_size),)
        y = (int_to_b64u(pn.public_numbers.y, key_size),)
        d = int_to_b64u(pn.private_value, key_size)
        return cls.private(crv=crv, x=x, y=y, d=d, **params)


class OKPJwk(Jwk):
    kty = "OKP"
    PARAMS = {
        "crv": ("Curve", False, True, "name"),
        "x": ("Public Key", False, True, "b64u"),
        "d": ("Private Key", True, False, "b64u"),
    }
    CURVES = {
        "Ed25519": ed25519.Ed25519PrivateKey,
        "Ed448": ed448.Ed448PrivateKey,
        "X25519": x25519.X25519PrivateKey,
        "X448": x448.X448PrivateKey,
    }

    @classmethod
    def public(
        cls,
        crv: str,
        x: str,
        kid: str = None,
        alg: str = None,
        use: str = None,
        key_ops: Iterable[str] = None,
    ):
        return cls(dict(crv=crv, x=x, kid=kid, alg=alg, use=use, key_ops=key_ops))

    @classmethod
    def private(
        cls,
        crv: str,
        x: str,
        d: str,
        kid: str = None,
        alg: str = None,
        use: str = None,
        key_ops: Iterable[str] = None,
    ):
        return cls(
            dict(
                crv=crv,
                x=b64u_encode(x),
                d=b64u_encode(d),
                kid=kid,
                alg=alg,
                use=use,
                key_ops=key_ops,
            )
        )

    @classmethod
    def generate(
        cls,
        crv: str,
        kid: str = None,
        alg: str = None,
        use: str = None,
        key_ops: Iterable[str] = None,
    ):
        curve = cls.CURVES.get(crv)
        if not curve:
            raise ValueError("Unsupported Curve", crv)
        key = curve.generate()
        x = key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        d = key.public_key()
        return cls.private(crv=crv, x=x, d=d, kid=kid, alg=alg, use=use, key_ops=key_ops)


def int_to_b64u(i: int, length: Optional[int] = None) -> str:
    if length is None:
        length = (i.bit_length() + 7) // 8
    data = i.to_bytes(length, "big", signed=False)
    return b64u_encode(data)


def b64u_to_int(b: str) -> int:
    return int.from_bytes(b64u_decode(b, encoding=None), "big", signed=False)


JWKType = Union[Dict[str, Any], Jwk]


class JwkSet:
    """
    A set of JWK keys, with methods for easy management of keys.
    """

    def __init__(self, jwks: Optional[Iterable[Jwk]] = None):
        self.keys: Dict[str, JWKType] = {}
        self.uses: Dict[str, List[str]] = defaultdict(list)

        if jwks:
            for jwk in jwks:
                self.add_jwk(jwk)

    def __iter__(self) -> Iterable[JWKType]:
        for key in self.keys:
            yield key

    def __getitem__(self, kid: str) -> JWKType:
        """
        This always returns public keys.
        :param kid: the kid to get
        :return: a Jwk with a public key
        """
        return self.keys.get(kid).public_jwk()

    def __len__(self):
        return len(self.keys)

    @property
    def jwks(self) -> Dict[str, JWKType]:
        return {"keys": self.keys}

    def add_jwk(
        self,
        jwk: JWKType,
        kid: Optional[str] = None,
        use: Optional[str] = None,
    ) -> str:
        if not isinstance(jwk, Jwk):
            jwk = Jwk(jwk)
        use = jwk.use or use
        kid = jwk.get("kid") or kid
        if not kid:
            kid = jwk.thumbprint()
        jwk["kid"] = kid
        if use:
            self.uses[use].append(kid)
            jwk["use"] = use
        self.keys[kid] = jwk
        return kid

    def remove_jwk(self, kid: str) -> None:
        jwk = self[kid]
        kid = jwk["kid"]
        use = jwk["use"]
        self.uses[use].remove(kid)

    def get_jwk_by_kid(self, kid: str) -> JWKType:
        return self.keys.get(kid)

    def get_jwks_by_use(self, use: str) -> JWKType:
        kids = self.uses.get(use)
        if not kids:
            return None
        return [self.keys.get(kid) for kid in kids]

    def get_signing_jwk(self) -> Dict[str, Any]:
        return self.get_jwk_by_use("sig")

    def get_encryption_jwk(self) -> Dict[str, Any]:
        return self.get_jwk_by_use("enc")

    @property
    def private_jwks(self):
        return self.keys


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
            self.signature = b64u_decode(signature, encoding=None)
        except ValueError:
            raise InvalidJws(
                "Invalid JWS signature: it must be a Base64URL-encoded binary data (bytes)"
            )

        self.value = value

    def get_header(self, name):
        return self.headers.get(name)

    @classmethod
    def sign(
        cls,
        payload: bytes,
        jwk: Jwk,
        extra_headers: Dict[str, Any] = None,
        alg: Optional[str] = None,
        kid: Optional[str] = None,
    ):
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
    def signed_part(self):
        return ".".join(self.value.split(".", 2)[:2])

    def verify_signature(self, jwk: Jwk, alg: str) -> bool:
        return jwk.verify(self.signed_part.encode(), self.signature, alg)


class InvalidJwt(ValueError):
    pass


class Jwt:
    def __new__(cls, value: str):
        if cls == Jwt:
            if value.count(".") == 2:
                return super().__new__(SignedJwt)
            elif value.count(".") == 3:
                return super().__new__(EncryptedJwt)
        return super().__new__(cls)

    def get_header(self, name: str) -> Any:
        return self.headers.get(name)


class SignedJwt(Jwt):
    """
    Represents a Signed Json Web Token (JWT), as defined in RFC7519.
    """

    def __init__(self, value: str):
        if value.count(".") != 2:
            raise InvalidJwt(
                "A JWT must contain a header, a payload and a signature, separated by dots"
            )

        header, payload, signature = value.split(".")
        try:
            self.headers = json.loads(b64u_decode(header))
        except ValueError:
            raise InvalidJwt("Invalid JWT header: it must be a Base64URL-encoded JSON object")

        try:
            self.claims = json.loads(b64u_decode(payload, encoding=None))
        except ValueError:
            raise InvalidJwt("Invalid JWT payload: it must be a Base64URL-encoded JSON object")

        try:
            self.signature = b64u_decode(signature, encoding=None)
        except ValueError:
            raise InvalidJwt(
                "Invalid JWT signature: it must be a Base64URL-encoded binary data (bytes)"
            )

        self.value = value

    @property
    def signed_part(self):
        return ".".join(self.value.split(".", 2)[:2])

    def verify_signature(self, jwk: Jwk, alg: Optional[str] = None) -> bool:
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
    def alg(self) -> str:
        return self.get_header("alg")  # type: ignore

    @property
    def kid(self) -> str:
        return self.get_header("kid")  # type: ignore

    def get_claim(self, key: str) -> Any:
        return self.claims.get(key)

    def __getattr__(self, item: str) -> Any:
        return self.get_claim(item)

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, str):
            return self.value == other
        elif isinstance(other, Jwt):
            return self.value == other.value
        return super().__eq__(other)

    @classmethod
    def sign(
        cls,
        claims: Dict[str, Any],
        jwk: Jwk,
        extra_headers: Dict[str, Any] = None,
        alg: Optional[str] = None,
        kid: Optional[str] = None,
    ):
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
        return cls(".".join((signed_value, signature)))

    def __str__(self) -> str:
        return self.value



#class EncryptedJwt(Jwt):
#    pass