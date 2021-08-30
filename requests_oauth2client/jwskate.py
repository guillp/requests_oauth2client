"""
Implements the various Json Web Crypto-related standards like JWA, JWK, JWKS, JWE, JWT.
"""
import hashlib
import json
from collections import UserDict, defaultdict, namedtuple
from datetime import datetime
from enum import Enum
from itertools import count
from typing import Any, Dict, Iterable, List, Optional, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

from requests_oauth2client import b64u_decode, b64u_encode
from requests_oauth2client.utils import b64_decode


class KeyTypes(Enum):
    RSA = "RSA"
    EC = "EC"
    SYMETRIC = "oct"


class Use(Enum):
    SIGNATURE = "sig"
    ENCRYPTION = "enc"


class KeyOp(Enum):
    SIGN = "sign"
    VERIFY = "verify"

    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"

    WRAP_KEY = "wrapKey"
    UNWRAP_KEY = "unwrapKey"
    DERIVE_KEY = "deriveKey"
    DERIVE_BITS = "deriveBits"


class EC_CURVE(Enum):
    P_256 = "P-256"
    P_384 = "P-384"
    P_521 = "P-521"


class ParamType(Enum):
    name = "A string with a name"
    b64 = "Base64url Encoded"
    b64u = "Base64urlUint Encoded"
    unsupported = "Unsupported Parameter"


JWKParameter = namedtuple("Parameter", "description private required type")
JWKValuesRegistry = {
    "EC": {
        "crv": JWKParameter("Curve", False, True, ParamType.name),
        "x": JWKParameter("X Coordinate", False, True, ParamType.b64),
        "y": JWKParameter("Y Coordinate", False, True, ParamType.b64),
        "d": JWKParameter("ECC Private Key", True, True, ParamType.b64),
    },
    "RSA": {
        "n": JWKParameter("Modulus", False, True, ParamType.b64),
        "e": JWKParameter("Exponent", False, True, ParamType.b64u),
        "d": JWKParameter("Private Exponent", True, True, ParamType.b64u),
        "p": JWKParameter("First Prime Factor", True, False, ParamType.b64u),
        "q": JWKParameter("Second Prime Factor", True, False, ParamType.b64u),
        "dp": JWKParameter("First Factor CRT Exponent", True, False, ParamType.b64u),
        "dq": JWKParameter("Second Factor CRT Exponent", True, False, ParamType.b64u),
        "qi": JWKParameter("First CRT Coefficient", True, False, ParamType.b64u),
        "oth": JWKParameter("Other Primes Info", True, False, ParamType.unsupported),
    },
    "oct": {
        "k": JWKParameter("Key Value", True, True, ParamType.b64),
    },
    "OKP": {
        "crv": JWKParameter("Curve", False, True, ParamType.name),
        "x": JWKParameter("Public Key", False, True, ParamType.b64),
        "d": JWKParameter("Private Key", True, False, ParamType.b64),
    },
}


class InvalidJwk(ValueError):
    pass


class Jwk(UserDict):
    """
    Represents a Json Web Key (JWK), as specified in RFC7517.
    A JWK is a JSON object that represents a cryptographic key.  The members of the object
    represent properties of the key, including its value.
    """

    def __init__(self, params: Dict[str, Any]):
        self.data = dict(params)
        self.is_private = False
        self._validate()

    def __getattr__(self, item):
        return self.data.get(item)

    def __getitem__(self, item):
        return getattr(self, item)

    def _validate(self):
        if self.kty not in JWKValuesRegistry:
            raise InvalidJwk("Unsupported Key Type (kty)", self.kty)

        params = JWKValuesRegistry.get(self.kty)

        is_private = False

        for name, config in params.items():
            param = getattr(self, name)

            if config.private and param is not None:
                is_private = True

            if not config.private and config.required and param is None:
                raise InvalidJwk(f"Missing required public param {config.description} ({name})")

            if config.type == ParamType.b64:
                try:
                    b64_decode(param)
                except ValueError:
                    InvalidJwk(
                        f"Parameter {config.description} ({name}) must be a Base64-encoded value"
                    )
            elif config.type == ParamType.b64u:
                try:
                    b64u_decode(param)
                except ValueError:
                    InvalidJwk(
                        f"Parameter {config.description} ({name}) must be a Base64URL-encoded value"
                    )
            elif config.type == ParamType.unsupported and param is not None:
                raise InvalidJwk(f"Unsupported JWK param {name}")

        # if at least one of the supplied parameter was private, then all required private parameters must be provided
        if is_private:
            for name, config in params.items():
                param = self.data.get(name)
                if config.private and config.required and param is None:
                    raise InvalidJwk(
                        f"Missing required private param {config.description} ({name})"
                    )

        self.is_private = is_private

    def thumbprint(self, alg: str='SHA256') -> str:
        """Returns the key thumbprint as specified by RFC 7638.

        :param hashalg: A hash function (defaults to SHA256)
        """

        digest = hashlib.new(alg)

        t = {'kty': self.get('kty')}
        for name, val in JWKValuesRegistry[t['kty']].items():
            if val.required and not val.private:
                t[name] = self.get(name)

        intermediary = json.dumps(t, separators=(',', ':'), sort_keys=True)
        digest.update(intermediary.encode('utf8'))
        return b64u_encode(digest.digest())

    @classmethod
    def symetric(
        cls,
        k: str,
        kid: str = None,
        alg: str = None,
        use: str = None,
        key_ops: Iterable[str] = None,
    ):
        return cls(dict(key="oct", k=k, kid=kid, alg=alg, use=use, key_ops=key_ops))

    @classmethod
    def public_RSA(
        cls,
        n: str,
        e: str,
        kid: str = None,
        alg: str = None,
        use: str = None,
        key_ops: Iterable[str] = None,
    ):
        return cls(dict(kty="RSA", n=n, e=e, kid=kid, alg=alg, use=use, key_ops=key_ops))

    @classmethod
    def private_RSA(
        cls,
        n: int,
        e: int,
        d: int,
        p: int,
        q: int,
        dp: int,
        dq: int,
        qi: int,
        kid: str = None,
        alg: str = None,
        use: str = None,
        key_ops: Iterable[str] = None,
    ):
        return cls(
            dict(
                kty="RSA",
                kid=kid,
                alg=alg,
                use=use,
                key_ops=key_ops,
                n=int_to_b64u(n),
                e=int_to_b64u(e),
                d=int_to_b64u(d),
                p=int_to_b64u(p),
                q=int_to_b64u(q),
                dp=int_to_b64u(dp),
                dq=int_to_b64u(dq),
                qi=int_to_b64u(qi),
            )
        )

    @classmethod
    def public_EC(
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
    def private_EC(
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

    def public_jwk(self):
        params = {
            name: self.data.get(name)
            for name, config in JWKValuesRegistry.get(self.kty).items()
            if not config.private
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

    @classmethod
    def generate_RSA(cls, key_size: int = 4096, **params):
        private_key = rsa.generate_private_key(65537, key_size=key_size)
        pn = private_key.private_numbers()
        return cls.private_RSA(
            n=pn.public_numbers.n,
            e=pn.public_numbers.e,
            d=pn.d,
            p=pn.p,
            q=pn.q,
            dp=pn.dmp1,
            dq=pn.dmq1,
            qi=pn.iqmp,
            **params
        )

    @classmethod
    def generate_EC(cls, crv: str):
        pass


def int_to_b64u(i: int):
    length = (i.bit_length() + 7) // 8
    data = i.to_bytes(length, "big", signed=False)
    return b64u_encode(data)


JWKType = Union[Dict[str, Any], Jwk]


class JwkSet:
    """
    A set of JWK keys, with methods for easy management of keys.
    """

    def __init__(self, jwks: Optional[Iterable[Jwk]] = None):
        self.keys: Dict[str, JWKType] = {}
        self.uses: Dict[str, List[str]] = defaultdict(list)

        for jwk in jwks:
            self.add_jwk(jwk)

    def __iter__(self) -> Iterable[JWKType]:
        for key in self.keys:
            yield key

    def __getitem__(self, kid: str) -> JWKType:
        return self.keys[kid]

    @property
    def jwks(self) -> Dict[str, JWKType]:
        return {"keys": self.keys}

    def add_jwk(
        self,
        jwk: JWKType,
        kid: Optional[str] = None,
        use: Optional[str] = None,
        alg: Optional[str] = None,
        key_ops: Optional[Iterable[str]] = None,
    ) -> None:
        if not isinstance(jwk, Jwk):
            jwk = Jwk(jwk)
        use = jwk.use or use
        if not use:
            raise ValueError("Each JWK in a Jwks must have a Public Key Use (use)")
        kid = jwk.get("kid") or kid
        if not kid:
            kid = self.get_default_kid(jwk, use)
        jwk["kid"] = kid
        jwk["use"] = use
        self.keys[kid] = jwk
        self.uses[use].append(kid)

    def remove_jwk(self, kid: str) -> None:
        jwk = self[kid]
        kid = jwk["kid"]
        use = jwk["use"]
        self.uses[use].remove(kid)

    def get_default_kid(self, jwk: JWKType, use: str):
        kid = f"{use}_{datetime.now():%Y%m%d}"
        # avoid overwriting existing keys
        if kid not in self.keys:
            return kid

        for i in count():
            kid_i = f"{kid}_{i}"
            if kid_i not in self.keys:
                return kid_i

    def get_jwk_by_kid(self, kid: str) -> JWKType:
        return self.keys.get(kid)

    def get_jwk_by_use(self, use: str) -> JWKType:
        kids = self.uses.get(use)
        if not kids:
            return None
        kid = kids[-1]
        return self.keys.get(kid)

    def get_signing_jwk(self) -> Dict[str, Any]:
        return self.get_jwk_by_use("sig")

    def get_encryption_jwk(self) -> Dict[str, Any]:
        return self.get_jwk_by_use("enc")
