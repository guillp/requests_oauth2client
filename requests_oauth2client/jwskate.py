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
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    Tuple,
    Type,
    Union,
    cast,
)

import cryptography.exceptions
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    ed448,
    ed25519,
    padding,
    rsa,
    x448,
    x25519,
)
from cryptography.hazmat.primitives.ciphers import aead

from .utils import b64u_decode, b64u_encode, b64u_encode_json, json_encode


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
if TYPE_CHECKING:  # pragma: no cover
    _BaseJwk = UserDict[str, Any]
else:
    _BaseJwk = UserDict


class Jwk(_BaseJwk):
    """
    Represents a Json Web Key (JWK), as specified in RFC7517.
    A JWK is a JSON object that represents a cryptographic key.  The members of the object
    represent properties of the key, including its value.
    Just like a parsed JSON object, a :class:`Jwk` is a dict, so you can do with a Jwk anything you can do with a `dict`.
    In addition, all keys parameters are exposed as attributes.
    There are subclasses of `Jwk` for each specific Key Type, but you shouldn't have to use the subclasses directly
    since they all present a common interface.
    """

    kty: str
    """The Key Type associated with this JWK."""

    subclasses: Dict[str, Type["Jwk"]] = {}
    """A dict of subclasses implementing each specific Key Type"""

    PARAMS: Dict[str, Tuple[str, bool, bool, str]]
    """A dict of parameters. Key is parameter name, value is a tuple (description, is_private, is_required, kind)"""

    def __init_subclass__(cls) -> None:
        """
        Automatically add subclasses to the registry.
        This allows __new__ to pick the appropriate subclass when creating a Jwk
        """
        Jwk.subclasses[cls.kty] = cls

    def __new__(cls, jwk: Dict[str, Any]):  # type: ignore
        """
        Overrided `__new__` to allow Jwk to accept a `dict` with the parsed Jwk content
        and return the appropriate subclass based on its `kty`.
        :param jwk:
        """
        if cls == Jwk:
            if jwk.get("keys"):  # if this is a JwkSet
                jwks = JwkSet(jwk)
                return jwks
            kty: Optional[str] = jwk.get("kty")
            if kty is None:
                raise ValueError("A Json Web Key must have a Key Type (kty)")
            subclass = Jwk.subclasses.get(kty)
            if subclass is None:
                raise ValueError("Unsupported Key Type", kty)
            return super().__new__(subclass)
        return super().__new__(cls)

    def __init__(self, params: Dict[str, Any], kid: Optional[str] = None):
        """
        Initialize a Jwk. Accepts a `dict` with the parsed Jwk contents, and an optional kid if it isn't already part
        of the dict.
        If no `kid` is supplied either way, a default kid is generated based on the key thumbprint (defined in RFC7638)
        :param params: a dict with the parsed Jwk parameters.
        :param kid: a Key Id to use if no `kid` parameters is present in `params`.
        """
        self.data = dict(params)
        self.is_private = False
        self._validate()
        if self.kid is None:
            self.data["kid"] = kid or self.thumbprint()

    def __getattr__(self, item: str) -> Any:
        """
        Allows access to key parameters as attributes, like `jwk.kid`, `jwk.kty`, instead of `jwk['kid']`, `jwk['kty']`, etc.
        :param item:
        :return:
        """
        return self.data.get(item)

    def public_jwk(self) -> "Jwk":
        """
        Returns the public Jwk associated with this private Jwk.
        :return: a Jwk containing only the public parameters.
        """
        if not self.is_private:
            return self

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

    def thumbprint(self, hashalg: str = "SHA256") -> str:
        """Returns the key thumbprint as specified by RFC 7638.

        :param hashalg: A hash function (defaults to SHA256)
        """

        digest = hashlib.new(hashalg)

        t = {"kty": self.get("kty")}
        for name, (description, private, required, kind) in self.PARAMS.items():
            if required and not private:
                t[name] = self.get(name)

        intermediary = json.dumps(t, separators=(",", ":"), sort_keys=True)
        digest.update(intermediary.encode("utf8"))
        return b64u_encode(digest.digest())

    def _validate(self) -> None:
        """
        Internal method used to validate a Jwk. It checks that all required parameters are present and well-formed.
        If the key is private, it sets the `is_private` flag to `True`.
        """
        is_private = False
        for name, (description, private, required, kind) in self.PARAMS.items():

            value = getattr(self, name)

            if private and value is not None:
                is_private = True

            if not private and required and value is None:
                raise InvalidJwk(
                    f"Missing required public param {description} ({name})"
                )

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
                    raise InvalidJwk(
                        f"Missing required private param {description} ({name})"
                    )

        self.is_private = is_private

    def sign(self, data: bytes, alg: Optional[str]) -> bytes:
        """
        Signs a data using this Jwk, and returns the signature.
        This is implemented by subclasses.
        :param data: the data to sign
        :param alg: the alg to use (if this key doesn't have an `alg` parameter).
        :return: the generated signature.
        """
        raise NotImplementedError  # pragma: no cover

    def verify(
        self, data: bytes, signature: bytes, alg: Union[str, Iterable[str], None]
    ) -> bool:
        """
        Verifies a signature using this Jwk, and returns `True` if valid.
        This is implemented by subclasses.
        :param data: the data to verify
        :param signature: the signature to verify
        :param alg: the alg to use to verify the signature (if this key doesn't have an `alg` parameter)
        :return: `True` if the signature matches, `False` otherwise
        """
        raise NotImplementedError  # pragma: no cover

    def encrypt(
        self,
        plaintext: bytes,
        aad: Optional[bytes] = None,
        alg: Optional[str] = None,
        iv: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes]:
        """
        Encrypts a data using this Jwk, and returns the encrypted result.
        This is implemented by subclasses.
        :param data: the data to encrypt
        :param alg: the alg to use for encryption
        :return: the enrypted data
        """
        raise NotImplementedError  # pragma: no cover

    def decrypt(
        self,
        cyphertext: bytes,
        iv: bytes,
        tag: Optional[bytes] = None,
        alg: Optional[str] = None,
    ) -> bytes:
        """
        Decrypts an encrypted data using this Jwk, and returns the encrypted result.
        This is implemented by subclasses.
        :param data: the data to decrypt
        :param alg: the alg to use for decryption
        :return: the clear-text data
        """
        raise NotImplementedError  # pragma: no cover

    @property
    def supported_signing_algorithms(self) -> List[str]:
        """
        Returns a list of signing algs that are compatible for use with this Jwk.
        :return: a list of signing algs
        """
        raise NotImplementedError  # pragma: no cover


class SymetricJwk(Jwk):
    """
    Implement Symetric keys, with `"kty": "oct"`.
    """

    kty = "oct"
    PARAMS = {
        # name: ("Description", is_private, is_required, "kind"),
        "k": ("Key Value", True, True, "b64u"),
    }

    SIGNATURE_ALGORITHMS = {
        # name: (MAC, alg, min_key_size)
        "HS256": (hmac.HMAC, hashes.SHA256(), 256),
        "HS384": (hmac.HMAC, hashes.SHA384(), 384),
        "HS512": (hmac.HMAC, hashes.SHA512(), 512),
    }

    ENCRYPTION_ALGORITHMS = {
        # name: (description, alg, key_size, iv_size, tag_size),
        "A128CBC-HS256": ("AES_128_CBC_HMAC_SHA_256", aead.AESCCM, 128, 96, 16),
        "A192CBC-HS384": ("AES_192_CBC_HMAC_SHA_384", aead.AESCCM, 192, 96, 24),
        "A256CBC-HS512": ("AES_128_CBC_HMAC_SHA_256", aead.AESCCM, 256, 96, 32),
        "A128GCM": ("AES GCM using 128-bit key", aead.AESGCM, 128, 96, 16),
        "A192GCM": ("AES GCM using 192-bit key", aead.AESGCM, 192, 96, 16),
        "A256GCM": ("AES GCM using 256-bit key", aead.AESGCM, 256, 96, 16),
    }

    @classmethod
    def from_bytes(cls, k: Union[bytes, str], **params: str) -> "SymetricJwk":
        """
        Initializes a SymetricJwk from a raw secret key.
        The provided secret key is encoded and used as the `k` parameter for the returned SymetricKey.
        :param k: the key to use
        :param params: additional parameters for the returned Jwk
        :return: a SymetricJwk
        """
        return cls(dict(key="oct", k=b64u_encode(k), **params))

    @classmethod
    def generate(cls, size: int = 128, **params: str) -> "SymetricJwk":
        """
        Generates a random SymetricJwk, with a given key size.
        :param size: the size of the generated key, in bytes.
        :param params: additional parameters for the returned Jwk
        :return: a SymetricJwk with a random key
        """
        key = secrets.token_bytes(size)
        return cls.from_bytes(key, **params)

    @classmethod
    def generate_for_alg(cls, alg: str, **params: str) -> "SymetricJwk":
        if alg in cls.SIGNATURE_ALGORITHMS:
            _, _, min_key_size = cls.SIGNATURE_ALGORITHMS[alg]
            return cls.generate(min_key_size, alg=alg, **params)
        if alg in cls.ENCRYPTION_ALGORITHMS:
            _, _, key_size, _, _ = cls.ENCRYPTION_ALGORITHMS[alg]
            return cls.generate(key_size, alg=alg, **params)

    @property
    def key(self) -> bytes:
        """
        Returns the raw symetric key.
        :return: the key from the `k` parameter, base64u-decoded.
        """
        return b64u_decode(self.k)

    @property
    def key_size(self) -> int:
        return len(self.key) * 8

    def sign(self, data: bytes, alg: Optional[str] = "HS256") -> bytes:
        alg = self.alg or alg
        if alg is None:
            raise ValueError("a signing alg is required")
        try:
            mac, hashalg, min_key_size = self.SIGNATURE_ALGORITHMS[alg]
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
                mac, hashalg, min_key_size = self.SIGNATURE_ALGORITHMS[alg]
            except KeyError:
                raise ValueError("Unsupported signing alg", alg)

            m = mac(self.key, hashalg)
            m.update(data)
            candidate_signature = m.finalize()
            if signature == candidate_signature:
                return True

        return False

    @property
    def supported_signing_algorithms(self) -> List[str]:
        return list(self.SIGNATURE_ALGORITHMS.keys())

    def encrypt(
        self,
        plaintext: bytes,
        aad: Optional[bytes] = None,
        alg: Optional[str] = None,
        iv: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes]:
        alg = self.alg or alg
        if alg is None:
            raise ValueError("An encryption alg is required")

        (
            description,
            alg_class,
            key_size,
            iv_size,
            tag_size,
        ) = self.ENCRYPTION_ALGORITHMS[alg]

        if self.key_size != key_size:
            raise ValueError(
                f"This key size of {self.key_size} doesn't match the expected keysize for {description} of {key_size} bits"
            )

        if iv is None:
            iv = secrets.token_bytes(iv_size)

        alg_key = alg_class(self.key)
        cyphertext_with_tag = alg_key.encrypt(iv, plaintext, aad)
        cyphertext = cyphertext_with_tag[:-tag_size]
        tag = cyphertext_with_tag[-tag_size:]

        return cyphertext, tag

    def decrypt(
        self,
        cyphertext: bytes,
        iv: bytes,
        tag: Optional[bytes] = None,
        aad: Optional[bytes] = None,
        alg: Optional[str] = None,
    ) -> bytes:
        alg = self.alg or alg
        if alg is None:
            raise ValueError("An encryption alg is required")

        (
            description,
            alg_class,
            key_size,
            iv_size,
            tag_size,
        ) = self.ENCRYPTION_ALGORITHMS[alg]

        if self.key_size != key_size:
            raise ValueError(
                f"This key size of {self.key_size} doesn't match the expected keysize for {description} of {key_size} bits"
            )

        alg_key = alg_class(self.key)
        plaintext = alg_key.decrypt(iv, cyphertext + tag, aad)

        return plaintext


class RSAJwk(Jwk):
    """
    Represents a RSA Jwk, with `"kid": "RSA"`.
    """

    kty = "RSA"

    PARAMS = {
        # name: ("Description", is_private, is_required, "kind"),
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

    SIGNATURE_ALGORITHMS = {
        # name : (description, padding_alg, hash_alg)
        "RS256": (
            "RSASSA-PKCS1-v1_5 using SHA-256",
            padding.PKCS1v15(),
            hashes.SHA256(),
        ),
        "RS384": (
            "RSASSA-PKCS1-v1_5 using SHA-384",
            padding.PKCS1v15(),
            hashes.SHA384(),
        ),
        "RS512": (
            "RSASSA-PKCS1-v1_5 using SHA-256",
            padding.PKCS1v15(),
            hashes.SHA512(),
        ),
    }

    KEY_MANAGEMENT_ALGORITHMS = {
        # name: ("description", alg)
        "RSA1_5": ("RSAES-PKCS1-v1_5", padding.PKCS1v15()),
        "RSA-OAEP": (
            "RSAES OAEP using default parameters",
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None,
            ),
        ),
        "RSA-OAEP-256": (
            "RSAES OAEP using SHA-256 and MGF1 with with SHA-256",
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        ),
    }

    @property
    def modulus(self) -> int:
        """
        Returns the modulus from this Jwk.
        :return: the key modulus (from parameter `n`)
        """
        return b64u_to_int(self.n)

    @property
    def exponent(self) -> int:
        """
        Returns the exponent from this Jwk.
        :return: the key exponent (from parameter `e`)
        """
        return b64u_to_int(self.e)

    @property
    def private_exponent(self) -> int:
        """
        Returns the private exponent from this Jwk.
        :return: the key private exponent (from parameter `d`)
        """
        return b64u_to_int(self.d)

    @property
    def first_prime_factor(self) -> int:
        """
        Returns the first prime factor from this Jwk.
        :return: the first prime factor (from parameter `p`)
        """
        return b64u_to_int(self.p)

    @property
    def second_prime_factor(self) -> int:
        """
        Returns the second prime factor from this Jwk.
        :return: the second prime factor (from parameter `q`)
        """
        return b64u_to_int(self.q)

    @property
    def first_factor_crt_exponent(self) -> int:
        return b64u_to_int(self.dp)

    @property
    def second_factor_crt_exponent(self) -> int:
        return b64u_to_int(self.dq)

    @property
    def first_crt_coefficient(self) -> int:
        """
        Returns the first CRT coefficient from this Jwk
        :return: he first CRT coefficient (from parameter `qi`)
        """
        return b64u_to_int(self.qi)

    @classmethod
    def public(cls, n: int, e: int, **params: str) -> "RSAJwk":
        """
        Initialize a Public RsaJwk from a modulus and an exponent.
        :param n: the modulus
        :param e: the exponent
        :param params: additional parameters for the return RSAJwk
        :return: a RsaJwk
        """
        return cls(dict(kty="RSA", n=int_to_b64u(n), e=int_to_b64u(e), **params))

    @classmethod
    def private(
        cls,
        n: int,
        e: int,
        d: int,
        p: int,
        q: int,
        dp: int,
        dq: int,
        qi: int,
        **params: str,
    ) -> "RSAJwk":
        """
        Initializes a Private RsaJwk from its required parameters.
        :param n: the modulus
        :param e: the exponent
        :param d: the private exponent
        :param p: the first prime factor
        :param q: the second prime factor
        :param dp: the first factor CRT exponent
        :param dq: the second factor CRT exponent
        :param qi: the first CRT coefficient
        :param params: additional parameters for the return RSAJwk
        :return:
        """
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
        """
        Generates a new random Private RSAJwk.
        :param key_size: the key size to use for the generated key.
        :param params: additional parameters for the generated RSAJwk
        :return: a generated RSAJwk
        """
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
            description, padding, hashing = self.SIGNATURE_ALGORITHMS[alg]
        except KeyError:
            raise ValueError("Unsupported signing alg", alg)

        return key.sign(data, padding, hashing)

    def verify(
        self,
        data: bytes,
        signature: bytes,
        alg: Union[str, Iterable[str], None] = "RS256",
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
                description, padding, hashing = self.SIGNATURE_ALGORITHMS[alg]
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

    @property
    def supported_signing_algorithms(self) -> List[str]:
        return list(self.SIGNATURE_ALGORITHMS.keys())

    def encrypt_cek(self, cek: bytes, alg: Optional[str] = None) -> bytes:
        alg = self.alg or alg
        if alg is None:
            raise ValueError("an encryption alg is required")
        description, padding_alg = self.KEY_MANAGEMENT_ALGORITHMS[alg]

        public_key = rsa.RSAPublicNumbers(e=self.exponent, n=self.modulus).public_key()

        cyphertext = public_key.encrypt(cek, padding_alg)

        return cyphertext

    def decrypt_cek(self, enc_cek, alg: Optional[str] = None) -> bytes:
        alg = self.alg or alg
        if alg is None:
            raise ValueError("an encryption alg is required")
        description, padding_alg = self.KEY_MANAGEMENT_ALGORITHMS[alg]

        key = rsa.RSAPrivateNumbers(
            self.first_prime_factor,
            self.second_prime_factor,
            self.private_exponent,
            self.first_factor_crt_exponent,
            self.second_factor_crt_exponent,
            self.first_crt_coefficient,
            rsa.RSAPublicNumbers(self.exponent, self.modulus),
        ).private_key()

        plaintext = key.decrypt(enc_cek, padding_alg)

        return plaintext


class ECJwk(Jwk):
    """
    Represents an Elliptic Curve Jwk, with `"kty": "EC"`.
    """

    kty = "EC"

    PARAMS = {
        # name : ("description", is_private, is_required, "kind"),
        "crv": ("Curve", False, True, "name"),
        "x": ("X Coordinate", False, True, "b64u"),
        "y": ("Y Coordinate", False, True, "b64u"),
        "d": ("ECC Private Key", True, True, "b64u"),
    }

    CURVES = {
        # name: curve
        "P-256": ec.SECP256R1(),
        "P-384": ec.SECP384R1(),
        "P-521": ec.SECP521R1(),
        "secp256k1": ec.SECP256K1(),
    }

    SIGNATURE_ALGORITHMS = {
        # name : (description, hash_alg)
        "ES256": ("ECDSA using P-256 and SHA-256", hashes.SHA256()),
        "ES384": ("ECDSA using P-384 and SHA-384", hashes.SHA384()),
        "ES512": ("ECDSA using P-521 and SHA-512", hashes.SHA512()),
    }

    @classmethod
    def public(cls, crv: str, x: str, y: str, **params: str) -> "ECJwk":
        """
        Initializes a public ECJwk from its public paramters.
        :param crv: the curve to use
        :param x: the x coordinate
        :param y: the y coordinate
        :param params: additional parameters for the returned ECJwk
        :return: an ECJwk initialized with the supplied parameters
        """
        return cls(dict(key="EC", crv=crv, x=x, y=y, **params))

    @classmethod
    def private(cls, crv: str, x: str, y: str, d: str, **params: str) -> "ECJwk":
        """
        Initializes a private ECJwk from its private parameters.
        :param crv: the curve to use
        :param x: the x coordinate
        :param y: the y coordinate
        :param d: the elliptic curve private key
        :param params: additional parameters for the returned ECJwk
        :return: an ECJWk initialized with the supplied parameters
        """
        return cls(dict(key="EC", crv=crv, x=x, y=y, d=d, **params))

    @classmethod
    def generate(cls, crv: str = "P-256", **params: str) -> "ECJwk":
        """
        Generates a random ECJwk.
        :param crv: the curve to use
        :param params: additional parameters for the returned ECJwk
        :return: a generated ECJwk
        """
        curve = cls.CURVES.get(crv)
        if curve is None:
            raise ValueError("Unsupported curve", crv)
        key = ec.generate_private_key(curve)
        pn = key.private_numbers()  # type: ignore
        # TODO: check why mypy complains that "EllipticCurvePrivateKey" has no attribute "private_numbers" while it does
        key_size = pn.public_numbers.curve.key_size
        x = int_to_b64u(pn.public_numbers.x, key_size)
        y = int_to_b64u(pn.public_numbers.y, key_size)
        d = int_to_b64u(pn.private_value, key_size)
        return cls.private(crv=crv, x=x, y=y, d=d, **params)

    def sign(self, data: bytes, alg: Optional[str] = "ES256") -> bytes:
        alg = self.alg or alg
        if alg is None:
            raise ValueError("a signing alg is required")

        if not self.is_private:
            raise PrivateKeyRequired("A private key is required for signing")

        key = ec.EllipticCurvePrivateNumbers(
            self.ecc_private_key,
            ec.EllipticCurvePublicNumbers(
                self.x_coordinate, self.y_coordinate, self.CURVES[self.curve]
            ),
        ).private_key()
        try:
            description, hashing = self.SIGNATURE_ALGORITHMS[alg]
        except KeyError:
            raise ValueError("Unsupported signing alg", alg)

        return key.sign(data, ec.ECDSA(hashing))

    def verify(
        self, data: bytes, signature: bytes, alg: Union[str, Iterable[str], None]
    ) -> bool:
        if isinstance(alg, str):
            algs = [alg]
        elif alg is None:
            algs = [self.alg]
        else:
            algs = list(alg)

        public_key = ec.EllipticCurvePublicNumbers(
            self.x_coordinate, self.y_coordinate, self.CURVES[self.curve]
        ).public_key()

        for alg in algs:
            try:
                description, hashing = self.SIGNATURE_ALGORITHMS[alg]
            except KeyError:
                raise ValueError("Unsupported signing alg", alg)

            try:
                public_key.verify(
                    signature,
                    data,
                    ec.ECDSA(hashing),
                )
                return True
            except cryptography.exceptions.InvalidSignature:
                continue

        return False

    @property
    def curve(self) -> str:
        if self.crv not in self.CURVES:
            raise AttributeError("unsupported crv", self.crv)
        return cast(str, self.crv)

    @property
    def x_coordinate(self) -> int:
        """
        Returns the x coordinate from this ECJwk
        :return: the x coordinate (from parameter `x`)
        """
        return b64u_to_int(self.x)

    @property
    def y_coordinate(self) -> int:
        """
        Returns the y coordinate from this ECJwk
        :return: the y coordinate (from parameter `y`)
        """
        return b64u_to_int(self.y)

    @property
    def ecc_private_key(self) -> int:
        """
        Returns the ECC private key from this ECJwk
        :return: the ECC private key (from parameter `d`)
        """
        return b64u_to_int(self.d)

    @property
    def supported_signing_algorithms(self) -> List[str]:
        return list(self.SIGNATURE_ALGORITHMS.keys())


class OKPJwk(Jwk):
    """
    Represents an OKP Jwk (with `"kty": "OKP"`)
    """

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

    SIGNATURE_ALGORITHMS: Dict[str, Tuple[str, hashes.HashAlgorithm]] = {
        # name : (description, hash_alg)
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

    @property
    def supported_signing_algorithms(self) -> List[str]:
        return list(self.SIGNATURE_ALGORITHMS.keys())


def int_to_b64u(i: int, length: Optional[int] = None) -> str:
    """
    Encodes an integer to the base64url encoding of the octet string representation of that integer, as defined in
    Section 2.3.5 of SEC1 [SEC1].
    :param i: the integer to encode
    :param length: the length of the encoding (left padding the integer if necessary)
    :return: the encoded representation
    """
    if length is None:
        length = (i.bit_length() + 7) // 8
    data = i.to_bytes(length, "big", signed=False)
    return b64u_encode(data)


def b64u_to_int(b: str) -> int:
    """
    Decodes a base64url encoding of the octet string representation of an integer.
    :param b: the encoded integer
    :return: the decoded integer
    """
    return int.from_bytes(b64u_decode(b), "big", signed=False)


class JwkSet(_BaseJwk):
    """
    A set of JWK keys, with methods for easy management of keys.
    A JwkSet is a dict subclass, so you can do anything with a JwkSet that you can do with a dict.
    In addition, it provides a few helpers methods to get the keys, add or remove keys, and verify signatures using keys
    from this set.
    """

    def __init__(
        self,
        jwks: Optional[Dict[str, Any]] = None,
        keys: Optional[Iterable[Jwk]] = None,
    ):
        """
        Intiializes a JwkSet. Multiple inputs can be provided:
        - a `dict` from the parsed JSON object representing this JwkSet (in paramter `jwks`)
        - a list of `Jwk` (in parameter `keys`
        - nothing, to initialize an empty JwkSet
        :param jwks: a dict, containing the JwkSet, parsed as a JSON object.
        :param keys: a list of Jwk, that will be added to this JwkSet
        """
        if jwks is not None and keys is not None:
            keys = []

        if jwks is not None:
            keys = jwks.pop("keys", [])
            super().__init__(
                jwks
            )  # init the dict with all the dict content that is not keys
        else:
            super().__init__()

        if keys is not None:
            for jwk in keys:
                self.add_jwk(jwk)

    @property
    def jwks(self) -> List[Jwk]:
        """
        Returns the list of keys from this JwkSet, as `Jwk` instances
        :return: a list of `Jwk`
        """
        return self.data.get("keys", [])

    def get_jwk_by_kid(self, kid: str) -> Optional[Jwk]:
        """
        Returns a Jwk from this JwkSet, based on its kid.
        :param kid:
        :return:
        """
        jwk = next(filter(lambda jwk: jwk.get("kid") == kid, self.jwks), None)
        if isinstance(jwk, Jwk):
            return jwk
        return None

    def __len__(self) -> int:
        """
        Returns the number of Jwk in this JwkSet.
        :return: the number of keys
        """
        return len(self.jwks)

    def add_jwk(
        self,
        jwk: Union[Jwk, Dict[str, Any]],
        kid: Optional[str] = None,
        use: Optional[str] = None,
    ) -> str:
        """
        Adds a Jwk in this JwkSet
        :param jwk: the Jwk to add (either a `Jwk` instance, or a dict containing the Jwk parameters)
        :param kid: the kid to use, if `jwk` doesn't contain one
        :param use: the defined use for the added Jwk
        :return: the kid from the added Jwk (it may be generated if no kid is provided)
        """
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
        """
        Removes a Jwk from this JwkSet, based on a `kid`.
        :param kid: the `kid` from the key to be removed.
        """
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
        """
        Verifies a signature with the key from this key set. It implements multiple techniques to avoid trying all keys:
        If a `kid` is provided, only the key with this `kid` will be tried.
        Otherwise, if an `alg` if provided, only keys that are compatible with the supplied `alg` will be tried.
        Otherwise,
        :param data: the signed data to verify
        :param signature: the signature to verify against the signed data
        :param alg: one or several algs to verify the signature
        :param kid: the kid of the Jwk that will be used to validate the signature. If no kid is provided, multiple keys
        from this key set may be tried.
        :return: `True` if the signature validates with any of the tried keys, `False` otherwise
        """

        # if a kid is provided, try only the key matching `kid`
        if kid is not None:
            jwk = self.get_jwk_by_kid(kid)
            if jwk is not None:
                return jwk.verify(data, signature, alg)

        # if one or several alg are provided, try only the keys that are compatible with one of the provided alg(s)
        algs = [alg] if isinstance(alg, str) else alg
        if algs:
            for jwk in (jwk for jwk in self.jwks if jwk.alg in algs):
                if jwk.verify(data, signature, alg):
                    return True

        # if no kid and no alg are provided, try first the keys flagged for signature verification (`"use": "verify"`)
        for jwk in (jwk for jwk in self.jwks if jwk.use == "verify"):
            if jwk.verify(data, signature, alg):
                return True

        # then with the keys that have no defined `use`
        for jwk in (jwk for jwk in self.jwks if jwk.use is None):
            if jwk.verify(data, signature, alg):
                return True

        # no key matches, so consider the signature invalid
        return False


class InvalidJws(ValueError):
    """Raised when an invalid Jws is parsed"""


class JwsCompact:
    """
    Represents a a Json Web Signature (JWS), using compact serialization, as defined in RFC7515.
    """

    def __init__(self, value: Union[bytes, str]):
        """
        Initializes a Jws, from its compact representation.
        :param value: the Jws value
        """
        if not isinstance(value, bytes):
            value = value.encode("ascii")

        if value.count(b".") != 2:
            raise InvalidJws(
                "A JWS must contain a header, a payload and a signature, separated by dots"
            )

        header, payload, signature = value.split(b".")
        try:
            self.headers = json.loads(b64u_decode(header))
        except ValueError:
            raise InvalidJws(
                "Invalid JWS header: it must be a Base64URL-encoded JSON object"
            )

        try:
            self.payload = b64u_decode(payload)
        except ValueError:
            raise InvalidJws(
                "Invalid JWS payload: it must be a Base64URL-encoded binary data (bytes)"
            )

        try:
            self.signature = b64u_decode(signature)
        except ValueError:
            raise InvalidJws(
                "Invalid JWS signature: it must be a Base64URL-encoded binary data (bytes)"
            )

        self.value = value

    def get_header(self, name: str) -> Any:
        """
        Gets an header from this Jws
        :param name: the header name
        :return: the header value
        """
        return self.headers.get(name)

    @classmethod
    def sign(
        cls,
        payload: bytes,
        jwk: Union[Jwk, Dict[str, Any]],
        alg: Optional[str] = None,
        extra_headers: Optional[Dict[str, Any]] = None,
    ) -> "JwsCompact":
        """
        Signs a payload into a Jws and returns the resulting JwsCompact
        :param payload: the payload to sign
        :param jwk: the jwk to use to sign this payload
        :param alg: the alg to use
        :param extra_headers: additional headers to add to the Jws Headers
        :return: a JwsCompact
        """
        if not isinstance(jwk, Jwk):
            jwk = Jwk(jwk)

        if not jwk.is_private:
            raise ValueError("Signing requires a private JWK")

        alg = alg or jwk.get("alg")
        kid = jwk.get("kid")

        if alg is None:
            raise ValueError("a signing alg is required")

        headers = dict(extra_headers or {}, alg=alg)
        if kid:
            headers["kid"] = kid

        signed_part = cls.assemble_signed_part(headers, payload)
        signature = jwk.sign(signed_part.encode(), alg=alg)
        return cls.from_parts(signed_part, signature)

    @classmethod
    def assemble_signed_part(
        cls, headers: Dict[str, Any], payload: Union[bytes, str]
    ) -> str:
        return ".".join((b64u_encode_json(headers), b64u_encode(payload)))

    @classmethod
    def from_parts(
        cls, signed_part: Union[bytes, str], signature: Union[bytes, str]
    ) -> "JwsCompact":
        if not isinstance(signed_part, bytes):
            signed_part = signed_part.encode("ascii")

        return cls(b".".join((signed_part, b64u_encode(signature).encode())))

    def __str__(self) -> str:
        """
        Returns the `str` representation of this JwsCompact
        :return: a `str`
        """
        return self.value.decode()

    def __bytes__(self) -> bytes:
        """
        Returns the `bytes` representation of this JwsCompact
        :return:
        """
        return self.value

    @property
    def signed_part(self) -> bytes:
        """
        Returns the signed part (header + payload) from this JwsCompact
        :return:
        """
        return b".".join(self.value.split(b".", 2)[:2])

    def verify_signature(self, jwk: Union[Jwk, Dict[str, Any]], alg: str) -> bool:
        """
        Verify the signature from this JwsCompact using a Jwk
        :param jwk: the Jwk to use to validate this signature
        :param alg: the alg to use
        :return: `True` if the signature matches, `False` otherwise
        """
        if not isinstance(jwk, Jwk):
            jwk = Jwk(jwk)
        return jwk.verify(self.signed_part, self.signature, alg)


class InvalidJwe(ValueError):
    """Raised when an invalid Jwe is parsed"""


class JweCompact:
    """
    Represents a Json Web Encryption object, as defined in RFC7516
    """

    def __init__(self, value: Union[bytes, str]):
        """
        Initializes a Jwe based on its compact representation.
        :param value: the compact representation for this Jwe
        """
        if not isinstance(value, bytes):
            value = value.encode("ascii")

        value = b"".join(value.split())

        if value.count(b".") != 4:
            raise InvalidJwe(
                "A JWE must contain a header, an encrypted key, an IV, a cyphertext and an authentication tag, separated by dots"
            )

        header, key, iv, cyphertext, auth_tag = value.split(b".")
        try:
            self.headers = json.loads(b64u_decode(header))
            self.additional_authenticated_data = header
        except ValueError:
            raise InvalidJwe(
                "Invalid JWE header: it must be a Base64URL-encoded JSON object"
            )

        try:
            self.content_encryption_key = b64u_decode(key)
        except ValueError:
            raise InvalidJwe(
                "Invalid JWE cek: it must be a Base64URL-encoded binary data (bytes)"
            )

        try:
            self.initialization_vector = b64u_decode(iv)
        except ValueError:
            raise InvalidJwe(
                "Invalid JWE iv: it must be a Base64URL-encoded binary data (bytes)"
            )

        try:
            self.cyphertext = b64u_decode(cyphertext)
        except ValueError:
            raise InvalidJwe(
                "Invalid JWE cyphertext: it must be a Base64URL-encoded binary data (bytes)"
            )

        try:
            self.authentication_tag = b64u_decode(auth_tag)
        except ValueError:
            raise InvalidJwe(
                "Invalid JWE authentication tag: it must be a Base64URL-encoded binary data (bytes)"
            )

        self.value = value

    def get_header(self, name: str) -> Any:
        """
        Returns an header from this Jwe
        :param name: the header name
        :return: the header value
        """
        return self.headers.get(name)

    def __str__(self):
        return self.value.decode()

    def __bytes__(self):
        return self.value

    @classmethod
    def from_parts(
        cls,
        headers: Dict[str, Any],
        cek: bytes,
        iv: bytes,
        cyphertext: bytes,
        tag: bytes,
    ):
        return cls(
            ".".join(
                (
                    b64u_encode_json(headers),
                    b64u_encode(cek),
                    b64u_encode(iv),
                    b64u_encode(cyphertext),
                    b64u_encode(tag),
                )
            )
        )

    @classmethod
    def encrypt(
        cls,
        plaintext: bytes,
        jwk: Union[Jwk, Dict[str, Any]],
        alg: Optional[str] = None,
        enc: Optional[str] = None,
        extra_headers: Dict[str, Any] = None,
        cek: bytes = None,
        iv: bytes = None,
    ):
        if not isinstance(jwk, Jwk):
            jwk = Jwk(jwk)

        alg = jwk.alg or alg
        enc = jwk.enc or enc

        headers = dict(extra_headers or {}, alg=alg, enc=enc)

        if cek is None:
            cek = SymetricJwk.generate_for_alg(enc)
        else:
            cek = SymetricJwk.from_bytes(cek, alg=enc)

        enc_cek = jwk.encrypt_cek(cek.key, alg)

        if iv is None:
            iv = secrets.token_bytes(96)

        aad = b64u_encode_json(headers).encode()

        cyphertext, tag = cek.encrypt(plaintext=plaintext, aad=aad, iv=iv, alg=enc)

        return cls.from_parts(headers, enc_cek, iv, cyphertext, tag)

    def decrypt(
        self,
        jwk: Union[Jwk, Dict[str, Any]],
        alg: Optional[str] = None,
        enc: Optional[str] = None,
    ) -> bytes:
        """
        Decrypts this Jwe using a Jwk
        :param jwk: the Jwk to use to decrypt this Jwe
        :param alg: the alg to use to decrypt this Jwe
        :return: the decrypted payload
        """
        if not isinstance(jwk, Jwk):
            jwk = Jwk(jwk)

        alg = jwk.alg or alg
        enc = jwk.enc or enc

        raw_cek = jwk.decrypt_cek(self.content_encryption_key, alg)
        cek = SymetricJwk.from_bytes(raw_cek)

        plaintext = cek.decrypt(
            cyphertext=self.cyphertext,
            iv=self.initialization_vector,
            tag=self.authentication_tag,
            aad=self.additional_authenticated_data,
            alg=enc,
        )
        return plaintext


class InvalidJwt(ValueError):
    """Raised when an invalid Jwt is parsed"""

    pass


class Jwt:
    """Represents a Json Web Token"""

    def __new__(cls, value: Union[bytes, str]):  # type: ignore
        """
        Allows parsing both Signed and Encrypted Jwts. Returns the appropriate subclass.
        :param value:
        """
        if not isinstance(value, bytes):
            value = value.encode("ascii")

        if cls == Jwt:
            if value.count(b".") == 2:
                return super().__new__(SignedJwt)
            elif value.count(b".") == 3:
                return super().__new__(EncryptedJwt)
        return super().__new__(cls)

    def __init__(self, value: Union[bytes, str]):
        """
        Initializes an Jwt from its string representation.
        :param value: the string or bytes representation of this Jwt
        """
        if not isinstance(value, bytes):
            value = value.encode("ascii")

        self.value = value
        self.headers: Dict[str, Any]

    def __eq__(self, other: Any) -> bool:
        """
        Checks that a Jwt is equals to another. Works with other instances of Jwt, or with string or bytes.
        :param other: the other token to compare with
        :return: True if the other token has the same representation, False otherwise
        """
        if isinstance(other, Jwt):
            return self.value == other.value
        if isinstance(other, str):
            return self.value == other
        if isinstance(other, bytes):
            return self.value.encode() == other
        return super().__eq__(other)

    def get_header(self, name: str) -> Any:
        """
        Returns an header from this Jwt
        :param name: the header name
        :return: the header value
        """
        return self.headers.get(name)

    @classmethod
    def sign(
        cls,
        claims: Dict[str, Any],
        jwk: Union[Jwk, Dict[str, Any]],
        alg: Optional[str] = None,
        extra_headers: Optional[Dict[str, Any]] = None,
    ) -> "SignedJwt":
        """
        Signs a JSON payload with a Jwk and returns the resulting SignedJwt
        :param claims: the payload to sign
        :param jwk: the Jwk to use for signing
        :param alg: the alg to use for signing
        :param extra_headers: additional headers to include in the Jwt
        :return: a SignedJwt
        """
        if not isinstance(jwk, Jwk):
            jwk = Jwk(jwk)

        if not jwk.is_private:
            raise ValueError("Signing requires a private JWK")

        alg = alg or jwk.get("alg")
        kid = jwk.get("kid")

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
        enc: Optional[str],
    ) -> "EncryptedJwt":
        """
        Sign then encrypts a payload with a Jwk and returns the resulting EncryptedJwt
        :param claims: the payload to encrypt
        :param sign_jwk: the Jwk to use for signature
        :param sign_alg: the alg to use for signature
        :param enc_jwk: the Jwk to use for encryption
        :param enc_alg: the alg to use for CEK encryption
        :param enc: the alg to use for payload encryption
        :return: an EncryptedJwt
        """
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
            raise InvalidJwt(
                "Invalid JWT header: it must be a Base64URL-encoded JSON object"
            )

        try:
            self.claims = json.loads(b64u_decode(payload))
        except ValueError:
            raise InvalidJwt(
                "Invalid JWT payload: it must be a Base64URL-encoded JSON object"
            )

        try:
            self.signature = b64u_decode(signature)
        except ValueError:
            raise InvalidJwt(
                "Invalid JWT signature: it must be a Base64URL-encoded binary data (bytes)"
            )

        self.value = value

    @property
    def signed_part(self) -> str:
        return ".".join(self.value.split(".", 2)[:2])

    def verify_signature(
        self,
        jwk: Union[Jwk, Dict[str, Any]],
        alg: Optional[Union[str, Iterable[str]]] = None,
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
    def audience(self) -> Optional[List[str]]:
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
            if isinstance(sub, str):
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
        audience: Union[None, str, List[str]] = None,
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
    def __init__(self, value: Union[bytes, str]):
        raise NotImplementedError


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
        subject: Optional[str] = None,
        audience: Union[str, Iterable[str], None] = None,
        extra_claims: Optional[Dict[str, Any]] = None,
        extra_headers: Optional[Dict[str, Any]] = None,
        lifetime: Optional[int] = None,
        leeway: Optional[int] = None,
    ) -> Jwt:
        now = datetime.now().timestamp()
        lifetime = lifetime or self.default_lifetime
        exp = now + lifetime
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
            ).items()
            if value is not None
        }
        return Jwt.sign(claims, jwk=self.jwk, alg=self.alg, extra_headers=extra_headers)

    def generate_jti(self) -> str:
        return str(uuid.uuid4())
