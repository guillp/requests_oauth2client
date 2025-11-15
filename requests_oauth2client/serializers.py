"""Contain utility classes for serializing/deserializing objects such as `BearerToken`, `AuthorizationRequest`, etc.

Those objects are typically stored in session when used in Web Applications, so they must be easily (de)serializable
to/from strings.

While those classes provide default implementation that should work well for most cases, you might have to customize,
subclass or replace those classes to support custom features from your application.

"""

from __future__ import annotations

from abc import ABC
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable, ClassVar, Generic, TypeVar, Union

import jwskate
from attr import asdict, field, frozen
from binapy import BinaPy

from .authorization_request import (
    AuthorizationRequest,
    RequestParameterAuthorizationRequest,
    RequestUriParameterAuthorizationRequest,
)
from .dpop import DPoPKey, DPoPToken
from .exceptions import UnsupportedTokenTypeError
from .tokens import BearerToken

if TYPE_CHECKING:
    from collections.abc import Mapping


T = TypeVar("T")


@frozen
class Serializer(ABC, Generic[T]):
    """Abstract class for (de)serializers."""

    dumper: Callable[[T], bytes] = field(repr=False)
    loader: Callable[[bytes], dict[str, Any]] = field(repr=False)
    make_instance: Callable[[Mapping[str, Any]], T] = field(repr=False)

    def dumps(self, instance: T) -> bytes:
        """Serialize and compress a given token for easier storage.

        Args:
            instance: a BearerToken to serialize

        Returns:
            the serialized token, as a str

        """
        return self.dumper(instance)

    def loads(self, serialized: bytes) -> T:
        """Deserialize a serialized token.

        Args:
            serialized: the serialized token

        Returns:
            the deserialized token

        """
        data = self.loader(serialized)
        return self.make_instance(data)


@frozen
class TokenSerializer(Serializer[BearerToken]):
    """A helper class to serialize Token Response returned by an AS.

    This may be used to store BearerTokens in session or cookies.

    It needs a `dumper` and a `loader` functions that will respectively serialize and deserialize
    BearerTokens (or subclasses).

    Default implementation uses gzip and base64url on the serialized JSON representation.
    It supports `BearerToken` and `DPoPToken` instances.

    """

    dumper: Callable[[BearerToken], bytes] = field(repr=False, factory=lambda: TokenSerializer.default_dumper)
    loader: Callable[[bytes], dict[str, Any]] = field(repr=False, factory=lambda: TokenSerializer.default_loader)
    make_instance: Callable[[Mapping[str, Any]], BearerToken] = field(
        repr=False, factory=lambda: TokenSerializer.default_make_instance
    )

    @classmethod
    def default_make_instance(cls, args: Mapping[str, Any]) -> BearerToken:
        """Instantiate the appropriate Token class, based on `token_type` in the provided `args`.

        This default implementation only supports "Bearer" and "DPoP" token_types,
        and will deserialize to `BearerToken`  and `DPoPToken` instances.
        """
        token_type = args["token_type"].lower()
        if token_type == "bearer":
            return BearerToken(**args)
        if token_type == "dpop":
            return DPoPToken(**args)
        raise UnsupportedTokenTypeError(token_type)

    @classmethod
    def default_dumper(cls, token: BearerToken) -> bytes:
        """Serialize a token as JSON, then compress with deflate, then encodes as base64url.

        Args:
            token: the `BearerToken` to serialize

        Returns:
            the serialized value

        """
        d = token.as_dict(with_expires_in=False)
        return BinaPy.serialize_to("json", {k: w for k, w in d.items() if w is not None}).to("deflate").to("b64u")

    @classmethod
    def default_loader(cls, serialized: bytes) -> dict[str, Any]:
        """Deserialize a BearerToken.

        This does the opposite operations than `default_dumper`.

        Args:
            serialized: The serialized token.

        Returns:
            a `BearerToken` or one of its subclasses.

        """
        args: dict[str, Any] = BinaPy(serialized).decode_from("b64u").decode_from("deflate").parse_from("json")
        expires_at = args.get("expires_at")
        if expires_at:
            args["expires_at"] = datetime.fromtimestamp(expires_at, tz=timezone.utc)

        dpop_key = args.get("dpop_key")
        if dpop_key:
            dpop_key["private_key"] = jwskate.Jwk(dpop_key["private_key"])
            args["_dpop_key"] = DPoPKey(**args.pop("dpop_key"))

        return args


@frozen
class DPoPKeySerializer(Serializer[DPoPKey]):
    """A (de)serializer for `DPoPKey` instances."""

    dumper: Callable[[DPoPKey], bytes] = field(factory=lambda: DPoPKeySerializer.default_dumper)
    loader: Callable[[bytes], dict[str, Any]] = field(factory=lambda: DPoPKeySerializer.default_loader)
    make_instance: Callable[[Mapping[str, Any]], DPoPKey] = field(
        repr=False, factory=lambda: DPoPKeySerializer.default_make_instance
    )

    @classmethod
    def default_make_instance(cls, args: Mapping[str, Any]) -> DPoPKey:
        """Instantiate the appropriate `DPoPKey` class based on `args`.

        Default implementation always returns `DPoPKey`.
        """
        return DPoPKey(**args)

    @classmethod
    def default_dumper(cls, dpop_key: DPoPKey) -> bytes:
        """Provide a default dumper implementation.

        This will not serialize jti_generator, iat_generator, and dpop_token_class!

        """
        d = dpop_key.private_key.to_dict()
        d.pop("jti_generator", None)
        d.pop("iat_generator", None)
        d.pop("dpop_token_class", None)
        return BinaPy.serialize_to("json", d).to("deflate").to("b64u")

    @classmethod
    def default_loader(
        cls,
        serialized: bytes,
    ) -> dict[str, Any]:
        """Provide a default deserializer implementation.

        This will not deserialize iat_generator, iat_generator, and dpop_token_class!

        """
        private_key = BinaPy(serialized).decode_from("b64u").decode_from("deflate").parse_from("json")
        return {"private_key": private_key}


@frozen
class AuthorizationRequestSerializer(
    Serializer[
        Union[AuthorizationRequest, RequestParameterAuthorizationRequest, RequestUriParameterAuthorizationRequest]
    ]
):
    """(De)Serializer for `AuthorizationRequest` instances.

    Default implementation supports `AuthorizationRequest`, `RequestParameterAuthorizationRequest`, and
    `RequestUriParameterAuthorizationRequest`.

    """

    dumper: Callable[
        [AuthorizationRequest | RequestParameterAuthorizationRequest | RequestUriParameterAuthorizationRequest], bytes
    ] = field(factory=lambda: AuthorizationRequestSerializer.default_dumper)
    loader: Callable[
        [
            bytes,
        ],
        dict[str, Any],
    ] = field(factory=lambda: AuthorizationRequestSerializer.default_loader)
    make_instance: Callable[
        [Mapping[str, Any]],
        AuthorizationRequest | RequestParameterAuthorizationRequest | RequestUriParameterAuthorizationRequest,
    ] = field(repr=False, factory=lambda: AuthorizationRequestSerializer.default_make_instance)

    dpop_key_serializer: ClassVar[Serializer[DPoPKey]] = DPoPKeySerializer()

    @classmethod
    def default_make_instance(
        cls, args: Mapping[str, Any]
    ) -> AuthorizationRequest | RequestParameterAuthorizationRequest | RequestUriParameterAuthorizationRequest:
        """Provide a default get_class implementation.

        - If there is a `request` parameter in the authorization request parameters,
          this returns `RequestParameterAuthorizationRequest`.
        - If there is a `request_uri` parameter in the authorization request parameters,
          this returns `RequestUriParameterAuthorizationRequest`.
        - Otherwise, returns `AuthorizationRequest`.

        Args:
            args: the token attributes and values.

        Returns:
            The appropriate AuthorizationRequest class.

        """
        if "request" in args:
            return RequestParameterAuthorizationRequest(**args)
        if "request_uri" in args:
            return RequestUriParameterAuthorizationRequest(**args)
        return AuthorizationRequest(**args)

    @classmethod
    def default_dumper(
        cls,
        azr: AuthorizationRequest | RequestParameterAuthorizationRequest | RequestUriParameterAuthorizationRequest,
    ) -> bytes:
        """Provide a default dumper implementation.

        Serialize an AuthorizationRequest as JSON, then compress with deflate, then encodes as
        base64url.

        Args:
            azr: the `AuthorizationRequest` to serialize

        Returns:
            the serialized value

        """
        d = asdict(azr)
        if azr.dpop_key:
            d["dpop_key"] = cls.dpop_key_serializer.dumps(azr.dpop_key)
        d.update(**d.pop("kwargs", {}))
        return BinaPy.serialize_to("json", d).to("deflate").to("b64u")

    @classmethod
    def default_loader(
        cls,
        serialized: bytes,
    ) -> dict[str, Any]:
        """Provide a default deserializer implementation.

        This does the opposite operations than `default_dumper`.

        Args:
            serialized: the serialized AuthorizationRequest

        Returns:
            an AuthorizationRequest

        """
        args: dict[str, Any] = BinaPy(serialized).decode_from("b64u").decode_from("deflate").parse_from("json")

        if args["dpop_key"]:
            args["dpop_key"] = cls.dpop_key_serializer.loads(args["dpop_key"])

        return args
