"""Contain utility classes for serializing/deserializing objects such as `BearerToken`, `AuthorizationRequest`, etc.

Those objects are typically stored in session when used in Web Applications, so they must be easily (de)serializable
to/from strings.

While those classes provide default implementation that should work well for most cases, you might have to customize,
subclass or replace those classes to support custom features from your application.

"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable, ClassVar, Generic, TypeVar, Union

import jwskate
from attr import asdict, field, frozen
from binapy import BinaPy
from typing_extensions import override

from .authorization_request import (
    AuthorizationRequest,
    RequestParameterAuthorizationRequest,
    RequestUriParameterAuthorizationRequest,
)
from .dpop import DPoPKey, DPoPToken
from .tokens import BearerToken

if TYPE_CHECKING:
    from collections.abc import Mapping


T = TypeVar("T")


@frozen
class Serializer(Generic[T], ABC):
    """Abstract class for (de)serializers."""

    dumper: Callable[[T], str] = field(repr=False)
    loader: Callable[[str, Callable[[Mapping[str, Any]], type[T]]], T] = field(repr=False)

    @abstractmethod
    def get_class(self, args: Mapping[str, Any]) -> type[T]:
        """Based on the parsed key/val mapping,return the appropriate class to use for deserialization.

        This must be implemented by subclasses.

        Parameters:
            args: a key/value mapping, parsed from the serialized string, that will be used to

        """

    def dumps(self, token: T) -> str:
        """Serialize and compress a given token for easier storage.

        Args:
            token: a BearerToken to serialize

        Returns:
            the serialized token, as a str

        """
        return self.dumper(token)

    def loads(self, serialized: str) -> T:
        """Deserialize a serialized token.

        Args:
            serialized: the serialized token

        Returns:
            the deserialized token

        """
        return self.loader(serialized, self.get_class)


@frozen
class BearerTokenSerializer(Serializer[BearerToken]):
    """A helper class to serialize Token Response returned by an AS.

    This may be used to store BearerTokens in session or cookies.

    It needs a `dumper` and a `loader` functions that will respectively serialize and deserialize
    BearerTokens (or subclasses).

    Default implementation uses gzip and base64url on the serialized JSON representation.
    It supports `BearerToken` and `DPoPToken` instances.

    """

    dumper: Callable[[BearerToken], str] = field(repr=False, factory=lambda: BearerTokenSerializer.default_dumper)
    loader: Callable[[str, Callable[[Mapping[str, Any]], type[BearerToken]]], BearerToken] = field(
        repr=False, factory=lambda: BearerTokenSerializer.default_loader
    )

    @override
    def get_class(self, args: Mapping[str, Any]) -> type[BearerToken]:
        token_type = args["token_type"]
        return {
            "bearer": BearerToken,
            "dpop": DPoPToken,
        }.get(token_type.lower(), BearerToken)

    @classmethod
    def default_dumper(cls, token: BearerToken) -> str:
        """Serialize a token as JSON, then compress with deflate, then encodes as base64url.

        Args:
            token: the `BearerToken` to serialize

        Returns:
            the serialized value

        """
        d = asdict(token)
        d.update(**d.pop("kwargs", {}))
        if isinstance(token, DPoPToken):
            d["dpop_key"]["private_key"] = token.dpop_key.private_key.to_dict()
            d["dpop_key"].pop("jti_generator", None)
            d["dpop_key"].pop("iat_generator", None)
            d["dpop_key"].pop("dpop_token_class", None)
        return (
            BinaPy.serialize_to("json", {k: w for k, w in d.items() if w is not None}).to("deflate").to("b64u").ascii()
        )

    @classmethod
    def default_loader(
        cls, serialized: str, get_class: Callable[[Mapping[str, Any]], type[BearerToken]]
    ) -> BearerToken:
        """Deserialize a BearerToken.

        This does the opposite operations than `default_dumper`.

        Args:
            serialized: The serialized token.
            get_class: A callable that takes the key/value mapping as input and returns the appropriate class to use.

        Returns:
            a BearerToken

        """
        args = BinaPy(serialized).decode_from("b64u").decode_from("deflate").parse_from("json")
        expires_at = args.get("expires_at")
        if expires_at:
            args["expires_at"] = datetime.fromtimestamp(expires_at, tz=timezone.utc)

        dpop_key = args.get("dpop_key")
        if "dpop_key" in args:
            dpop_key["private_key"] = jwskate.Jwk(dpop_key["private_key"])
            args["_dpop_key"] = DPoPKey(**args.pop("dpop_key"))

        token_class = get_class(args)
        return token_class(**args)


@frozen
class DPoPKeySerializer(Serializer[DPoPKey]):
    """A (de)serializer for `DPoPKey` instances."""

    dumper: Callable[[DPoPKey], str] = field(factory=lambda: DPoPKeySerializer.default_dumper)
    loader: Callable[[str, Callable[[Mapping[str, Any]], type[DPoPKey]]], DPoPKey] = field(
        factory=lambda: DPoPKeySerializer.default_loader
    )

    @override
    def get_class(self, args: Mapping[str, Any]) -> type[DPoPKey]:
        return DPoPKey

    @classmethod
    def default_dumper(cls, dpop_key: DPoPKey) -> str:
        """Provide a default dumper implementation.

        This will not serialize jti_generator, iat_generator, and dpop_token_class!

        """
        d = dpop_key.private_key.to_dict()
        d.pop("jti_generator", None)
        d.pop("iat_generator", None)
        d.pop("dpop_token_class", None)
        return BinaPy.serialize_to("json", d).to("deflate").to("b64u").ascii()

    @classmethod
    def default_loader(
        cls,
        serialized: str,
        get_class: Callable[[Mapping[str, Any]], type[DPoPKey]],
    ) -> DPoPKey:
        """Provide a default deserializer implementation.

        This will not deserialize iat_generator, iat_generator, and dpop_token_class!

        """
        private_key = BinaPy(serialized).decode_from("b64u").decode_from("deflate").parse_from("json")
        dpop_class = get_class({})
        return dpop_class(private_key=private_key)


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
        [AuthorizationRequest | RequestParameterAuthorizationRequest | RequestUriParameterAuthorizationRequest], str
    ] = field(factory=lambda: AuthorizationRequestSerializer.default_dumper)
    loader: Callable[
        [
            str,
            Callable[
                [Mapping[str, Any]],
                type[
                    AuthorizationRequest
                    | RequestParameterAuthorizationRequest
                    | RequestUriParameterAuthorizationRequest
                ],
            ],
        ],
        AuthorizationRequest | RequestParameterAuthorizationRequest | RequestUriParameterAuthorizationRequest,
    ] = field(factory=lambda: AuthorizationRequestSerializer.default_loader)

    dpop_key_serializer: ClassVar[Serializer[DPoPKey]] = DPoPKeySerializer()

    @override
    def get_class(
        self, args: Mapping[str, Any]
    ) -> type[AuthorizationRequest | RequestParameterAuthorizationRequest | RequestUriParameterAuthorizationRequest]:
        if "request" in args:
            return RequestParameterAuthorizationRequest
        if "request_uri" in args:
            return RequestUriParameterAuthorizationRequest
        return AuthorizationRequest

    @classmethod
    def default_dumper(
        cls,
        azr: AuthorizationRequest | RequestParameterAuthorizationRequest | RequestUriParameterAuthorizationRequest,
    ) -> str:
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
        return BinaPy.serialize_to("json", d).to("deflate").to("b64u").ascii()

    @classmethod
    def default_loader(
        cls,
        serialized: str,
        get_class: Callable[
            [Mapping[str, Any]],
            type[AuthorizationRequest | RequestParameterAuthorizationRequest | RequestUriParameterAuthorizationRequest],
        ],
    ) -> AuthorizationRequest | RequestParameterAuthorizationRequest | RequestUriParameterAuthorizationRequest:
        """Provide a default deserializer implementation.

        This does the opposite operations than `default_dumper`.

        Args:
            serialized: the serialized AuthorizationRequest
            get_class: a callable to obtain the appropriate class for deserialization

        Returns:
            an AuthorizationRequest

        """
        args = BinaPy(serialized).decode_from("b64u").decode_from("deflate").parse_from("json")

        if args["dpop_key"]:
            args["dpop_key"] = cls.dpop_key_serializer.loads(args["dpop_key"])

        azr_class = get_class(args)

        return azr_class(**args)
