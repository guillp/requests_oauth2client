import base64
from typing import Any, Dict, Optional, Tuple, Union

from furl import furl  # type: ignore

from requests_oauth2client.exceptions import InvalidUrl


def b64_encode(data: Union[bytes, str], encoding: str = "utf-8") -> str:
    if not isinstance(data, bytes):
        if not isinstance(data, str):
            data = str(data)
        data = data.encode(encoding)

    encoded = base64.b64encode(data)
    return encoded.decode()


def b64u_encode(data: Union[bytes, str], encoding: str = "utf-8") -> str:
    """
    Encodes some data in Base64url.
    :param data: the data to encode. Can be bytes or str.
    :param encoding: if data is a string, the encoding to use to convert it as bytes
    :return: the base64url encoded data, as a string
    """
    if not isinstance(data, bytes):
        if not isinstance(data, str):
            data = str(data)
        data = data.encode(encoding)

    encoded = base64.urlsafe_b64encode(data).rstrip(b"=")
    return encoded.decode()


def b64u_decode(
    data: Union[str, bytes], encoding: Optional[str] = "utf-8"
) -> Union[str, bytes]:
    """
    Decodes a base64encoded string or bytes.
    :param data: the data to decode. Can be bytes or str
    :param encoding: the encoding to use when converting the decoded data to str. If None, no decoding will
    be done and data will be decoded as bytes.
    :return: the decoded data as a string, or bytes if `encoding` is None.
    """
    if not isinstance(data, bytes):
        if not isinstance(data, str):
            data = str(data)
        data = data.encode()

    padding_len = len(data) % 4
    if padding_len:
        data = data + b"=" * padding_len

    decoded = base64.urlsafe_b64decode(data)
    if encoding:
        return decoded.decode(encoding)
    return decoded


def generate_jwk_key_pair(
    kty: str = "RSA", **kwargs: Any
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    from jwcrypto.jwk import JWK  # type: ignore

    jwk = JWK.generate(kty=kty, **kwargs)
    private_jwk = jwk.export_private(as_dict=True)
    public_jwk = jwk.export_public(as_dict=True)
    return private_jwk, public_jwk


def sign_jwt(
    claims: Dict[str, Any],
    private_jwk: Dict[str, Any],
    extra_headers: Optional[Dict[str, Any]] = None,
    alg: Optional[str] = None,
    kid: Optional[str] = None,
) -> str:
    from jwcrypto.jwk import JWK
    from jwcrypto.jwt import JWT  # type: ignore

    jwk = JWK(**private_jwk)
    alg = alg or private_jwk.get("alg")
    kid = kid or private_jwk.get("kid")

    if alg is None:
        raise ValueError("a signing alg is required")

    headers = dict(extra_headers or {}, alg=alg)
    if kid:
        headers["kid"] = kid

    jwt = JWT(header=headers, claims=claims,)

    jwt.make_signed_token(jwk)
    assertion: str = jwt.serialize()
    return assertion


def validate_url(
    value: str, https: bool = True, no_fragment: bool = True, path: bool = True
) -> None:
    try:
        url = furl(value)
        if https and url.scheme != "https":
            raise ValueError("url must use https")
        if no_fragment and url.fragment:
            raise ValueError("url must not contain a fragment")
        if path and not url.path:
            raise ValueError("url has no path")
    except ValueError as exc:
        raise InvalidUrl(value) from exc
