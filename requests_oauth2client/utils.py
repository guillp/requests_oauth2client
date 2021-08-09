import base64
from typing import Optional, Union


def b64u_encode(data: Union[bytes, str], encoding="utf-8"):
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


def generate_jwk_key_pair(kty="RSA", **kwargs):
    from jwcrypto.jwk import JWK # type: ignore

    jwk = JWK.generate(kty=kty, **kwargs)
    private_jwk = jwk.export_private(as_dict=True)
    public_jwk = jwk.export_public(as_dict=True)
    return private_jwk, public_jwk
