import base64
from typing import Union


def b64u_encode(data: Union[str, bytes], encoding="utf-8"):
    if not isinstance(data, bytes):
        if not isinstance(data, str):
            data = str(data)
        data = data.encode(encoding)

    encoded = base64.urlsafe_b64encode(data).rstrip(b"=")
    return encoded.decode()


def b64u_decode(data: Union[str, bytes], encoding="utf-8"):
    if not isinstance(data, bytes):
        if not isinstance(data, str):
            data = str(data)
        data = data.encode()

    padding_len = len(data) % 4
    if padding_len:
        data = data + b"=" * padding_len

    decoded = base64.urlsafe_b64decode(data)
    return decoded.decode(encoding)
