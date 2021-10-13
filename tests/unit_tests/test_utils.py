import string
import uuid
from datetime import datetime
from uuid import uuid4

import pytest

from requests_oauth2client.utils import (
    accepts_expires_in,
    b64_decode,
    b64_encode,
    b64u_decode,
    b64u_encode,
    json_encode,
    validate_endpoint_uri,
)

clear_text = string.printable
b64 = "MDEyMzQ1Njc4OWFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVohIiMkJSYnKCkqKywtLi86Ozw9Pj9AW1xdXl9ge3x9fiAJCg0LDA=="
b64u = "MDEyMzQ1Njc4OWFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVohIiMkJSYnKCkqKywtLi86Ozw9Pj9AW1xdXl9ge3x9fiAJCg0LDA"


def test_b64():
    assert b64_encode(clear_text) == b64
    assert b64_decode(b64).decode() == clear_text

    assert b64_encode(clear_text.encode()) == b64
    assert b64_decode(b64u.encode()).decode() == clear_text

    assert b64_encode(clear_text, padded=False) == b64.rstrip("=")

    uuid = uuid4()
    assert b64_decode(b64_encode(uuid)).decode() == str(uuid)

    class Str:
        def __str__(self):
            return b64_encode(uuid)

    assert b64_decode(Str()) == str(uuid).encode()


def test_b64u():
    assert b64u_encode(clear_text) == b64u
    assert b64u_decode(b64u).decode() == clear_text

    assert b64u_encode(clear_text.encode()) == b64u
    assert b64u_decode(b64u.encode()).decode() == clear_text

    assert b64u_encode(clear_text, padded=True) == b64u + "=" * (4 - (len(b64u) % 4))

    uuid = uuid4()
    assert b64u_decode(b64u_encode(uuid)).decode() == str(uuid)

    class Str:
        def __str__(self):
            return b64u_encode(uuid)

    assert b64u_decode(Str()) == str(uuid).encode()


def test_validate_uri():
    validate_endpoint_uri("https://myas.local/token")
    with pytest.raises(ValueError):
        validate_endpoint_uri("http://myas.local/token")
    with pytest.raises(ValueError):
        validate_endpoint_uri("https://myas.local")
    with pytest.raises(ValueError):
        validate_endpoint_uri("https://myas.local/token#foo")


def test_accepts_expires_in():
    @accepts_expires_in
    def foo(expires_at=None):
        return expires_at

    now = datetime.now()
    assert foo(expires_at=now) == now
    assert foo(now) == now
    assert isinstance(foo(expires_in=10), datetime)
    assert foo() is None


def test_json_encode():
    now = datetime.fromtimestamp(1630916771)
    uuid_ = uuid.UUID("40971d1d-24c5-40d6-bf5f-7ceb35fe81ca")
    assert (
        json_encode({"foo": "bar", "iat": now, "jti": uuid_})
        == '{"foo":"bar","iat":1630916771,"jti":"40971d1d-24c5-40d6-bf5f-7ceb35fe81ca"}'
    )
