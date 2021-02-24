import string
from uuid import uuid4

from requests_oauth2client.utils import b64u_decode, b64u_encode, generate_jwk_key_pair

clear_text = string.printable
b64u = "MDEyMzQ1Njc4OWFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVohIiMkJSYnKCkqKywtLi86Ozw9Pj9AW1xdXl9ge3x9fiAJCg0LDA"


def test_b64u():
    assert b64u_encode(clear_text) == b64u
    assert b64u_decode(b64u) == clear_text

    assert b64u_encode(clear_text.encode()) == b64u
    assert b64u_decode(b64u.encode()) == clear_text

    uuid = uuid4()
    assert b64u_decode(b64u_encode(uuid)) == str(uuid)


def test_generate_jwk_key_pair():
    private, public = generate_jwk_key_pair()
    assert private.get("kty") == "RSA"
