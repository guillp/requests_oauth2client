import base64
import hashlib
import string

import pytest

from requests_oauth2client import PkceUtils


def test_generate_code_verifier_and_challenge() -> None:
    verifier, challenge = PkceUtils.generate_code_verifier_and_challenge()
    assert isinstance(verifier, str)
    assert 43 <= len(verifier) <= 128
    assert set(verifier).issubset(set(string.ascii_letters + string.digits + "_-~."))

    assert isinstance(challenge, str)
    assert len(challenge) == 43
    assert set(verifier).issubset(set(string.ascii_letters + string.digits + "_-"))

    assert (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .decode()
        .rstrip("=")
        == challenge
    )

    assert PkceUtils.validate_code_verifier(verifier, challenge)


def test_unsupported_challenge_method() -> None:
    verifier = PkceUtils.generate_code_verifier()
    with pytest.raises(ValueError):
        PkceUtils.derive_challenge(verifier, method="foo")


def test_challenge_method_plain() -> None:
    verifier = PkceUtils.generate_code_verifier()
    challenge = PkceUtils.derive_challenge(verifier, method="plain")
    assert challenge == verifier


def test_invalid_verifier() -> None:
    with pytest.raises(ValueError):
        PkceUtils.derive_challenge("foo")


def test_verifier_bytes() -> None:
    challenge = PkceUtils.derive_challenge(
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMOPQRSTUVWXYZ1234567890"
    )
    assert challenge == "FYKCx6MubiaOxWp8-ciyDkkkOapyAjR9sxikqOSXLdw"
