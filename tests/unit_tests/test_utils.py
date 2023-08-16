from __future__ import annotations

from datetime import datetime

import pytest

from requests_oauth2client.utils import accepts_expires_in, validate_endpoint_uri


def test_validate_uri() -> None:
    validate_endpoint_uri("https://myas.local/token")
    with pytest.raises(ValueError):
        validate_endpoint_uri("http://myas.local/token")
    with pytest.raises(ValueError):
        validate_endpoint_uri("https://myas.local")
    with pytest.raises(ValueError):
        validate_endpoint_uri("https://myas.local/token#foo")


def test_accepts_expires_in() -> None:
    @accepts_expires_in
    def foo(expires_at: datetime | None = None) -> datetime | None:
        return expires_at

    now = datetime.now()
    assert foo(expires_at=now) == now
    assert foo(now) == now
    assert isinstance(foo(expires_in=10), datetime)
    assert foo() is None
