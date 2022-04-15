from datetime import datetime
from typing import Optional

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
    def foo(expires_at: Optional[datetime] = None) -> Optional[datetime]:
        return expires_at

    now = datetime.now()
    assert foo(expires_at=now) == now
    assert foo(now) == now
    assert isinstance(foo(expires_in=10), datetime)
    assert foo() is None
