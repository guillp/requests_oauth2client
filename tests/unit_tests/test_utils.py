from __future__ import annotations

from datetime import datetime, timezone

import pytest

from requests_oauth2client import InvalidUri, validate_endpoint_uri
from requests_oauth2client.utils import accepts_expires_in


def test_validate_uri() -> None:
    validate_endpoint_uri("https://myas.local/token")
    validate_endpoint_uri("https://myas.local:443/token", no_port=True)
    with pytest.raises(ValueError, match="https") as exc:
        validate_endpoint_uri("http://myas.local/token")
    assert exc.type is InvalidUri
    with pytest.raises(ValueError, match="path") as exc:
        validate_endpoint_uri("https://myas.local")
    assert exc.type is InvalidUri
    with pytest.raises(ValueError, match="fragment") as exc:
        validate_endpoint_uri("https://myas.local/token#foo")
    assert exc.type is InvalidUri
    with pytest.raises(ValueError, match="credentials") as exc:
        validate_endpoint_uri("https://user:passwd@myas.local/token")
    assert exc.type is InvalidUri
    with pytest.raises(ValueError, match="port") as exc:
        validate_endpoint_uri("https://myas.local:1234/token", no_port=True)
    assert exc.type is InvalidUri


@pytest.mark.parametrize("expires_in", [10, "10"])
def test_accepts_expires_in(expires_in: int | str) -> None:
    @accepts_expires_in
    def foo(expires_at: datetime | None = None) -> datetime | None:
        return expires_at

    now = datetime.now(tz=timezone.utc)
    assert foo(expires_at=now) == now
    assert foo(now) == now
    assert isinstance(foo(expires_in=expires_in), datetime)
    assert foo() is None
