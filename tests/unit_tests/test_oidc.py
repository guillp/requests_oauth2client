import pytest
from freezegun import freeze_time  # type: ignore[import]

from requests_oauth2client import (
    AuthorizationResponse,
    BearerToken,
    InvalidIdToken,
    OAuth2Client,
)

ID_TOKEN = (
    "eyJraWQiOiIxZTlnZGs3IiwiYWxnIjoiUlMyNTYifQ.ewogIml"
    "zcyI6ICJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwKICJzdWIiOiAiMjQ"
    "4Mjg5NzYxMDAxIiwKICJhdWQiOiAiczZCaGRSa3F0MyIsCiAibm9uY2UiOiA"
    "ibi0wUzZfV3pBMk1qIiwKICJleHAiOiAxMzExMjgxOTcwLAogImlhdCI6IDE"
    "zMTEyODA5NzAsCiAiY19oYXNoIjogIkxEa3RLZG9RYWszUGswY25YeENsdEE"
    "iCn0.XW6uhdrkBgcGx6zVIrCiROpWURs-4goO1sKA4m9jhJIImiGg5muPUcN"
    "egx6sSv43c5DSn37sxCRrDZZm4ZPBKKgtYASMcE20SDgvYJdJS0cyuFw7Ijp"
    "_7WnIjcrl6B5cmoM6ylCvsLMwkoQAxVublMwH10oAxjzD6NEFsu9nipkszWh"
    "sPePf_rM4eMpkmCbTzume-fzZIi5VjdWGGEmzTg32h3jiex-r5WTHbj-u5HL"
    "7u_KP3rmbdYNzlzd1xWRYTUs4E8nOTgzAUwvwXkIQhOh5TPcSMBYy6X3E7-_"
    "gr9Ue6n4ND7hTFhtjYs3cjNKIA08qm5cpVYFMFMG6PkhzLQ"
)


@freeze_time("2011-07-21 20:42:55")  # type: ignore[misc]
def test_validate_oidc(token_endpoint: str) -> None:
    assert ID_TOKEN == BearerToken(
        access_token="jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y",
        expires_in=60,
        id_token=ID_TOKEN,
    ).validate_id_token(
        client=OAuth2Client(token_endpoint, client_id="s6BhdRkqt3"),
        azr=AuthorizationResponse(
            code="Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk"
        ),
    )


def test_invalid_oidc(token_endpoint: str) -> None:
    with pytest.raises(InvalidIdToken):
        BearerToken(
            access_token="an_access_token", expires_in=60, id_token="foo"
        ).validate_id_token(
            client=OAuth2Client(token_endpoint, client_id="client_id"),
            azr=AuthorizationResponse(code="foo"),
        )
