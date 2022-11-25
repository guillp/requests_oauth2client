from typing import Dict

import jwskate
import pytest
from binapy import BinaPy
from freezegun import freeze_time  # type: ignore[import]

from requests_oauth2client import (
    AuthorizationResponse,
    BearerToken,
    IdToken,
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
@pytest.mark.parametrize(
    "kwargs, at_hash",
    (
        ({"alg": "PS256"}, "xsZZrUssMXjL3FBlzoSh2g"),
        ({"alg": "PS384"}, "adt46pcdiB-l6eTNifgoVM-5AIJAxq84"),
        ({"alg": "PS512"}, "p2LHG4H-8pYDc0hyVOo3iIHvZJUqe9tbj3jESOuXbkY"),
        (
            {"alg": "EdDSA", "crv": "Ed448"},
            "sB_U72jyb0WgtX8TsVoqJnm6CD295W9gfSDRxkilB3LAL7REi9JYutRW_s1yE4lD8cOfMZf83gi4",
        ),
    ),
)
def test_validate_oidc(kwargs: Dict[str, str], at_hash: str) -> None:
    signing_key = jwskate.Jwk.generate_for_alg(**kwargs).with_kid_thumbprint()
    client_id = "s6BhdRkqt3"
    access_token = (
        "YmJiZTAwYmYtMzgyOC00NzhkLTkyOTItNjJjNDM3MGYzOWIy9sFhvH8K_x8UIHj1osisS57f5DduL"
    )
    code = "Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk"
    nonce = "n-0S6_WzA2Mj"
    id_token = IdToken.sign(
        {
            "iss": "http://server.example.com",
            "sub": "248289761001",
            "aud": client_id,
            "nonce": nonce,
            "exp": 1311281970,
            "iat": 1311280970,
            # "c_hash": BinaPy(code).to("sha256")[:16].to("b64u").ascii(),
            "at_hash": at_hash,
        },
        signing_key,
    )
    assert id_token == BearerToken(
        access_token=access_token,
        expires_in=60,
        id_token=str(id_token),
    ).validate_id_token(
        client=OAuth2Client(
            "https://myas.local/token",
            client_id=client_id,
            authorization_server_jwks=signing_key.public_jwk().as_jwks(),
        ),
        azr=AuthorizationResponse(
            code=code,
            nonce=nonce,
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
