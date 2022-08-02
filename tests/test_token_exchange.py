import secrets

import pytest
from furl import Query  # type: ignore[import]

from requests_oauth2client import BearerToken, ClientSecretPost, IdToken, OAuth2Client
from tests.conftest import RequestsMocker


def test_token_exchange(
    requests_mock: RequestsMocker,
    client_id: str,
    client_secret: str,
    token_endpoint: str,
) -> None:
    access_token = secrets.token_urlsafe()

    client = OAuth2Client(token_endpoint, ClientSecretPost(client_id, client_secret))

    requests_mock.post(
        token_endpoint,
        json={
            "access_token": access_token,
            "token_type": "Bearer",
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "expires_in": 60,
        },
    )

    subject_token = "accVkjcJyb4BWCxGsndESCJQbdFMogUC5PbRDqceLTC"
    resource = "https://backend.example.com/api"
    token_response = client.token_exchange(
        subject_token=BearerToken(subject_token), resource=resource
    )

    assert token_response.access_token == access_token
    assert token_response.issued_token_type == "urn:ietf:params:oauth:token-type:access_token"
    assert token_response.token_type == "Bearer"
    assert 58 <= token_response.expires_in <= 60

    assert requests_mock.last_request is not None
    params = Query(requests_mock.last_request.text).params
    assert params.pop("client_id") == client_id
    assert params.pop("client_secret") == client_secret
    assert params.pop("grant_type") == "urn:ietf:params:oauth:grant-type:token-exchange"
    assert params.pop("subject_token") == subject_token
    assert params.pop("subject_token_type") == "urn:ietf:params:oauth:token-type:access_token"
    assert params.pop("resource") == resource
    assert not params


def test_token_type() -> None:
    assert (
        OAuth2Client.get_token_type("urn:ietf:params:oauth:token-type:access_token")
        == "urn:ietf:params:oauth:token-type:access_token"
    )
    assert (
        OAuth2Client.get_token_type("urn:ietf:params:oauth:token-type:refresh_token")
        == "urn:ietf:params:oauth:token-type:refresh_token"
    )
    assert (
        OAuth2Client.get_token_type("urn:ietf:params:oauth:token-type:id_token")
        == "urn:ietf:params:oauth:token-type:id_token"
    )
    assert (
        OAuth2Client.get_token_type("urn:ietf:params:oauth:token-type:saml1")
        == "urn:ietf:params:oauth:token-type:saml1"
    )
    assert (
        OAuth2Client.get_token_type("urn:ietf:params:oauth:token-type:saml2")
        == "urn:ietf:params:oauth:token-type:saml2"
    )
    assert (
        OAuth2Client.get_token_type("urn:ietf:params:oauth:token-type:jwt")
        == "urn:ietf:params:oauth:token-type:jwt"
    )

    assert (
        OAuth2Client.get_token_type("access_token")
        == "urn:ietf:params:oauth:token-type:access_token"
    )
    assert (
        OAuth2Client.get_token_type("refresh_token")
        == "urn:ietf:params:oauth:token-type:refresh_token"
    )
    assert (
        OAuth2Client.get_token_type("id_token") == "urn:ietf:params:oauth:token-type:id_token"
    )
    assert OAuth2Client.get_token_type("saml1") == "urn:ietf:params:oauth:token-type:saml1"
    assert OAuth2Client.get_token_type("saml2") == "urn:ietf:params:oauth:token-type:saml2"
    assert OAuth2Client.get_token_type("jwt") == "urn:ietf:params:oauth:token-type:jwt"

    assert OAuth2Client.get_token_type("foobar") == "foobar"

    assert (
        OAuth2Client.get_token_type(token=BearerToken("mytoken"))
        == "urn:ietf:params:oauth:token-type:access_token"
    )
    assert (
        OAuth2Client.get_token_type(
            token_type="refresh_token",
            token=BearerToken("mytoken", refresh_token="myrefreshtoken"),
        )
        == "urn:ietf:params:oauth:token-type:refresh_token"
    )
    assert (
        OAuth2Client.get_token_type("id_token", token="foo")
        == "urn:ietf:params:oauth:token-type:id_token"
    )
    assert OAuth2Client.get_token_type("saml1") == "urn:ietf:params:oauth:token-type:saml1"
    assert OAuth2Client.get_token_type("saml2") == "urn:ietf:params:oauth:token-type:saml2"
    assert OAuth2Client.get_token_type("jwt") == "urn:ietf:params:oauth:token-type:jwt"

    with pytest.raises(TypeError):
        OAuth2Client.get_token_type(
            token_type="access_token",
            token=IdToken(
                "eyJraWQiOiIxZTlnZGs3IiwiYWxnIjoiUlMyNTYifQ.ewogImlz"
                "cyI6ICJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwKICJzdWIiOiAiMjQ4"
                "Mjg5NzYxMDAxIiwKICJhdWQiOiAiczZCaGRSa3F0MyIsCiAibm9uY2UiOiAi"
                "bi0wUzZfV3pBMk1qIiwKICJleHAiOiAxMzExMjgxOTcwLAogImlhdCI6IDEz"
                "MTEyODA5NzAsCiAibmFtZSI6ICJKYW5lIERvZSIsCiAiZ2l2ZW5fbmFtZSI6"
                "ICJKYW5lIiwKICJmYW1pbHlfbmFtZSI6ICJEb2UiLAogImdlbmRlciI6ICJm"
                "ZW1hbGUiLAogImJpcnRoZGF0ZSI6ICIwMDAwLTEwLTMxIiwKICJlbWFpbCI6"
                "ICJqYW5lZG9lQGV4YW1wbGUuY29tIiwKICJwaWN0dXJlIjogImh0dHA6Ly9l"
                "eGFtcGxlLmNvbS9qYW5lZG9lL21lLmpwZyIKfQ.rHQjEmBqn9Jre0OLykYNn"
                "spA10Qql2rvx4FsD00jwlB0Sym4NzpgvPKsDjn_wMkHxcp6CilPcoKrWHcip"
                "R2iAjzLvDNAReF97zoJqq880ZD1bwY82JDauCXELVR9O6_B0w3K-E7yM2mac"
                "AAgNCUwtik6SjoSUZRcf-O5lygIyLENx882p6MtmwaL1hd6qn5RZOQ0TLrOY"
                "u0532g9Exxcm-ChymrB4xLykpDj3lUivJt63eEGGN6DH5K6o33TcxkIjNrCD"
                "4XB1CKKumZvCedgHHF3IAK4dVEDSUoGlH9z4pP_eWYNXvqQOjGs-rDaQzUHl"
                "6cQQWNiDpWOl_lxXjQEvQ"
            ),
        )

    with pytest.raises(ValueError):
        OAuth2Client.get_token_type(token_type="refresh_token", token=BearerToken("mytoken"))

    with pytest.raises(TypeError):
        OAuth2Client.get_token_type(token_type="id_token", token=BearerToken("mytoken"))
