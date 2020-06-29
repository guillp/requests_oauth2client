from datetime import datetime
from urllib.parse import parse_qs
from uuid import uuid4

import jwt
import requests
from requests.auth import _basic_auth_str


class ClientAuthenticationMethod(requests.auth.AuthBase):
    """
    Base class for the Client Authentication methods.
    """

    def __call__(self, request):
        if (
                request.method != "POST"
                or request.headers["Content-Type"] != "application/x-www-form-urlencoded"
        ):
            raise RuntimeError(
                "This request is not suitable to add OAuth2.0 Client Authentication"
            )
        return request


class ClientSecretBasic(ClientAuthenticationMethod):
    """
    Handles client_secret_basic authentication (client_id and client_secret passed as Basic authentication)
    """

    def __init__(self, client_id, client_secret):
        self.client_id = str(client_id)
        self.client_secret = str(client_secret)

    def __call__(self, request):
        request = super().__call__(request)
        request.headers["Authorization"] = _basic_auth_str(self.client_id, self.client_secret)
        return request


class ClientSecretPost(ClientAuthenticationMethod):
    """
    Handles client_secret_post client authentication method (client_id and client_secret
    passed as part of the request form data).
    """

    def __init__(self, client_id, client_secret):
        self.client_id = str(client_id)
        self.client_secret = str(client_secret)

    def __call__(self, request):
        request = super().__call__(request)
        data = parse_qs(request.body)
        data["client_id"] = [self.client_id]
        data["client_secret"] = [self.client_secret]
        request.prepare_body(data, files=None)
        return request


class ClientAssertionAuthenticationMethod(ClientAuthenticationMethod):
    """
    Base class for assertion based client authentication methods.
    """

    def client_assertion(self, audience, lifetime=60, jti=None):
        raise NotImplementedError()

    def __call__(self, request):
        request = super().__call__(request)
        token_endpoint = request.url
        data = parse_qs(request.body)
        data["client_id"] = self.client_id
        data["client_assertion"] = self.client_assertion(token_endpoint)
        data["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        request.prepare_body(data, files=None)
        return request


class ClientSecretJWT(ClientAssertionAuthenticationMethod):
    """
    Handles client_secret_jwt client authentication method (client_assertion symmetrically signed with the client_secet).
    """

    def __init__(self, client_id, client_secret):
        self.client_id = str(client_id)
        self.client_secret = str(client_secret)

    def client_assertion(self, audience, lifetime=60, jti=None):
        iat = int(datetime.now().timestamp())
        exp = iat + lifetime
        if jti is None:
            jti = str(uuid4())
        elif callable(jti):
            jti = jti()

        if not isinstance(jti, str):
            jti = str(jti)

        return jwt.encode(
            {
                "iss": self.client_id,
                "sub": self.client_id,
                "aud": audience,
                "iat": iat,
                "exp": exp,
                "jti": jti,
            },
            self.client_secret,
            algorithm="HS256",
        )


class PrivateKeyJWT(ClientAssertionAuthenticationMethod):
    """
    Handles private_key_jwt client authentication method (client_assertion asymmetrically signed with a private key).
    """

    def __init__(self, client_id, private_jwk, alg="RS256"):
        self.client_id = str(client_id)
        self.private_jwk = private_jwk
        self.alg = private_jwk.get("alg", alg)

    def client_assertion(self, audience, lifetime=60, jti=None):
        iat = int(datetime.now().timestamp())
        exp = iat + lifetime
        if jti is None:
            jti = str(uuid4())
        elif callable(jti):
            jti = jti()

        if not isinstance(jti, str):
            jti = str(jti)

        return jwt.encode(
            {
                "iss": self.client_id,
                "sub": self.client_id,
                "aud": audience,
                "iat": iat,
                "exp": exp,
                "jti": jti,
            },
            self.private_jwk,
            algorithm=self.alg,
        )


class PublicApp(ClientAuthenticationMethod):
    """
    Handles the "none" authentication method (client only sends its client_id).
    """

    def __init__(self, client_id):
        self.client_id = client_id

    def __call__(self, request):
        request = super().__call__(request)
        data = parse_qs(request.body)
        data["client_id"] = self.client_id
        request.prepare_body(data, files=None)
        return request
