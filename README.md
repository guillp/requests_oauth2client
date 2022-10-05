`requests_oauth2client` is a OAuth 2.x client for Python, able to obtain, refresh and revoke tokens from any OAuth2.x/OIDC
compliant Authorization Server. It sits upon and extends the famous [requests] HTTP client module.

It can act as an [OAuth 2.0](https://tools.ietf.org/html/rfc6749) /
[2.1](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1) client, to automatically get and renew Access Tokens,
based on the
[Client Credentials](https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-03.html#name-client-credentials),
[Authorization Code](https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-03.html#name-authorization-code),
[Refresh token](https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-03.html#name-refresh-token),
[Token Exchange](https://www.rfc-editor.org/rfc/rfc8693.html),
[JWT Bearer](https://www.rfc-editor.org/rfc/rfc7523.html#section-2.1),
[Device Authorization](https://www.rfc-editor.org/rfc/rfc8628.html), or
[CIBA](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html) grants.

It also supports [OpenID Connect 1.0](https://openid.net/specs/openid-connect-core-1_0.html),
[PKCE](https://www.rfc-editor.org/rfc/rfc7636.html),
[Client Assertions](https://www.rfc-editor.org/rfc/rfc7523.html#section-2.2),
[Token Revocation](https://www.rfc-editor.org/rfc/rfc7009.html),
and [Introspection](https://www.rfc-editor.org/rfc/rfc7662.html),
[Resource Indicators](https://www.rfc-editor.org/rfc/rfc8707.html),
[JWT-secured Authorization Requests](https://datatracker.ietf.org/doc/rfc9101/),
[Pushed Authorization Requests](https://datatracker.ietf.org/doc/rfc9126/),
[Authorization Server Issuer Identification](https://www.rfc-editor.org/rfc/rfc9207.html)
as well as using custom params to any endpoint, and other important features that are often overlooked in other client
libraries.

And it also includes a [wrapper][apiclient] around [requests.Session] that makes it super easy to use REST-style APIs,
with or without OAuth 2.x.

Please note that despite the name, this library has no relationship with Google
[oauth2client](https://github.com/googleapis/oauth2client) library.

[![made-with-python](https://img.shields.io/badge/Made%20with-Python-1f425f.svg)](https://www.python.org/)
[![Downloads](https://pepy.tech/badge/requests_oauth2client/month)](https://pepy.tech/project/requests_oauth2client)
[![Supported Versions](https://img.shields.io/pypi/pyversions/requests_oauth2client.svg)](https://pypi.org/project/requests_oauth2client)
[![PyPi license](https://badgen.net/pypi/license/requests_oauth2client/)](https://pypi.com/project/requests_oauth2client/)
[![PyPI status](https://img.shields.io/pypi/status/requests_oauth2client.svg)](https://pypi.python.org/pypi/requests_oauth2client/)
[![GitHub commits](https://badgen.net/github/commits/guillp/requests_oauth2client)](https://github.com/guillp/requests_oauth2client/commit/)
[![GitHub latest commit](https://badgen.net/github/last-commit/guillp/requests_oauth2client)](https://github.com/guillp/requests_oauth2client/commit/)

# Documentation

Full module documentation is available at https://guillp.github.io/requests_oauth2client/

# Installation

`requests_oauth2client` is [available from PyPi](https://pypi.org/project/requests-oauth2client/), so installing it is as easy as:

```shell
pip install requests_oauth2client
```

# Usage

Everything from `requests_oauth2client` is available from the root module, so you can import it like this:

```python
from requests_oauth2client import *
```

Note that this automatically imports `requests`, so no need to import it yourself.

## Calling APIs with Access Tokens

If you already managed to obtain an access token for the API you want to call, you can simply use the [BearerAuth] Auth Handler for [requests]:

```python
import requests
from requests_oauth2client import BearerAuth

token = "an_access_token"
resp = requests.get("https://my.protected.api/endpoint", auth=BearerAuth(token))
```

This authentication handler will add a properly formatted `Authorization: Bearer <access_token>` header in the request, with your access token
according to [RFC6750](https://datatracker.ietf.org/doc/html/rfc6750#section-2.1).

## Using an OAuth2Client

[OAuth2Client] offers several methods that implement the communication to the various endpoints that are standardised by
OAuth 2.0 and its extensions. Those endpoints include the Token Endpoint, the Revocation, Introspection, UserInfo,
BackChannel Authentication and Device Authorization Endpoints.

You have to provide the URLs for those endpoints if you intend to use them. Otherwise, only the Token Endpoint is mandatory to initialize an `OAuth2Client`.

To initialize an [OAuth2Client], you only need a Token Endpoint URI from your AS, and the credentials for your application, which are
often a `client_id` and a `client_secret`, usually also provided by the AS:

```python
from requests_oauth2client import OAuth2Client

oauth2client = OAuth2Client(
    token_endpoint="https://url.to.the/token_endpoint",
    auth=("my_client_id", "my_client_secret"),
)
```

The Token Endpoint is the only endpoint that is mandatory to obtain tokens. Credentials are used to authenticate the
client everytime it sends a request to its Authorization Server. Usually, those are a static Client ID and Secret, which
are the direct equivalent of a username and a password, but meant for an application instead of for a human user. The
default authentication method used by `OAuth2Client` is *Client Secret Post*, but other standardised methods such as
*Client Secret Basic*, *Client Secret JWT* or *Private Key JWT* are supported as well. See
[more about client authentication methods below](#supported-client-authentication-methods).

## Obtaining tokens

[OAuth2Client] has dedicated methods to send requests to the Token Endpoint using the different standardised (and/or custom)
grants. Since the Token Endpoint URL and Client Authentication Method to use are already declared for the client at init time, the only
required parameters for those methods are those that will be sent in the request to the Token Endpoint.

Those methods directly return a [BearerToken] if the request is successful, or raise an exception if it fails.
[BearerToken] contains all the data as returned by the Token Endpoint, including the Access Token. It will:

- keep track of the Access Token expiration date (based on the `expires_in` hint as returned by the AS). This date is accessible with the `expires_at` attribute.
- contain the Refresh Token, if returned by the AS, accessible with the `refresh_token` attribute.
- contain the ID Token, if returned by the AS, accessible with the `ìd_token` attribute.
- keep track of other associated metadata as well, also accessible as attributes with the same name (`token.custom_attr`), or with subscription (`token["my.custom.attr"]`).

You can create such a [BearerToken] yourself if you need:

```python
from requests_oauth2client import BearerToken

bearer_token = BearerToken(access_token="an_access_token", expires_in=60)
print(bearer_token)
# {'access_token': 'an_access_token',
#  'expires_in': 55,
#  'token_type': 'Bearer'}
print(bearer_token.expires_at)
# datetime.datetime(2021, 8, 20, 9, 56, 59, 498793)
assert not bearer_token.is_expired()

print(bearer_token.expires_in)
# 40
```

Note that the `expires_in` indicator here is not static. It keeps track of the token lifetime and is calculated as the
time flies. The actual static expiration date is accessible with the `expires_at` property. You can check if a token is
expired with [bearer_token.is_expired()](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.tokens.BearerToken.is_expired).

You can use a [BearerToken] instance anywhere you can supply an access_token as string.

### Using OAuth2Client as a requests Auth Handler

While using [OAuth2Client] directly is great for testing or debugging OAuth2.x flows, it is not a viable option for
actual applications where tokens must be obtained, used during their lifetime then obtained again or refreshed once they
are expired. `requests_oauth2client` contains several [requests] compatible Auth Handlers (as subclasses of
[requests.auth.AuthBase](https://requests.readthedocs.io/en/latest/user/advanced/#custom-authentication)), that will
take care of obtaining tokens when required, then will cache those tokens until they are expired, and will obtain new
ones (or refresh them, when possible), once the initial token is expired. Those are best used with a [requests.Session],
or an [ApiClient], which is a wrapper around `Session` with a few enhancements as described below.

### Client Credentials grant

To send a request using the Client Credentials grant, use the aptly named
[.client_credentials()](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.client.OAuth2Client.client_credentials)
method, with the parameters to send in the token request as keyword parameters:

```python
# using `oauth2client` as defined above

token = oauth2client.client_credentials(scope="myscope")
# or, if your AS uses resource indicator:
token = oauth2client.client_credentials(scope="myscope", resource="https://myapi.local")
# or, if your AS uses 'audience' as parameter to identify the requested API (Auth0 style):
token = oauth2client.client_credentials(audience="https://myapi.local")
# or, if your AS uses custom parameters:
token = oauth2client.client_credentials(scope="myscope", custom_param="custom_value")
```

Parameters such as `scope`, `resource` or `audience` or any other parameter that may be required by the AS can be passed as keyword
parameters. Those will be included in the token request that is sent to the AS. `scope` is not mandatory at client level (but it might be required by your AS to serve your request).

#### As Auth Handler

You can use the
[OAuth2ClientCredentialsAuth](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.auth.OAuth2ClientCredentialsAuth)
auth handler. It takes an [OAuth2Client] as parameter, and the additional kwargs to pass to the token endpoint:

```python
import requests
from requests_oauth2client import OAuth2Client, OAuth2ClientCredentialsAuth

oauth2client = OAuth2Client(
    token_endpoint="https://url.to.the/token_endpoint",
    auth=("client_id", "client_secret"),
)

auth = OAuth2ClientCredentialsAuth(
    oauth2client, scope="myscope", resource="https://myapi.local"
)

# use it like this:
requests.get("https://myapi.local/resource", auth=auth)

# or
session = requests.Session()
session.auth = auth

resp = session.get("https://myapi.local/resource")
```

Once again, extra parameters such as `scope`, `resource` or `audience` are allowed if required.

When you send your first request, [OAuth2ClientCredentialsAuth](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.auth.OAuth2ClientCredentialsAuth)
will automatically retrieve an access token from the AS using the Client Credentials grant, then will include it in the
request. Next requests will use the same token, as long as it is valid. A new token will be automatically retrieved once
the previous one is expired.

### Authorization Code Grant

Obtaining tokens with the Authorization code grant is made in 3 steps:

1. your application must open specific url called the *Authentication Request* in a browser.

2. your application must obtain and validate the *Authorization Response*, which is a redirection back to your
   application that contains an *Authorization Code* as parameter.

3. your application must then exchange this Authorization Code for an *Access Token*, with a request to the Token
   Endpoint.

[OAuth2Client] doesn't implement anything that is related to the Authorization Request or Response. It is only able to
exchange the Authorization Code for a Token in step 3. But `requests_oauth2client` has other classes to help you with
steps 1 and 2, as described below:

#### Generating Authorization Requests

You can generate valid authorization requests with the
[AuthorizationRequest](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.authorization_request.AuthorizationRequest)
class:

```python
from requests_oauth2client import AuthorizationRequest

auth_request = AuthorizationRequest(
    "https://url.to.the/authorization_endpoint",
    client_id="my_client_id",
    redirect_uri="http://localhost/callback",  # this redirect_uri is specific to your app
    scope="openid email profile",
    # extra parameters such as `resource` can be included as well if required by your AS
    resource="https://my.resource.local/api",
)
print(auth_request)  # redirect the user to that URL to get a code
```

This request will look like this (with line breaks for display purposes only):

```
https://url.to.the/authorization_endpoint
?client_id=my_client_id
&redirect_uri=http%3A%2F%2Flocalhost%callback
&response_type=code
&state=kHWL4VwcbUbtPR4mtht6yMAGG_S-ZcBh5RxI_IGDmJc
&nonce=mSGOS1M3LYU9ncTvvutoqUR4n1EtmaC_sQ3db4dyMAc
&scope=openid+email+profile
&code_challenge=Dk11ttaDb_Hyq1dObMqQcTIlfYYRVblFMC9lFM3UWW8
&code_challenge_method=S256
&resource=https%3A%2F%2Fmy.resource.local%2Fapi
```

[AuthorizationRequest] supports PKCE and uses it by default. You can avoid it by passing `code_challenge_method=None` to
[AuthorizationRequest]. You can obtain the generated code_verifier from `auth_request.code_verifier`.

A `nonce` and a `state` will also be generated by default, if none are passed as parameter.

Redirecting or otherwise sending the user to this url is your application responsibility, as well as obtaining the
Authorization Response url.

#### Validating the Authorization Response

Once the user is successfully authenticated and authorized, the AS will respond with a redirection to your redirect_uri.
That is the *Authorization Response*. It contains several parameters that must be retrieved by your client. The
authorization code is one of those parameters, but you must also validate that the *state* matches your request. You can
do this with:

```python
# using `auth_request` as defined above

response_uri = input(
    "Please enter the full url and/or params obtained on the redirect_uri: "
)
auth_response = auth_request.validate_callback(response_uri)
```

#### Exchanging code for tokens

Once you have obtained the AS response, containing an authorization code, your application must exchange it for actual Token(s).

To exchange a code for Access and/or ID tokens, use the
[OAuth2Client.authorization_code()](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.client.OAuth2Client.authorization_code)
method. If you have obtained an AuthorizationResponse as described above, you can simply do:

```python
token = oauth2client.authorization_code(auth_response)
```

This will automatically include the `code`, `redirect_uri` and `code_verifier` parameters in the Token Request,
as expected by the AS.

If you managed another way to obtain an Authorization Code, you can manually pass those parameters like this:

```python
token = oauth2client.authorization_code(
    code=code,
    code_verifier=code_verifier,
    redirect_uri=redirect_uri,
    custom_param=custom_value,
)
```

#### As Auth Handler

The
[OAuth2AuthorizationCodeAuth](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.auth.OAuth2AuthorizationCodeAuth)
handler takes an [OAuth2Client] and an authorization code as parameter, plus whatever additional keyword parameters are
required by your Authorization Server:

```python
from requests_oauth2client import OAuth2Client, ApiClient, OAuth2AuthorizationCodeAuth

client = OAuth2Client(
    token_endpoint="https://url.to.the/token_endpoint",
    authorization_endpoint="https://url.to.the/authorization_endpoint",
    auth=("client_id", "client_secret"),
)

api_client = ApiClient(
    "https://your.protected.api/endpoint",
    auth=OAuth2AuthorizationCodeAuth(
        client,
        "code",
    ),
)

# any request using api_client will trigger exchanging the code for an access_token, which is then cached, and refreshed later if needed
resp = api_client.post(data={...})
```

[OAuth2AuthorizationCodeAuth](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.auth.OAuth2AuthorizationCodeAuth)
will take care of refreshing the token automatically once it is expired, using the refresh token, if available.

### Device Authorization Grant

Helpers for the Device Authorization Grant are also included. To get device and user codes, read the response attributes (including Device Code, User Code, Verification URI, etc.), then pooling the Token Endpoint:

```python
from requests_oauth2client import (
    OAuth2Client,
    DeviceAuthorizationPoolingJob,
    BearerToken,
)

client = OAuth2Client(
    token_endpoint="https://url.to.the/token_endpoint",
    device_authorization_endpoint="https://url.to.the/device_authorization_endpoint",
    auth=("client_id", "client_secret"),
)

da_resp = client.authorize_device()

# `da_resp` contains the Device Code, User Code, Verification URI and other info returned by the AS:
da_resp.device_code
da_resp.user_code
da_resp.verification_uri
da_resp.verification_uri_complete
da_resp.expires_at  # just like for BearerToken, expiration is tracked by requests_oauth2client
da_resp.interval

# Send/show the Verification Uri and User Code to the user. He must use a browser to visit that url, authenticate and
# input the User Code.

# You can then request the Token endpoint to check if the user successfully authorized your device like this:
pool_job = DeviceAuthorizationPoolingJob(client, da_resp)

resp = None
while resp is None:
    resp = pool_job()

assert isinstance(resp, BearerToken)
```

[DeviceAuthorizationPoolingJob](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.device_authorization.DeviceAuthorizationPoolingJob)
will automatically obey the pooling period. Everytime you call `pool_job()`, it will wait the appropriate number of
seconds as indicated by the AS, and will apply slow_down requests.

#### As Auth Handler

Use
[OAuth2DeviceCodeAuth](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.auth.OAuth2DeviceCodeAuth)
as auth handler to exchange a device code for an access token:

```python
from requests_oauth2client import ApiClient, OAuth2DeviceCodeAuth, OAuth2Client

client = OAuth2Client(
    token_endpoint="https://url.to.the/token_endpoint",
    device_authorization_endpoint="https://url.to.the/device_authorization_endpoint",
    auth=("client_id", "client_secret"),
)

device_auth_resp = client.authorize_device()

# expose user_code and verification_uri or verification_uri_complete to the user
device_auth_resp.user_code
device_auth_resp.verification_uri
device_auth_resp.verification_uri_complete

# then try to send your request with a OAuth2DeviceCodeAuth handler
# this will pool the token endpoint until the user authorize the device
api_client = ApiClient(
    "https://your.protected.api/endpoint",
    auth=OAuth2DeviceCodeAuth(client, device_auth_resp),
)

resp = api_client.post(
    data={...}
)  # first call will hang until the user authorizes your app and the token endpoint returns a token.
```

### Client-Initiated BackChannel Authentication (CIBA)

To initiate a BackChannel Authentication against the dedicated endpoint, read the response attributes, and pool the Token Endpoint until the end-user successfully authenticates:

```python
from requests_oauth2client import (
    OAuth2Client,
    BearerToken,
    BackChannelAuthenticationPoolingJob,
)

client = OAuth2Client(
    token_endpoint="https://url.to.the/token_endpoint",
    backchannel_authentication_endpoint="https://url.to.the/backchannel_authorization_endpoint",
    auth=("client_id", "client_secret"),
)

ba_resp = client.backchannel_authentication_request(
    scope="openid email profile",
    login_hint="user@example.net",
)

# `ba_resp` will contain the response attributes as returned by the AS, including an `auth_req_id`:
ba_resp.auth_req_id
ba_resp.expires_in  # decreases as times fly
ba_resp.expires_at  # a datetime to keep track of the expiration date, based on the "expires_in" returned by the AS
ba_resp.interval  # the pooling interval indicated by the AS
ba_resp.custom  # if the AS respond with additional attributes, they are also accessible

pool_job = BackChannelAuthenticationPoolingJob(client, ba_resp)

resp = None
while resp is None:
    resp = pool_job()

assert isinstance(resp, BearerToken)
```

Hints by the AS to slow down pooling will automatically be obeyed.

### Token Exchange

To send a token exchange request, use the
[OAuth2Client.token_exchange()](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.client.OAuth2Client.token_exchange)
method:

```python
from requests_oauth2client import OAuth2Client, ClientSecretJwt

client = OAuth2Client(
    "https://url.to.the/token_endpoint",
    auth=ClientSecretJwt("client_id", "client_secret"),
)
token = client.token_exchange(
    subject_token="your_token_value",
    subject_token_type="urn:ietf:params:oauth:token-type:access_token",
)
```

As with the other grant-type specific methods, you may specify additional keyword parameters, that will be passed to the
token endpoint, including any standardised attribute like `actor_token` or `actor_token_type`, or any custom parameter.
There are short names for token types, that will be automatically translated to standardised types:

```python
token = client.token_exchange(
    subject_token="your_token_value",
    subject_token_type="access_token",  # will be automatically replaced by "urn:ietf:params:oauth:token-type:access_token"
    actor_token="your_actor_token",
    actor_token_type="id_token",  # will be automatically replaced by "urn:ietf:params:oauth:token-type:id_token"
)
```

Or to make it even easier, types can be guessed based on the supplied subject or actor token:

```python
from requests_oauth2client import BearerToken, ClientSecretJwt, IdToken, OAuth2Client

client = OAuth2Client(
    "https://url.to.the/token_endpoint",
    auth=ClientSecretJwt("client_id", "client_secret"),
)

token = client.token_exchange(
    subject_token=BearerToken(
        "your_token_value"
    ),  # subject_token_type will be "urn:ietf:params:oauth:token-type:access_token"
    actor_token=IdToken(
        "your_actor_token"
    ),  # actor_token_type will be "urn:ietf:params:oauth:token-type:id_token"
)
```

## Supported Client Authentication Methods

`requests_oauth2client` supports several client authentication methods, as defined in multiple OAuth2.x standards. You
select the appropriate method to use when initializing your [OAuth2Client], with the `auth` parameter. Once initialized,
a client will automatically use the configured authentication method every time it sends a requested to an endpoint that
requires client authentication. You don't have anything else to do afterwards.

### Client Secret Basic

With **client_secret_basic**, `client_id` and `client_secret` are included in clear-text in the `Authorization` header when sending requests to the Token Endpoint. To use
it, just pass a
[`ClientSecretBasic(client_id, client_secret)`](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.client_authentication.ClientSecretBasic)
as `auth` parameter:

```python
from requests_oauth2client import OAuth2Client, ClientSecretBasic

client = OAuth2Client(
    "https://url.to.the/token_endpoint",
    auth=ClientSecretBasic("client_id", "client_secret"),
)
```

### Client Secret Post

With **client_secret_post**, `client_id` and `client_secret` are included as part of the body form data. To use it, pass a
[`ClientSecretPost(client_id, client_secret)`](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.client_authentication.ClientSecretPost)
as `auth` parameter. This is the default when you pass a tuple `(client_id, client_secret)` as
`auth` when initializing an `OAuth2Client`:

```python
from requests_oauth2client import OAuth2Client, ClientSecretPost

client = OAuth2Client(
    "https://url.to.the/token_endpoint",
    auth=ClientSecretPost("client_id", "client_secret"),
)
# or
client = OAuth2Client(
    "https://url.to.the/token_endpoint", auth=("client_id", "client_secret")
)
# or
oauth2client = OAuth2Client(
    token_endpoint="https://url.to.the/token_endpoint",
    client_id="my_client_id",
    client_secret="my_client_secret",
)
```

### Client Secret JWT

With **client_secret_jwt**, the client generates an ephemeral JWT assertion including information about itself (client_id), the
AS (url of the endpoint), and an expiration date a few seconds in the future. To use it, pass a
[`ClientSecretJwt(client_id, client_secret)`](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.client_authentication.ClientSecretJwt)
as `auth` parameter. Assertion generation is entirely automatic, you don't have anything to do:

```python
from requests_oauth2client import OAuth2Client, ClientSecretJwt

client = OAuth2Client(
    "https://url.to.the/token_endpoint",
    auth=ClientSecretJwt("client_id", "client_secret"),
)
```

This method is more secure than the 2 previous, because only ephemeral credentials are transmitted, which limits the possibility for interception and replay of the Client Secret.
But that Client Secret still needs to be shared between the AS and Client owner(s).

### Private Key JWT

With **private_key_jwt**, client uses a JWT assertion that is just like the one for _client_secret_jwt_, but it is signed with an _asymmetric_ key.
To use it, you need a private signing key, in a `dict` that matches the JWK format, or as an instance of `jwskate.Jwk`. The matching public key must be
registered for your client on AS side. Once you have that, using this auth method is simple with the
[`PrivateKeyJwt(client_id, private_jwk)`](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.client_authentication.PrivateKeyJwt)
auth handler:

```python
from requests_oauth2client import OAuth2Client, PrivateKeyJwt

private_jwk = {
    "kid": "mykid",
    "kty": "RSA",
    "e": "AQAB",
    "n": "...",
    "d": "...",
    "p": "...",
    "q": "...",
    "dp": "...",
    "dq": "...",
    "qi": "...",
}

client = OAuth2Client(
    "https://url.to.the/token_endpoint", auth=PrivateKeyJwt("client_id", private_jwk)
)
# or
client = OAuth2Client(
    "https://url.to.the/token_endpoint", auth=("client_id", private_jwk)
)
# or
client = OAuth2Client(
    "https://url.to.the/token_endpoint", client_id="client_id", private_jwk=private_jwk
)
```

This method can be considered more secure than those relying on a client secret, because only ephemeral credentials are sent over the wire, and it uses asymetric cryptography: the signing key is generated by the client, and only the public key is known by the AS.
Transmitting that public key between owner(s) of the client and of the AS is much easier than transmitting the Client Secret, which is a shared key that must be considered as confidential.

### None

The latest Client Authentication Method, **none**, is for Public Clients which do not authenticate to the Token Endpoint.
Those clients only include their `client_id` in body form data, without any authentication credentials. Use
[`PublicApp(client_id)`](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.client_authentication.PublicApp):

```python
from requests_oauth2client import OAuth2Client, PublicApp

client = OAuth2Client(
    "https://url.to.the/token_endpoint", auth=PublicApp("app_client_id")
)
```

## Token Revocation

[OAuth2Client] can send revocation requests to a Revocation Endpoint. You need to provide a Revocation Endpoint URI when
creating the [OAuth2Client].
The
[OAuth2Client.revoke_token()](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.client.OAuth2Client.revoke_token)
method and its specialized aliases
[.revoke_access_token()](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.client.OAuth2Client.revoke_access_token)
and
[.revoke_refresh_token()](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.client.OAuth2Client.revoke_refresh_token)
are then available:

```python
from requests_oauth2client import OAuth2Client, ClientSecretJwt

oauth2client = OAuth2Client(
    token_endpoint="https://url.to.the/token_endpoint",
    revocation_endpoint="https://url.to.the/revocation_endpoint",
    auth=ClientSecretJwt("client_id", "client_secret"),
)

oauth2client.revoke_token("mytoken", token_type_hint="access_token")
oauth2client.revoke_access_token(
    "mytoken"
)  # will automatically add token_type_hint=access_token
oauth2client.revoke_refresh_token(
    "mytoken"
)  # will automatically add token_type_hint=refresh_token
```

Because Revocation Endpoints usually don't return meaningful responses, those methods return a boolean. This boolean
indicates that a request was successfully sent and no error was returned. If the Authorization Server returns a non-successful
HTTP code, but no standardised error message, it will return `False`. If the Authorization Server actually returns a
standardised error, an exception will be raised instead, like the other methods from `OAuth2Client`.

## Token Introspection

[OAuth2Client] can send requests to a Token Introspection Endpoint. You need to provide an Introspection Endpoint URI
when creating the `OAuth2Client`.
The
[OAuth2Client.introspect_token()](<https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.client.OAuth2Client.instrospect_token()>)
method is then available:

```python
from requests_oauth2client import OAuth2Client, ClientSecretJwt

oauth2client = OAuth2Client(
    token_endpoint="https://url.to.the/token_endpoint",
    introspection_endpoint="https://url.to.the/introspection_endpoint",
    auth=ClientSecretJwt("client_id", "client_secret"),
)

resp = oauth2client.introspect_token("mytoken", token_type_hint="access_token")
```

It returns whatever data is returned by the introspection endpoint (if it is a JSON, its content is returned decoded).

## UserInfo Requests

[OAuth2Client] can send requests to an UserInfo Endpoint. You need to provide an UserInfo Endpoint URI when creating the
`OAuth2Client`.
The
[OAuth2Client.userinfo()](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.client.OAuth2Client.userinfo))
method is then available:

```python
from requests_oauth2client import OAuth2Client, ClientSecretJwt

oauth2client = OAuth2Client(
    token_endpoint="https://url.to.the/token_endpoint",
    userinfo_endpoint="https://url.to.the/userinfo_endpoint",
    auth=ClientSecretJwt("client_id", "client_secret"),
)
resp = oauth2client.userinfo("mytoken")
```

It returns whatever data is returned by the userinfo endpoint (if it is a JSON, its content is returned decoded).

## Initializing an OAuth2Client from a discovery document

You can initialize an [OAuth2Client] with the endpoint URIs mentioned in a standardised discovery document with the
[OAuth2Client.from_discovery_endpoint()](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.client.OAuth2Client.from_discovery_document)
class method:

```python
from requests_oauth2client import OAuth2Client, ClientSecretJwt

oauth2client = OAuth2Client.from_discovery_endpoint(
    "https://url.to.the/.well-known/openid-configuration",
    auth=ClientSecretJwt("client_id", "client_secret"),
)
```

This will fetch the document from the specified URI, then will decode it and initialize an [OAuth2Client] pointing to
the appropriate endpoint URIs.

## Specialized API Client

Using APIs usually involves multiple endpoints under the same root url, with a common authentication method. To make it
easier, `requests_oauth2client` includes a [requests.Session] wrapper called [ApiClient], which takes the
root API url as parameter on initialization. You can then send requests to different endpoints by passing their relative
path instead of the full url. [ApiClient] also accepts an `auth` parameter with an AuthHandler. You can pass any of the
OAuth2 Auth Handler from this module, or any [requests]-compatible
[Authentication Handler](https://requests.readthedocs.io/en/latest/user/advanced/#custom-authentication). Which makes
it very easy to call APIs that are protected with an OAuth2 Client Credentials Grant:

```python
from requests_oauth2client import OAuth2Client, ApiClient, OAuth2ClientCredentialsAuth

oauth2client = OAuth2Client(
    "https://url.to.the/token_endpoint", ("client_id", "client_secret")
)
api = ApiClient(
    "https://myapi.local/root", auth=OAuth2ClientCredentialsAuth(oauth2client)
)

# will actually send a GET to https://myapi.local/root/resource/foo
resp = api.get("/resource/foo")
```

Note that [ApiClient] will never send requests "outside" its configured root url, unless you specifically give it a full
url at request time. The leading `/` in `/resource` above is optional. A leading `/` will not "reset" the url path to
root, which means that you can also write the relative path without the `/` and it will automatically be included:

```python
api.get("resource/foo")  # will also send a GET to https://myapi.local/root/resource/foo
```

You may also pass the path as an iterable of strings (or string-able objects), in which case they will be joined with a
`/` and appended to the url path:

```python
# will send a GET to https://myapi.local/root/resource/foo
api.get(["resource", "foo"])
# will send a GET to https://myapi.local/root/users/1234/details
api.get(["users", 1234, "details"])
```

You can also use a syntax based on `__getattr__` or `__getitem__`:

```python
api.resource.get()  # will send a GET to https://myapi.local/root/resource
api["my-resource"].get()  # will send a GET to https://myapi.local/root/my-resource
```

Both `__getattr__` and `__getitem__` return a new `ApiClient` initialised on the new base_url.
So you can easily call multiple sub-resources on the same API this way:

```python
from requests_oauth2client import ApiClient

api = ApiClient("https://myapi.local")
users_api = api.users
user = users_api.get("userid")  # GET https://myapi.local/users/userid
other_user = users_api.get("other_userid")  # GET https://myapi.local/users/other_userid
resources_api = api.resources
resources = resources_api.get()  # GET https://myapi.local/resources
```

[ApiClient] will, by default, raise exceptions whenever a request returns an error status. You can disable that by
passing `raise_for_status=False` when initializing your [ApiClient]:

```python
from requests_oauth2client import ApiClient

api = ApiClient(
    "http://httpstat.us", raise_for_status=False
)  # raise_for_status defaults to True
resp = api.get("500")
assert resp is not None
# without raise_for_status=False, a requests.exceptions.HTTPError exception would be raised instead
```

You may override this at request time:

```python
# raise_for_status at request-time overrides the value defined at init-time
resp = api.get("500", raise_for_status=True)
```

You can access the underlying `requests.Session` with the session attribute, and you can provide an already existing and configured `Session` instance at init time:

```python
import requests
from requests_oauth2client import ApiClient

session = requests.Session()
session.proxies = {"https": "http://localhost:3128"}
api = ApiClient("https://myapi.local/resource", session=session)
assert api.session == session
```

## Vendor-Specific clients

`requests_oauth2client` being flexible enough to handle most use cases, you should be able to use any AS by any vendor
as long as it supports OAuth 2.0.

You can however create a subclass of [OAuth2Client] or [ApiClient] to make it easier to use with specific Authorization
Servers or APIs. The sub-module `requests_oauth2client.vendor_specific` includes such classes for [Auth0](https://auth0.com):

```python
from requests_oauth2client.vendor_specific import Auth0Client, Auth0ManagementApiClient

a0client = Auth0Client("mytenant.eu", ("client_id", "client_secret"))
# this will automatically initialize the token endpoint to https://mytenant.eu.auth0.com/oauth/token
# and other endpoints accordingly
token = a0client.client_credentials(audience="audience")

# this is a wrapper around Auth0 Management API
a0mgmt = Auth0ManagementApiClient("mytenant.eu", ("client_id", "client_secret"))
myusers = a0mgmt.get("users")
```

[apiclient]: https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.api_client.ApiClient
[authorizationrequest]: https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.authorization_request.AuthorizationRequest
[bearerauth]: https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.auth.BearerAuth
[bearertoken]: https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.tokens.BearerToken
[oauth2client]: https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.client.OAuth2Client
[requests]: https://requests.readthedocs.io/en/latest/
[requests.session]: https://requests.readthedocs.io/en/latest/api/#requests.Session
