# ![requests_oauth2client](docs/logo.png)

`requests_oauth2client` is an OAuth 2.x client for Python, able to obtain, refresh and revoke tokens from any
OAuth2.x/OIDC compliant Authorization Server. It sits upon and extends the famous [requests] HTTP client module.

It can act as an [OAuth 2.0](https://tools.ietf.org/html/rfc6749) /
[2.1](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1) client, to automatically get and renew Access Tokens,
based on the
[Client Credentials](https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-07.html#name-client-credentials),
[Authorization Code](https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-07.html#name-authorization-code),
[Refresh token](https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-07.html#name-refresh-token),
[Token Exchange](https://www.rfc-editor.org/rfc/rfc8693.html),
[JWT Bearer](https://www.rfc-editor.org/rfc/rfc7523.html#section-2.1),
[Device Authorization](https://www.rfc-editor.org/rfc/rfc8628.html),
[Resource Owner Password](https://www.rfc-editor.org/rfc/rfc6749#section-4.3) or
[CIBA](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html) grants.
Additional grant types are easy to add if needed.

It also supports [OpenID Connect 1.0](https://openid.net/specs/openid-connect-core-1_0.html),
[PKCE](https://www.rfc-editor.org/rfc/rfc7636.html),
[Client Assertions](https://www.rfc-editor.org/rfc/rfc7523.html#section-2.2),
[Token Revocation](https://www.rfc-editor.org/rfc/rfc7009.html) and
[Introspection](https://www.rfc-editor.org/rfc/rfc7662.html),
[Resource Indicators](https://www.rfc-editor.org/rfc/rfc8707.html),
[JWT-secured Authorization Requests](https://datatracker.ietf.org/doc/rfc9101/),
[Pushed Authorization Requests](https://datatracker.ietf.org/doc/rfc9126/),
[Authorization Server Issuer Identification](https://www.rfc-editor.org/rfc/rfc9207.html),
[Demonstrating Proof of Possession](https://www.rfc-editor.org/rfc/rfc9449.html),
as well as using custom params to any endpoint, and other important features that are often overlooked or needlessly
complex in other client libraries.

And it also includes a [wrapper][apiclient] around [requests.Session] that makes it super easy to use REST-style APIs,
with or without OAuth 2.x.

Please note that despite the name, this library has no relationship with Google
[oauth2client](https://github.com/googleapis/oauth2client) library.

[![made-with-python](https://img.shields.io/badge/Made%20with-Python-1f425f.svg)](https://www.python.org/)
[![PyPi version](https://img.shields.io/pypi/v/requests_oauth2client)](https://pypi.org/project/requests_oauth2client/)
[![Downloads](https://static.pepy.tech/badge/requests_oauth2client/month)](https://pepy.tech/project/requests_oauth2client)
[![Supported Versions](https://img.shields.io/pypi/pyversions/requests_oauth2client.svg)](https://pypi.org/project/requests_oauth2client)
[![PyPi license](https://badgen.net/pypi/license/requests_oauth2client/)](https://pypi.com/project/requests_oauth2client/)
[![PyPI status](https://img.shields.io/pypi/status/requests_oauth2client.svg)](https://pypi.python.org/pypi/requests_oauth2client/)
[![GitHub commits](https://badgen.net/github/commits/guillp/requests_oauth2client)](https://github.com/guillp/requests_oauth2client/commit/)
[![GitHub latest commit](https://badgen.net/github/last-commit/guillp/requests_oauth2client)](https://github.com/guillp/requests_oauth2client/commit/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

# Documentation

Full module documentation is available at https://guillp.github.io/requests_oauth2client/.

# Installation

`requests_oauth2client` is [available from PyPi](https://pypi.org/project/requests-oauth2client/), so installing it is
as easy as:

```shell
pip install requests_oauth2client
```

# Usage

Everything from `requests_oauth2client` is available from the root module, so you can import it like this:

```python
from requests_oauth2client import *
```

Or you can import individual objects from this package as usual. Note that importing `*` automatically imports
`requests`, so no need to import it yourself.

## Calling APIs with Access Tokens

If you have already obtained an access token for the API you want to call, you can convert it to an instance of
[BearerToken]. Instances of this class work as a `requests` compatible auth handler.

```python
import requests
from requests_oauth2client import BearerToken

token = BearerToken("my_access_token")
resp = requests.get("https://my.protected.api/endpoint", auth=token)
```

This authentication handler will add a `Authorization: Bearer <my_access_token>` header in the request, with your access
token value, properly formatted according to [RFC6750](https://datatracker.ietf.org/doc/html/rfc6750#section-2.1).

## Using an OAuth2Client

[OAuth2Client] offers several methods that implement the communication to the various endpoints that are standardised by
OAuth 2.0 and its extensions. These endpoints include the Token Endpoint, Revocation, Introspection, UserInfo,
BackChannel Authentication and Device Authorization Endpoints.

You must provide the URLs for these endpoints if you intend to use them. Otherwise, only the Token Endpoint is mandatory
to initialize an `OAuth2Client`.

To initialize an instance of `OAuth2Client`, you only need the Token Endpoint URI from your Authorization Server (AS),
and the credentials for your application, typically a `client_id` and a `client_secret`, usually also provided by the
AS:

```python
from requests_oauth2client import OAuth2Client

oauth2client = OAuth2Client(
    token_endpoint="https://url.to.the/token_endpoint",
    client_id="my_client_id",
    client_secret="my_client_secret",
)
```

The Token Endpoint is the only endpoint that is mandatory to obtain tokens. Credentials are used to authenticate the
client everytime it sends a request to its Authorization Server. Usually, these are a static Client ID and Secret, which
are the equivalent of a username and a password, but meant for an application instead of for a human user. The default
authentication method used by `OAuth2Client` is *Client Secret Post*, but other standardized methods such as *Client
Secret Basic*, *Client Secret JWT* or *Private Key JWT* are supported as well. See
[more about client authentication methods below](#supported-client-authentication-methods).

Instead of providing each endpoint URL yourself, you may also
[use the AS metadata endpoint URI](#initializing-an-oauth2client-from-a-discovery-document), or the document data
itself, to initialize your OAuth 2.0 client with the appropriate endpoints.

## Obtaining tokens

[OAuth2Client] has dedicated methods to send requests to the Token Endpoint using different standardized grants. Since
the Token Endpoint URL and Client Authentication Method are already declared for the client at initialization, the only
required parameters for these methods are those that will be sent in the request to the Token Endpoint.

These methods directly return a [BearerToken] if the request is successful, or raise an exception if it fails.
[BearerToken] contains all the data returned by the Token Endpoint, including the Access Token. It will also:

- Keep track of the Access Token expiration date (based on the `expires_in` hint as returned by the AS). This date is
  accessible with the `expires_at` attribute.
- Contain the Refresh Token, if returned by the AS, accessible with the `refresh_token` attribute.
- Contain the ID Token, if returned by the AS, accessible with the `id_token` attribute (typically available when using
  the Authorization Code flow).
- Keep track of other associated metadata as well, also accessible as attributes with the same name:
  `token.custom_attr`, or with subscription syntax `token["my.custom.attr"]`.

You can create such a [BearerToken] yourself if needed:

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

Note that the `expires_in` indicator here is not static. It keeps track of the token lifetime, in seconds, and is
calculated as the time flies. The actual static expiration date is accessible with the `expires_at` property. You can
check if a token is expired with
[bearer_token.is_expired()](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.tokens.BearerToken.is_expired).

You can use a [BearerToken] instance anywhere you can use an access_token as string.

### Using OAuth2Client as a requests Auth Handler

Using [OAuth2Client] directly is useful for testing or debugging OAuth2.x flows, but it may not be suitable for actual
applications where tokens must be obtained, used during their lifetime, then obtained again or refreshed once they are
expired. `requests_oauth2client` contains several [requests] compatible Auth Handlers (as subclasses of
[requests.auth.AuthBase](https://requests.readthedocs.io/en/latest/user/advanced/#custom-authentication)), that will
take care of obtaining tokens when required, then will cache those tokens until they are expired, and will obtain new
ones (or refresh them, when possible), once the initial token is expired. Those are best used with a [requests.Session],
or an [ApiClient], which is a wrapper around `Session` with a few enhancements as described below.

### Client Credentials grant

To send a request using the Client Credentials grant, use the
[.client_credentials()](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.client.OAuth2Client.client_credentials)
method, providing the necessary parameters as keyword arguments in the token request.

```python
from requests_oauth2client import OAuth2Client

oauth2client = OAuth2Client(
    token_endpoint="https://url.to.the/token_endpoint",
    client_id="client_id",
    client_secret="client_secret",
)

token = oauth2client.client_credentials(scope="myscope")
# or, if your AS uses resource indicator:
token = oauth2client.client_credentials(scope="myscope", resource="https://myapi.local")
# or, if your AS uses 'audience' as parameter to identify the requested API (Auth0 style):
token = oauth2client.client_credentials(audience="https://myapi.local")
# or, if your AS uses custom parameters:
token = oauth2client.client_credentials(scope="myscope", custom_param="custom_value")
```

Parameters such as `scope`, `resource`, or `audience`, as well as any other required parameters by the Authorization
Server (AS), can be passed as keyword parameters. These parameters will be included in the token request sent to the AS.
Please note that none of those parameters are mandatory at the client level, but some might be required by your AS to
fulfill your request.

#### As Auth Handler

You can use the
[OAuth2ClientCredentialsAuth](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.auth.OAuth2ClientCredentialsAuth)
auth handler. It takes an `OAuth2Client` as parameter, and the additional kwargs to pass to the token endpoint:

```python
import requests
from requests_oauth2client import OAuth2Client, OAuth2ClientCredentialsAuth

oauth2client = OAuth2Client(
    token_endpoint="https://url.to.the/token_endpoint",
    client_id="client_id",
    client_secret="client_secret",
)

auth = OAuth2ClientCredentialsAuth(
    oauth2client, scope="myscope", resource="https://myapi.local"
)

# use it like this:
requests.get("https://myapi.local/resource", auth=auth)

# or like this:
session = requests.Session()
session.auth = auth

resp = session.get("https://myapi.local/resource")
```

Once again, extra parameters such as `scope`, `resource` or `audience` are allowed if required.

When you send your first request,
[OAuth2ClientCredentialsAuth](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.auth.OAuth2ClientCredentialsAuth)
will automatically retrieve an access token from the AS using the Client Credentials grant, then will include it in the
request. Next requests will use the same token, as long as it is valid. A new token will be automatically retrieved once
the previous one is expired.

You can configure a leeway, which is a period of time before the actual expiration, in seconds, when a new token will be
obtained. This may help getting continuous access to the API when the client and API clocks are slightly out of sync.
Use the parameter `leeway` to `OAuth2ClientCredentialsAuth`:

```python
from requests_oauth2client import OAuth2ClientCredentialsAuth

auth = OAuth2ClientCredentialsAuth(
    oauth2client,
    scope="myscope",
    leeway=30,
)
```

### Authorization Code Grant

Obtaining tokens using the Authorization code grant is made in 3 steps:

1. your application must open a specific url called the *Authentication Request* in a browser.
2. your application must obtain and validate the *Authorization Response*, which is a redirection back to your
   application that contains an *Authorization Code* as parameter. This redirect back (often called "callback") is
   initiated by the Authorization Server after any necessary interaction with the user is complete (Registration, Login,
   Profile completion, Multi-Factor Authentication, Authorization, Consent, etc.)
3. your application must then exchange this Authorization Code for an *Access Token*, with a request to the Token
   Endpoint.

Using an `OAuth2Client` will help you with all those steps, as described below.

#### Generating Authorization Requests

To be able to use the Authorization Code grant, you need 2 (optionally 3) URIs:

- the URL for Authorization Endpoint, which is the url where you must send your Authorization Requests
- the Redirect URI, which is the url pointing to your application, where the Authorization Server will reply with
  Authorization Response
- optionally, the issuer identifier, if your AS uses
  [Issuer Identification](https://www.rfc-editor.org/rfc/rfc9207.html).

You can declare those URIs when initializing your `OAuth2Client` instance, or you can
[use the AS discovery endpoint](#initializing-an-oauth2client-from-a-discovery-document) to initialize those URLs
automatically. Then you can generate valid Authorization Requests by calling the method `.authorization_request()`, with
the request specific parameters, such as `scope`, `state`, `nonce` as parameter:

```python
from requests_oauth2client import OAuth2Client

client = OAuth2Client(
    token_endpoint="https://url.to.the/token_endoint",
    authorization_endpoint="https://url.to.the/authorization_endpoint",
    redirect_uri="https://url.to.my.application/redirect_uri",
    client_id="client_id",
    client_secret="client_secret",
)

az_request = client.authorization_request(scope="openid email profile")

print(az_request)
# this will look like this, with line feeds for display purposes only:
# https://url.to.the.as/authorization_endpoint
# ?client_id=client_id
# &redirect_uri=https%3A%2F%2Furl.to.my.application%2Fredirect_uri
# &response_type=code
# &scope=openid+email+profile
# &state=FBx9mWeLwoKGgG76vhi6v61-4mgxmgZhtWIa7aTffdY
# &nonce=iHZJokhkGOAojff1tdknRyz9mPZyy5vq9JDlVaUHyqk
# &code_challenge=TG7qgdyKnwUPuoQ6NNJRlLMoHbeVmJlB8g0VOcfQEkc
# &code_challenge_method=S256

# you can send the user to that url with:
import webbrowser

webbrowser.open(az_request.uri)
```

Note that the `state`, `nonce` and `code_challenge` parameters are generated with secure random values by default.
Should you wish to use your own values, you can pass them as parameters to `OAuth2Client.authorization_request()`. For
PKCE, you need to pass your generated `code_verifier`, and the `code_challenge` will automatically be derived from it.
If you want to disable PKCE, you can pass `code_challenge_method=None` when initializing your `OAuth2Client`.

#### Validating the Authorization Response

Once you have redirected the user browser to the Authorization Request URI, and after the user is successfully
authenticated and authorized, plus any other extra interactive step is complete, the AS will respond with a redirection
to your redirect_uri. That is the *Authorization Response*. It contains several parameters that must be retrieved by
your client. The *Authorization Code* is one of those parameters, but you must also validate that the *state* matches
your request; if using [AS Issuer Identification](https://www.rfc-editor.org/rfc/rfc9207.html), you must also validate
that the issuer matches what is expected. You can do this with:

```python
# using the `az_request` as defined above

response_uri = input(
    "Please enter the full url and/or params obtained on the redirect_uri: "
)
# say the callback url is https://url.to.my.application/redirect_uri?code=an_az_code&state=FBx9mWeLwoKGgG76vhi6v61-4mgxmgZhtWIa7aTffdY&issuer=https://url.to.the.as
az_response = az_request.validate_callback(response_uri)
```

This `auth_response` is an `AuthorizationResponse` instance and contains everything that is needed for your application
to complete the authentication and get its tokens from the AS.

#### Exchanging code for tokens

Once you have obtained the AS response, containing an authorization code, your application must exchange it for actual
Token(s).

To exchange a code for Access and/or ID tokens, use the
[OAuth2Client.authorization_code()](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.client.OAuth2Client.authorization_code)
method. If you have obtained an AuthorizationResponse as described above, you can simply do:

```python
token = oauth2client.authorization_code(az_response)
```

This will automatically include the `code`, `redirect_uri` and `code_verifier` parameters in the Token Request, as
expected by the AS. You may include extra parameters if required, or you may pass your own parameters, without using an
`AuthorizationResponse` instance, like this:

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

oauth2client = OAuth2Client(
    token_endpoint="https://url.to.the/token_endpoint",
    authorization_endpoint="https://url.to.the/authorization_endpoint",
    auth=("client_id", "client_secret"),
)

api_client = ApiClient(
    "https://your.protected.api/endpoint",
    auth=OAuth2AuthorizationCodeAuth(
        oauth2client,
        "my_authorization_code",
    ),
)

# any request using api_client will trigger exchanging the code for an access_token, which is then cached, and refreshed later if needed
resp = api_client.post(data={...})
```

[OAuth2AuthorizationCodeAuth](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.auth.OAuth2AuthorizationCodeAuth)
will take care of refreshing the token automatically once it is expired, using the refresh token, if available.

### Note on AuthorizationRequest

Authorization Requests generated by `OAuth2Client.authorization_request()` are instance of the class
[`AuthorizationRequest`](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.authorization_request.AuthorizationRequest).
You can also use that class directly to generate your requests, but in that case you need to supply your Authorization
Endpoint URI, your `client_id`, `redirect_uri`, etc. You can access every parameter from an `AuthorizationRequest`
instance, as well as the generated `code_verifier`, as attributes of this instance. Once an Authorization Request URL is
generated, it your application responsibility to redirect or otherwise send the user to that URL. You may use the
`webbrowser` module from Python standard library to do so. Here is an example for generating Authorization Requests:

```python
from requests_oauth2client import AuthorizationRequest

az_request = AuthorizationRequest(
    "https://url.to.the/authorization_endpoint",
    client_id="my_client_id",
    redirect_uri="http://localhost/callback",  # this redirect_uri is specific to your app
    scope="openid email profile",
    # extra parameters such as `resource` can be included as well if required by your AS
    resource="https://my.resource.local/api",
)
print(
    az_request
)  # this request will look like this, with line breaks for display purposes only
# https://url.to.the/authorization_endpoint
# ?client_id=my_client_id
# &redirect_uri=http%3A%2F%2Flocalhost%callback
# &response_type=code
# &state=kHWL4VwcbUbtPR4mtht6yMAGG_S-ZcBh5RxI_IGDmJc
# &nonce=mSGOS1M3LYU9ncTvvutoqUR4n1EtmaC_sQ3db4dyMAc
# &scope=openid+email+profile
# &code_challenge=W3n02f6xUKoDVbmhWEWz3h780b-Ci6ucnBS_d7nogmQ
# &code_challenge_method=S256
# &resource=https%3A%2F%2Fmy.resource.local%2Fapi

print(az_request.code_verifier)
# 'gYK-ZnQfoat2bghwed7oEz--wvn4D70ksJ5GuWO9sXXygZ7PMnUlSpBmMCcNRHxdgTS9m_roYwGxF6HQxIqZVwXmxRJUziFHUFxDrNuUIjCJCx6gBhPlpFbUXulB1fo2'
```

### Device Authorization Grant

Helpers for the Device Authorization Grant are also included. To get device and user codes, read the response attributes
(including Device Code, User Code, Verification URI, etc.), then pooling the Token Endpoint:

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

# `da_resp` contains the Device Code, User Code, Verification URI, and other info returned by the AS:
da_resp.device_code
da_resp.user_code
da_resp.verification_uri
da_resp.verification_uri_complete
da_resp.expires_at
da_resp.interval

# Send/show the Verification Uri and User Code to the user. They must use a browser to visit that URL, authenticate, and input the User Code.

# You can then request the Token endpoint to check if the user successfully authorized your device like this:
pool_job = DeviceAuthorizationPoolingJob(client, da_resp)

resp = None
while resp is None:
    resp = pool_job()

assert isinstance(resp, BearerToken)
```

[DeviceAuthorizationPoolingJob](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.device_authorization.DeviceAuthorizationPoolingJob)
will automatically obey the pooling period. Everytime you call `pool_job()`, it will wait the appropriate number of
seconds as indicated by the AS, and will apply slow-down requests.

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

# then try to send your request with an OAuth2DeviceCodeAuth handler
# this will pool the token endpoint until the user authorizes the device
api_client = ApiClient(
    "https://your.protected.api/endpoint",
    auth=OAuth2DeviceCodeAuth(client, device_auth_resp),
)

resp = api_client.post(
    data={...}
)  # the first call will hang until the user authorizes your app and the token endpoint returns a token.
```

### Client-Initiated BackChannel Authentication (CIBA)

To initiate a BackChannel Authentication against the dedicated endpoint, read the response attributes and pool the Token
Endpoint until the end-user successfully authenticates:

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
ba_resp.expires_in  # decreases with time
ba_resp.expires_at  # a static `datetime` to keep track of the expiration date, based on the "expires_in" returned by the AS
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

With **client_secret_basic**, `client_id` and `client_secret` are included in clear-text in the `Authorization` header
when sending requests to the Token Endpoint. To use it, just pass a
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

With **client_secret_post**, `client_id` and `client_secret` are included as part of the body form data. To use it, pass
a
[`ClientSecretPost(client_id, client_secret)`](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.client_authentication.ClientSecretPost)
as `auth` parameter. This is the default when you pass a tuple `(client_id, client_secret)` as `auth` when initializing
an `OAuth2Client`:

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

With **client_secret_jwt**, the client generates an ephemeral JWT assertion including information about itself
(client_id), the AS (url of the endpoint), and an expiration date a few seconds in the future. To use it, pass a
[`ClientSecretJwt(client_id, client_secret)`](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.client_authentication.ClientSecretJwt)
as `auth` parameter. Assertion generation is entirely automatic, you don't have anything to do:

```python
from requests_oauth2client import OAuth2Client, ClientSecretJwt

client = OAuth2Client(
    "https://url.to.the/token_endpoint",
    auth=ClientSecretJwt("client_id", "client_secret"),
)
```

This method is more secure than the 2 previous, because only ephemeral credentials are transmitted, which limits the
possibility for interception and replay of the Client Secret. But that Client Secret still needs to be shared between
the AS and Client owner(s).

### Private Key JWT

With **private_key_jwt**, client uses a JWT assertion that is just like the one for _client_secret_jwt_, but it is
signed with an _asymmetric_ key. To use it, you need a private signing key, in a `dict` that matches the JWK format, or
as an instance of `jwskate.Jwk`. The matching public key must be registered for your client on AS side. Once you have
that, using this auth method is simple with the
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

This method can be considered more secure than those relying on a client secret, because only ephemeral credentials are
sent over the wire, and it uses asymmetric cryptography: the signing key is generated by the client, and only the public
key is known by the AS. Transmitting that public key between owner(s) of the client and of the AS is much easier than
transmitting the Client Secret, which is a shared key that must be considered as confidential.

### None

The latest Client Authentication Method, **none**, is for Public Clients which do not authenticate to the Token
Endpoint. Those clients only include their `client_id` in body form data, without any authentication credentials. Use
[`PublicApp(client_id)`](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.client_authentication.PublicApp):

```python
from requests_oauth2client import OAuth2Client, PublicApp

client = OAuth2Client(
    "https://url.to.the/token_endpoint", auth=PublicApp("app_client_id")
)
```

## Token Revocation

The [OAuth2Client] class provides methods for sending revocation requests to a Revocation Endpoint. To use this feature,
you need to provide the Revocation Endpoint URI when creating an instance of [OAuth2Client].
The available methods for revoking tokens are:

- [revoke_token()](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.client.OAuth2Client.revoke_token): Revokes a token by providing the token value and an optional token_type_hint.
- [revoke_access_token()](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.client.OAuth2Client.revoke_access_token): Revokes an access token by providing the token value.
- [revoke_refresh_token()](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.client.OAuth2Client.revoke_refresh_token): Revokes a refresh token by providing the token value.

Here is an example of how to use these methods:

```python
from requests_oauth2client import OAuth2Client, ClientSecretJwt

oauth2client = OAuth2Client(
    token_endpoint="https://url.to.the/token_endpoint",
    revocation_endpoint="https://url.to.the/revocation_endpoint",
    auth=ClientSecretJwt("client_id", "client_secret"),
)

oauth2client.revoke_token("mytoken", token_type_hint="access_token")
oauth2client.revoke_access_token("mytoken")
oauth2client.revoke_refresh_token("mytoken")
```

These methods return a boolean value indicating whether the revocation request was successfully sent and no error was
returned. If the Authorization Server returns a non-successful HTTP code without a standard error message, it will
return `False`. If the Authorization Server returns a standard error, an exception will be raised.

## Token Introspection

The [OAuth2Client] class also supports sending requests to a Token Introspection Endpoint.
To use this feature, you need to provide the Introspection Endpoint URI when creating an instance of [OAuth2Client].
The [introspect_token()](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.client.OAuth2Client.instrospect_token())
method is then available for introspecting tokens:

```python
from requests_oauth2client import OAuth2Client, ClientSecretJwt

oauth2client = OAuth2Client(
    token_endpoint="https://url.to.the/token_endpoint",
    introspection_endpoint="https://url.to.the/introspection_endpoint",
    auth=ClientSecretJwt("client_id", "client_secret"),
)

resp = oauth2client.introspect_token("mytoken", token_type_hint="access_token")
```

The `introspect_token()` method returns the data returned by the introspection endpoint, decoded if it is in JSON format.

## UserInfo Requests

The [OAuth2Client] class also supports sending requests to a UserInfo Endpoint.
To use this feature, you need to provide the UserInfo Endpoint URI when creating an instance of [OAuth2Client]
The [userinfo()](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.client.OAuth2Client.userinfo)
method is then available for retrieving user information:

```python
from requests_oauth2client import OAuth2Client, ClientSecretJwt

oauth2client = OAuth2Client(
    token_endpoint="https://url.to.the/token_endpoint",
    userinfo_endpoint="https://url.to.the/userinfo_endpoint",
    auth=ClientSecretJwt("client_id", "client_secret"),
)

resp = oauth2client.userinfo("mytoken")
```

The `userinfo()` method returns the data returned by the userinfo endpoint, decoded if it is in JSON format.

## Initializing an `OAuth2Client` from a discovery document

You can initialize an [OAuth2Client] with the endpoint URIs mentioned in a standardised discovery document using the
[OAuth2Client.from_discovery_endpoint()](https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.client.OAuth2Client.from_discovery_document)
class method:

```python
from requests_oauth2client import OAuth2Client, ClientSecretJwt

oauth2client = OAuth2Client.from_discovery_endpoint(
    "https://url.to.the.as/.well-known/openid-configuration",
    auth=ClientSecretJwt("client_id", "client_secret"),
)

# OR, if you know the issuer value
oauth2client = OAuth2Client.from_discovery_endpoint(
    issuer="https://url.to.the.as",
    auth=ClientSecretJwt("client_id", "client_secret"),
)
```

This will fetch the document from the specified URI, decode it, and initialize an [OAuth2Client] pointing to the
appropriate endpoint URIs.

If you use the `issuer` keyword argument, the URI to the discovery endpoint will be deduced from that identifier, and a
check will be made to ensure that the `issuer` from the retrieved metadata document matches that value.

## Using DPoP

### Basic usage

`DPoP` (Demonstrating Proof of Possession) is supported out-of-the-box. To obtain a *DPoP* token, you can either:

- pass `dpop=True` when using any `OAuth2Client` method that sends a token request,
- or enable `DPoP` by default by passing `dpop_bound_access_tokens=True` when initializing your client.

```python
from requests_oauth2client import DPoPToken, OAuth2Client

oauth2client = OAuth2Client.from_discovery_endpoint(
    issuer="https://as.local",
    client_id="client_id", client_secret="client_secret",
)

token = oauth2client.client_credentials(scope="my_scope", dpop=True)
assert isinstance(token, DPoPToken)

# or, to enable DPoP by default for every token request
oauth2client = OAuth2Client.from_discovery_endpoint(
    issuer="https://as.local",
    client_id="client_id", client_secret="client_secret",
    dpop_bound_access_tokens=True,
)
token = oauth2client.client_credentials(scope="my_scope")
assert isinstance(token, DPoPToken)
```

### About `DPoPToken`

`DPoPToken` is actually a `BearerToken` subclass. If you use it as a `requests` Auth Handler, it will take care of
adding a `DPoP` proof to the request headers, in addition to the access token.

Since it is a `BearerToken` subclass, it is fully compatible with the `requests` compatible auth handlers provided by
`requests_oauth2client`, such as `OAuth2ClientCredentialsAuth`, `OAuth2AccessTokenAuth`, etc. So you may use DPoP with
those auth handlers like this:

```python
import requests
from requests_oauth2client import OAuth2Client, OAuth2ClientCredentialsAuth, PrivateKeyJwt

client = OAuth2Client.from_discovery_endpoint(
    issuer="https://my.issuer.local",
    auth=PrivateKeyJwt("client_id", "client_secret"),
    dpop_bound_access_tokens=True, # enable DPoP by default
)

session = requests.Session()
session.auth = OAuth2ClientCredentialsAuth(
    client=client,
    scope="my_scope"
)

resp = session.get("https://my.api.local/endpoint")  # this will automatically obtain a DPoP token and use it
assert "DPoP" in resp.requests.headers  # the appropriate DPoP proof will be included in the request
```

Since DPoP is enabled by default with `dpop_bound_access_tokens=True`, then the `OAuth2ClientCredentialsAuth` will
obtain and use `DPoPToken` instances. You could also leave it disabled by default and pass `dpop=True` when initializing
you auth handler instance: `OAuth2ClientCredentialsAuth(client=client, scope="my_scope", dpop=True)`.

### Choosing your own proof signature keys

By default, the private key used for signing `DPoP` proofs is auto-generated by `OAuth2Client` whenever a new token is
obtained. By default, generated keys are of type *Elliptic Curve* (`EC`), and use the `ES256` signature alg (as in
*Elliptic-Curve with a SHA256 hash*). Should you, for testing purposes, wish to generate or use your own key, you may
use the parameter `dpop_key` to provide a key of your choice. It takes a `DPoPKey` instance, which you can generate
using `DPoPKey.generate()`, or by initializing an instance with a key that you previously generated:

```python
from cryptography.hazmat.primitives.asymmetric import rsa
import jwskate
from requests_oauth2client import DPoPKey, DPoPToken, OAuth2Client

oauth2client = OAuth2Client.from_discovery_endpoint(
    issuer="https://as.local",
    client_id="client_id", client_secret="client_secret",
    dpop_bound_access_tokens=True,
)

dpop_key = DPoPKey.generate(alg="RS512")  # generate a new DPoP key with an alg of your choice
# or, for testing purposes only, your can load your own key
dpop_key = DPoPKey(private_key=jwskate.Jwk({"kty": "EC", "crv": "P-256", "alg": "ES256", "x": "...", "y": "...", "d": "..."}))
# or, any key material supported by `jwskate` is supported, so you can also use `cryptography` keys directly,
# but you need to specify the signature `alg` since it is not part of the key itself
dpop_key = DPoPKey(private_key=rsa.generate_private_key(public_exponent=65537, key_size=2048), alg="RS256")

token = oauth2client.client_credentials(scope="my_scope", dpop_key=dpop_key)
assert isinstance(token, DPoPToken)
assert token.dpop_key == dpop_key
```

### Hooking into DPoP key and proof generation

Instead of generating your own keys everytime, you may also control how `DPoPKey`s are automatically generated. This can
be useful for fuzz-testing, pen-testing or feature-testing the Authorization Server. To choose the signing alg, use the
parameter `dpop_alg` when initializing your client. This will accordingly determine the key type to generate. You may
also pass a custom `dpop_key_generator`, which is a callable that accepts a signature `alg` as parameter, and generates
`DPoPKey` instances.

You can also override the `DPoPToken` class with a custom one, which will be used to represent the DPoP token that is
returned by the AS, and then generates proofs and includes those proofs into HTTP requests.

You may use `DPoPKey.generate` as a helper method for that, or implement your own generator:


```python
import secrets
from requests_oauth2client import DPoPKey, DPoPToken, OAuth2Client

class CustomDPoPToken(DPoPToken):
    """A custom DPoP token class that places the DPoP proof and token into a non-standard header."""
    AUTHORIZATION_HEADER = "X-Custom-Auth"
    DPOP_HEADER = "X-DPoP"

oauth2client = OAuth2Client.from_discovery_endpoint(
    issuer="https://as.local",
    client_id="client_id", client_secret="client_secret",
    dpop_bound_access_tokens=True,  # enable DPoP by default
    dpop_alg="RS256", # choose the signing alg to use, and it will automatically determine the key type to generate.
    dpop_key_generator=lambda alg: DPoPKey.generate(
        alg=alg,
        # those other parameters are for feature testing the AS, or for workarounding AS bugs:
        jwt_typ="jwt+custom", # you can customize the `typ` that is included in DPoP proof headers
        jti_generator=lambda: secrets.token_urlsafe(24), # generate unique jti differently than the default UUIDs
        iat_generator=lambda: 12532424, # override `iat` generation in DPoP proofs, here it will return a static value
        dpop_token_class=CustomDPoPToken, # override the class that represents DPoP tokens
    )
)
```

### About DPoP nonces

Authorization Server provided `DPoP` nonces are automatically and transparently handled by `OAuth2Client`.

Likewise, Resource Server provided `DPoP` nonces are supported when using the default `DPoPToken` class.
This includes all requests-compatible auth handlers provided by `requests_oauth2client`, like `OAuth2AccessTokenAuth`,
`OAuth2ClientCredentialsAuth`, `OAuth2AuthorizationCodeAuth`, etc.

As an example, see the sample below:

```python
from requests_oauth2client import OAuth2Client, OAuth2ClientCredentialsAuth

import requests

oauth2client = OAuth2Client.from_discovery_endpoint(
    issuer="https://as.local",
    client_id="client_id", client_secret="client_secret",
)

response = requests.get(
    "https://my.api.local/endpoint",
    auth=OAuth2ClientCredentialsAuth(oauth2client, scope="my_scope", dpop=True),
)
```

Assuming that both the Authorization Server (at https://as.local) and the Resource Server (at https://my.api.local)
require the use of `DPoP` nonces, then at least 4 different requests are sent as a result of the `requests.get()` call
above:

1. The first request is to get a token from the Authorization Server, here using a *Client Credentials* grant and
including a DPoP proof. DPoP also works with all other grant types. That first requests does not include a nonce.
Since the AS requires a DPoP nonce, it replies to that request with an `error=use_dpop_nonce` flag and a generated DPoP
nonce.
2. Second request is automatically sent to the AS, this time with a DPoP proof that contains the nonce provided by the AS.
As a result, the AS returns a DPoP token.
3. Third request is sent to the target API, with the DPoP token obtained at step 2, and a DPoP proof that does not yet
contain a `nonce`.
   The response from this call is a `401` with at least these 2 response headers:

   - a `WWW-Authenticate: DPoP error="use_dpop_nonce"` header, indicating that a DPoP `nonce` is requested,
   - and a `DPoP-Nonce` header containing the `nonce` to use.
4. a request is sent again to the target API, this time with a DPoP proof that contains the RS provided `nonce`
   obtained at step 3. Target API then should accept that request, do its own business and return a `200` response.

If you send multiple requests to the same API, instead of using individual calls to `requests.get()`, `requests.post()`
etc., you should use a `requests.Session` or an `ApiClient`. It will make sure that the obtained access token and
DPoP nonce(s) are reused as long as they are valid, which avoid repeating calls 1 and 2 unnecessarily and consuming more
tokens and nonces than necessary:

```python
from requests_oauth2client import ApiClient, OAuth2Client, OAuth2ClientCredentialsAuth

oauth2client = OAuth2Client.from_discovery_endpoint(
    issuer="https://as.local",
    client_id="client_id",
    client_secret="client_secret",
)

api = ApiClient("https://my.api.local/", auth=OAuth2ClientCredentialsAuth(oauth2client, scope="my_scope", dpop=True))
response1 = api.get("endpoint") # the first call will trigger requests 1. 2. 3. 4. like above
response2 = api.post("other_endpoint") # next calls will reuse the same token and DPoP nonces as long as they are valid.
# some time later
response3 = api.get("other_endpoint") # new tokens and DPoP nonces will automatically be obtained when the first ones are expired
```

AS and RS provided nonces are memoized independently by the `DPoPToken` instance, so the amount of "extra" requests to
obtain new DPoP nonces should be minimal.

## Specialized API Client

Using APIs usually involves multiple endpoints under the same root url, with a common authentication method. To make it
easier, `requests_oauth2client` includes a [requests.Session] wrapper called [ApiClient], which takes the root API url
as parameter on initialization. You can then send requests to different endpoints by passing their relative path instead
of the full url. [ApiClient] also accepts an `auth` parameter with an AuthHandler. You can pass any of the OAuth2 Auth
Handler from this module, or any [requests]-compatible
[Authentication Handler](https://requests.readthedocs.io/en/latest/user/advanced/#custom-authentication). Which makes it
very easy to call APIs that are protected with an OAuth2 Client Credentials Grant:

```python
from requests_oauth2client import OAuth2Client, ApiClient, OAuth2ClientCredentialsAuth

oauth2client = OAuth2Client(
    "https://url.to.the/token_endpoint", client_id="client_id", client_secret="client_secret"
)
api = ApiClient(
    "https://myapi.local/root", auth=OAuth2ClientCredentialsAuth(oauth2client)
)

# will actually send a GET to https://myapi.local/root/resource/foo
resp = api.get("/resource/foo")
```

Note that [ApiClient] will never send requests "outside" its configured root url. The leading `/` in `/resource` above
is optional. A leading `/` will not "reset" the url path to root, which means that you can also write the relative path
without the `/` and it will automatically be included:

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

Both `__getattr__` and `__getitem__` return a new `ApiClient` initialised on the new base_url. So you can easily call
multiple sub-resources on the same API this way:

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

You can access the underlying `requests.Session` with the session attribute, and you can provide an already existing and
configured `Session` instance at init time:

```python
import requests
from requests_oauth2client import ApiClient

session = requests.Session()
session.proxies = {"https": "http://localhost:3128"}
api = ApiClient("https://myapi.local/resource", session=session)
assert api.session == session
```

## Vendor-Specific clients

`requests_oauth2client` is flexible enough to handle most use cases, so you should be able to use any AS by any vendor
as long as it supports OAuth 2.0.

You can however create a subclass of [OAuth2Client] or [ApiClient] to make it easier to use with specific Authorization
Servers or APIs. [OAuth2Client] has several extensibility points in the form of methods like
`OAuth2Client.parse_token_response()`, `OAuth2Client.on_token_error()` that implement response parsing, error handling,
etc.

```python
from requests_oauth2client.vendor_specific import Auth0

a0client = Auth0.client(
    "mytenant.eu", client_id="client_id", client_secret="client_secret"
)
# this will automatically initialize the token endpoint to https://mytenant.eu.auth0.com/oauth/token
# and other endpoints accordingly
token = a0client.client_credentials(audience="audience")

# this is a wrapper around Auth0 Management API
a0mgmt = Auth0.management_api_client(
    "mytenant.eu", client_id="client_id", client_secret="client_secret"
)
myusers = a0mgmt.get("users")
```

[apiclient]: https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.api_client.ApiClient
[bearertoken]: https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.tokens.BearerToken
[oauth2client]: https://guillp.github.io/requests_oauth2client/api/#requests_oauth2client.client.OAuth2Client
[requests]: https://requests.readthedocs.io/en/latest/
[requests.session]: https://requests.readthedocs.io/en/latest/api/#requests.Session
