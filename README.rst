A Python OAuth 2.0 client, able to obtain tokens from any OAuth2.x/OIDC compliant Authorization Server.

It comes with a `requests` add-on to handle OAuth 2.0 Bearer based authorization.
It can also act as an OAuth 2.0/2.1 client, to automatically get and renew access tokens,
based on the Client Credentials or Authorization Code (+ Refresh token) grants, and Device Authorization Grant.

It also supports PKCE, Client Assertions, and other important features that are often overlooked in other client libraries.

And it also has a wrapper around `requests.Session` that makes it super easy to use REST-style APIs.

*****
Installation
*****

As easy as::

    pip install requests_oauth2client


*****
Usage
*****

Import it like this::

    from requests_oauth2client import *

You usually also have to use requests for your actual API calls::

    import requests

That is unless you use the `ApiClient` wrapper from `requests_oauth2client`, as described below.

Calling API with an access token
======

If you already managed to obtain an access token, you can simply use the BearerAuth authorization::

    token = "an_access_token"
    resp = requests.get("https://my.protected.api/endpoint", auth=BearerAuth(token))

Obtaining tokens with the client credentials grant
=======
To obtain tokens, you can do it the "manual" way, great for testing::

    token_endpoint = "https://my.as/token"
    client = OAuth2Client(token_endpoint, ClientSecretPost("client_id", "client_secret"))
    token = client.client_credentials(scope="myscope") # you may pass additional kw params such as resource, audience, or whatever your AS needs

Or the "automated" way, for actual applications, with a custom requests Authentication Handler that will automatically
fetch an access token before accessing the API, and will obtain a new one once it is expired::

    token_endpoint = "https://my.as/token"
    client = OAuth2Client(token_endpoint, ClientSecretPost("client_id", "client_secret"))
    auth = OAuth2ClientCredentialsAuth(client, audience=audience) # you may add additional kw params such as scope, resource, audience or whatever param the AS uses to grant you access
    response = requests.get("https://my.protected.api/endpoint", auth=auth)

Obtaining tokens with the Authorization code grant
========

Obtaining tokens with the Authorization code grant is made in 2 steps.
First you must send the user to a specific url called the *Authentication Request*,
then obtain the authorization code as response to this request, then exchange it for an access token.

Generating authorization requests
****************
If you want to use the authorization code grant, you must first manage to obtain an authorization code,
then exchange that code for an initial access token::

    auth_request = AuthorizationRequest(
        authorization_endpoint,
        client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        resource=resource, # not mandatory
    ) # add any other param that needs to be sent to your AS
    print(auth_request) # redirect the user to that URL to get a code

This request will look like, with line breaks for display purposes only::

    https://myas.local/authorize
    ?client_id=my_client_id
    &redirect_uri=http%3A%2F%2Flocalhost%2Fcallback
    &response_type=code
    &state=kHWL4VwcbUbtPR4mtht6yMAGG_S-ZcBh5RxI_IGDmJc
    &nonce=mSGOS1M3LYU9ncTvvutoqUR4n1EtmaC_sQ3db4dyMAc
    &scope=openid+email+profile
    &code_challenge=Dk11ttaDb_Hyq1dObMqQcTIlfYYRVblFMC9lFM3UWW8
    &code_challenge_method=S256
    &resource=https%3A%2F%2Fmy.resource.local%2Fapi

Validating the response
**********

Once the user is successfully authenticated and authorized, the AS will respond with a redirection to the redirect_uri.
The authorization code is one of those parameters, but you must also validate that thee state matches your request.
You can do this with::

    params = input("Please enter the full url and/or params obtained on the redirect_uri: ")
    code = auth_request.validate_callback(params)

    # initialize a OAuth2Client, same way as before
    client = OAuth2Client(token_endpoint, auth=ClientSecretPost(client_id, client_secret))

AuthorizationRequest supports PKCE and uses it by default. You can avoid it by passing `code_challenge_method=None`
You can obtain the generated code_verifier from `auth_request.code_verifier`.

Exchanging code for tokens
******************

To exchange a code for access and/or ID tokens, once again you can have the "manual" way::

    token = client.authorization_code(code=code, code_verifier=auth_request.code_verifier, redirect_uri=redirect_uri) # add any other params as needed
    resp = requests.post("https://your.protected.api/endpoint", auth=BearerAuthorization(token))

Or the "automated" way::

    auth = OAuth2AuthorizationCodeAuth(client, code, redirect_uri=redirect_uri)  # add any other params as needed
    resp = requests.post("https://your.protected.api/endpoint", auth=auth)

`OAuth2AuthorizationCodeAuth` will take care of refreshing the token automatically once it is expired, using the refresh token, if available


Device Authorization Grant
===============

Helpers for the Device Authorization Grant are also included. To get device and user codes::

    da_client = DeviceAuthorizationClient(
        device_authorization_endpoint="https://myas.local/device",
        auth=(client_id, client_secret),
    )

    device_auth_resp = da_client.authorize_device()

`device_auth_resp` contains the Device Code, User Code and Verification URI returned by the AS::

    device_auth_resp.device_code
    device_auth_resp.user_code
    device_auth_resp.verification_uri
    device_auth_resp.interval

Send/show the verification uri to the user.
You can then try the Token endpoint to check if the user successfully authorized you using an OAuth2Client:

    client = OAuth2Client(
        token_endpoint="https://myas.local/token",
        auth=(client_id, client_secret)
    )

    client.device_code(device_auth_resp.device_code)

This will raise an exception, either `AuthorizationPending`, `SlowDown` or `ExpiredDeviceCode`, if the user did not yet finish authorizing your device,
if you should increase your pooling period, or if the device code is no longer valid.

To make pooling easier, you can use a `DeviceAuthorizationPoolingJob` like this:

    pool_job = DeviceAuthorizationPoolingJob(
        client,
        device_auth_resp.device_code,
        interval=device_auth_resp.interval
    )

    while True:
        resp = pool_job()
        if resp is not None:
            break

`DeviceAuthorizationPoolingJob` will automatically obey the pooling period. Everytime you call pool_job(), it will wait the appropriate number of seconds as indicated by the AS, and will apply slow_down requests.


Supported Client Authorization Methods
==============

`requests_oauth2client` supports multiple client authentication methods, as defined in multiple OAuth2.x standards.
You select the appropriate method to use when initializing your OAuth2Client, with the `auth` parameter. Once initialised,
a client will automatically use the configured authentication method every time it sends
a requested to an endpoint that requires client authentication.

- **client_secret_basic**: client_id and client_secret are included in clear-text in the Authorization header.
To use it, just pass a `ClientSecretBasic(client_id, client_secret)` as auth parameter.

- **client_secret_post**: client_id and client_secret are included as part of the body form data.
To use it, pass a `ClientSecretPost(client_id, client_secret)` as auth parameter.
This also what is being used as default when you pass a tuple `(client_id, client_secret)` as `auth`.

- **client_secret_jwt**: client generates an ephemeral JWT assertion including information about itself (client_id), the AS (url of the endpoint),
To use it, pass a `ClientSecretJWT(client_id, client_secret)` as auth parameter. Assertion generation is entirely automatic, you don't have anything to do.

- **private_key_jwt**: client uses a JWT assertion like client_secret_jwt, but it is signed with an asymetric key.
To use it, you need a private signing key, in a `dict` that matches the JWK format. The matching public key must be registered for your client on AS side. Once you have that, using this auth method is as simple with the `PrivateKeyJWT` auth handler::

    private_jwk = {
        "kid": "mykid",
        "kty": "RSA",
        "e": "AQAB", "n": "...", "d": "...", "p": "...",
        "q": "...", "dp": "...", "dq": "...", "qi": "...",
    }

    client = OAuth2Client(
        "https://myas.local/token",
         auth=PrivateKeyJWT(client_id, private_jwk)
    )

Specialized API Client
===============

Using APIs usually involves multiple endpoints under the same root url, with a common authentication method.
To make it easier, `requests_oauth2client` includes a specialized `requests.Session` subclass called ApiClient,
which takes a root url as parameter on initialization. You can then send requests to different endpoints by passing
their relative path instead of the full url. ApiClient also accepts an `auth` parameter with an AuthHandler. You can pass
any of the OAuth2 Auth Handler from this module, or any `requests`-compatible `AuthHandler`. Which makes it very easy to
call APIs that are protected with an OAuth2 Client Credentials Grant::

    oauth2client = OAuth2Client("https://myas.local/token", (client_id, client_secret))
    api = ApiClient("https://myapi.local/root", auth=OAuth2ClientCredentialsAuth(oauth2client))
    resp = api.get("/resource") # will actually send a get to https://myapi.local/root/resource

Note that `ApiClient` will never send requests "outside" its configured root url, unless you specifically give it full url at request time.
The leading / in "/resource" above is optional.
A leading / will not "reset" the url path to root, which means that you can also write::

    api.get("resource") # will actually send a get to https://myapi.local/root/resource

`ApiClient` will, by default, raise exceptions whenever a requests returns an error status. You can disable that by passing `raise_for_status=False` when initializing you ApiClient.

