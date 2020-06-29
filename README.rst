A Python OAuth 2.0 client, able to make backend requests to any OAuth2.0/OIDC compliant Authorization Server Token Endpoint.

It comes with a `requests` add-on to handle OAuth 2.0 Bearer based authorization.
It can also act as an OAuth 2.0 client, to automatically get and renew access tokens,
based on the Client Credentials and Authorization Code (+ Refresh token) grants.

Use it like this:

If you already managed to obtain an access token, you can simply use the BearerAuth authorization::

    token = "an_access_token"
    resp = requests.get("https://my.protected.api/endpoint", auth=BearerAuth(token))

If you want requests to fetch an access token automatically with OAuth2.0 Client Credentials grant,
using a client_id and client_secret against a given Token Endpoint::

    client = OAuth2Client(token_endpoint, ClientSecretPost("client_id", "client_secret"))
    auth = OAuth2ClientCredentialsAuth(client, audience=audience) # pass scope, resource, audience or whatever param the AS use to grant you access
    response = requests.get("https://my.protected.api/endpoint", auth=auth)

If you want to use the authorization code grant, you must first manage to obtain an authorization code,
then exchange that code for an initial access token::

    authorization_handler = AuthorizationCodeHandler(
        authorization_endpoint,
        client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        audience=audience,
    )
    print(authorization_request.request) # redirect the user to that URL to get a code

    # once the user is successfully authenticated and authorized, the AS will respond with a redirection to the redirect_uri
    # the code is one of those parameters, but you must also validate the state
    params = input("Please enter the path and/or params obtained on the redirect_uri: ")
    code = authorization_handler.validate_callback(params)

    # initialize a OAuth2Client, same way as before
    client = OAuth2Client(token_endpoint, ClientSecretPost(client_id, client_secret))

    # once you have the code, you can exchange it manually for a token:
    token = client.authorization_code(code=code, redirect_uri=redirect_uri)
    resp = requests.post("https://your.protected.api/endpoint", auth=BearerAuthorization(token))

    # or you can use the OAuth2AuthorizationCodeAuth auth scheme:
    auth = OAuth2AuthorizationCodeAuth(client, code)
    resp = requests.post("https://your.protected.api/endpoint", auth=auth)
    # OAuth20AuthorizationCode will take care of refreshing the token automatically once it is expired,
    # using the refresh token, if available

