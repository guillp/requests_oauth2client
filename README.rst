A Python OAuth 2.0 client, able to make backend requests to any OAuth2.x/OIDC compliant Authorization Server Token Endpoint.

It comes with a `requests` add-on to handle OAuth 2.0 Bearer based authorization.
It can also act as an OAuth 2.0/2.1 client, to automatically get and renew access tokens,
based on the Client Credentials or Authorization Code (+ Refresh token) grants.

Use it like this:

If you already managed to obtain an access token, you can simply use the BearerAuth authorization::

    token = "an_access_token"
    resp = requests.get("https://my.protected.api/endpoint", auth=BearerAuth(token))

To obtain tokens, you can do it the "manual" way, great for testing::

    token_endpoint = "https://my.as/token"
    client = OAuth2Client(token_endpoint, ClientSecretPost("client_id", "client_secret"))
    token = client.client_credentials(scope="myscope") # you may pass additional kw params such as resource, audience, or whatever your AS needs

Or the "automated" way, for actual applications, with a custom requests Authentication Handler that will automatically
fetch an access token before accessing the API, and will obtain a new one once it is expired::

    token_endpoint = "https://my.as/token"
    client = OAuth2Client(token_endpoint, ClientSecretPost("client_id", "client_secret"))
    auth = OAuth2ClientCredentialsAuth(client, audience=audience) # you may additional kw params such as scope, resource, audience or whatever param the AS use to grant you access
    response = requests.get("https://my.protected.api/endpoint", auth=auth)

If you want to use the authorization code grant, you must first manage to obtain an authorization code,
then exchange that code for an initial access token::

    auth_request = AuthorizationRequest(
        authorization_endpoint,
        client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        audience=audience,
    ) # add any other param that needs to be sent to your AS
    print(auth_request) # redirect the user to that URL to get a code

    # once the user is successfully authenticated and authorized, the AS will respond with a redirection to the redirect_uri
    # the code is one of those parameters, but you must also validate the state
    params = input("Please enter the path and/or params obtained on the redirect_uri: ")
    code = auth_request.validate_callback(params)

    # initialize a OAuth2Client, same way as before
    client = OAuth2Client(token_endpoint, auth=ClientSecretPost(client_id, client_secret))

Once again you can have the "manual" way::

    token = client.authorization_code(code=code, redirect_uri=redirect_uri) # add any other params as needed
    resp = requests.post("https://your.protected.api/endpoint", auth=BearerAuthorization(token))

Or the "automated" way::

    auth = OAuth2AuthorizationCodeAuth(client, code, redirect_uri=redirect_uri)  # add any other params as needed
    resp = requests.post("https://your.protected.api/endpoint", auth=auth)
    # OAuth20AuthorizationCode will take care of refreshing the token automatically once it is expired,
    # using the refresh token, if available

