# History

## 1.2

- `OAuth2AuthorizationCodeAuth` now accepts an AuthorizationResponse
- `AuthorizationRequest` now handles `nonce` and `acr_values`
- `OAuth2Client` accepts `authorization_endpoint` and `redirect_uri` at init time, and has a `authorization_request()` method to generate AuthorizationRequests
- `BearerToken` has a `validate_id_token()` method to handle ID Token validation has specified in OIDC
- Added `PingClient` for PingFederate by PingID

## 1.1

- ApiClient now has `allow_redirects=False` by default
- OAuth2Client now has `extra_metadata`
- bugfixes, optimizations, introduce methods for easier subclassing

## 1.0.0

- First properly documented version.
- Migrated from pipenv to poetry
- Added pre-commit checks
- `requests` is now automatically imported with `from requests_oauth2client import *`
- ApiClient is now a wrapper around `requests.Session` instead of a subclass
- `ApiClient.__init__()` now accepts extra kwargs which will be used to configure the `Session`.
- Add `__getitem__` and `__getattr_` to ApiClient
- `AuthorizationRequest.validate_callback()` now returns an `AuthorizationResponse` which contains all returned
  response attributes instead of just a code. To access the authorization code, get the `code` attribute from that response.
- `OAuth2Client.authorization_code()` now accepts an `AuthorizationResponse` as parameter, and will
  use it to include all necessary parameters for the Authorization Code Grant.
- removed `OAuth2Client.authorization_code_pkce()`
- Renamed `ClientSecretJWT` and `PrivateKeyJWT` to `ClientSecretJwt` and `PrivateKeyJwt`, for consistency with `jwskate`.
- Methods from `requests_oauth2client.utils` are no longer exposed in top-level module.
- Renamed base class `ClientAuthenticationMethod` to `BaseClientAuthenticationMethod`.
- Introduced a default timeout in `ApiClient`
- Splitted `jwskate` into its own independant module
- Use `BinaPy` for binary data manipulation
- Add support for Pushed Authorization Requests

## \<= 0.18

- Draft versions
