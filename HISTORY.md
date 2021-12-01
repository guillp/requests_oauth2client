# History

## 1.0.0 (to be released)

* First properly documented version.
* Migrated from pipenv to poetry
* Added pre-commit checks
* Major refactor of the Json Web Crypto related classes
* `requests` is now automatically imported with `from requests_oauth2client import *`
* `ApiClient.__init__()` now accepts extra kwargs which will be used to configure the `Session`.
* `AuthorizationRequest.validate_callback()` now returns an `AuthorizationResponse` which contains all returned
response attributes instead of just a code. To access the authorization code, get the `code` attribute from that response.
* `OAuth2Client.authorization_code()` now accepts an `AuthorizationResponse` as parameter, and will
use it to include all necessary parameters for the Authorization Code Grant.
* removed `OAuth2Client.authorization_code_pkce()`
* Added `ClientSecretJwt` and `PrivateKeyJwt` aliases to `ClientSecretJWT` and `PrivateKeyJWT`, for consistency with `jwskate`.
* Methods from `requests_oauth2client.utils` are no longer exposed in top-level module.
* Renamed base class `ClientAuthenticationMethod` to `BaseClientAuthenticationMethod`.
* Introduced a default timeout in `ApiClient`

## <= 0.18

* Draft versions
