# Security policy

## Scope of security vulnerabilities

### Out of scope

`requests_oauth2client` is a relatively thin wrapper around the `requests` library that implements OAuth 2.x and OpenID
Connect 1.0 and some related protocols. It also uses `jwskate` for JWK and JWT handling, and `furl` for URL
parsing/manipulation. Security vulnerabilities in these underlying libraries are out of scope for this policy, and
should be reported to their respective maintainers.

Applications using this library are responsible for securely configuring and using it, including but not limited to:

- Properly validating TLS certificates when making HTTP requests
- Correctly validating JWTs according to their specific use case
- Safely managing/storing/revoking OAuth 2.x tokens and secrets
- Ensuring secure redirect URIs and scopes
- Following best practices for OAuth 2.x and OpenID Connect security

Any vulnerability in the above areas is out of scope for this policy.

### Barely in scope

In case a vulnerability in an underlying library is found to be exploitable due to the way `requests_oauth2client` uses
it, please report it to us and we will do our best to work with the maintainers of the underlying library to resolve the
issue.

### In scope

Any security vulnerabilities caused directly by the implementation of `requests_oauth2client` itself are in scope for
this policy.

Such vulnerabilities could include, but are not limited to:

- Incorrect implementation of OAuth 2.x or OpenID Connect protocols
- Flaws in the handling of OAuth 2.x flows that could lead to token leakage
- Issues in the way JWTs are created, signed, or verified that could lead to token forgery or misuse
- Problems in the way TLS is handled when making HTTP requests that could lead to man-in-the-middle attacks
- Vulnerabilities in the way JWKs are fetched or cached that could lead to key compromise
- Any other security issue directly attributable to the code in this library

## Reporting a vulnerability

If you have found a possible vulnerability that is not excluded by the above
[scope](#scope-of-security-vulnerabilities), please email `guillp dot dev at pm dot me`.

## Bug bounties

There is currently no bug bounty program for this project.

## Vulnerability disclosures process

Vulnerabilities will be handled on a best effort basis, depending on their severity and complexity. Once fixed, they
will be disclosed in the release notes of the version that includes the fix. We aim to fix and disclose vulnerabilities
within 90 days of being reported, but this may vary depending on the nature of the issue, the time required to develop
and test a fix, and the availability of the maintainer(s).
