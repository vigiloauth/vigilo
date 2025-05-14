# OpenID Connect Conformance Tests Checklist

## Setup
1. Clone the repo: `git clone git@gitlab.com:openid/conformance-suite.git`
2. Install maven and docker.
3. Ensure you are using Java version 11 (any 11.0 version is fine).
4. Build the Java code using: `mvn clean package`.
5. Start the docker container using: `docker-compose up`. For development, use `docker-compose -f docker-compose-dev.yml up` or `docker-compose -f docker-compose-dev-mac.yml up`.
6. The UI will be available at `http://localhost:8443/`

You can visit OpenID's official [GitLab](https://gitlab.com/openid/conformance-suite/-/wikis/Developers/Build-&-Run) for more information on how to properly setup the conformance suite.

## Conformance Profiles Tests
### 🛠️ OIDC Basic Certification Plan / OIDC Comprehensive Authorization Server Test
- ✅ `oidcc-server`
- ✅ `oidcc-ensure-request-without-nonce-succeeds-for-code-flow`
- ✅ `oidcc-idtoken-rs256`
- ✅ `oidcc-idtoken-signature`
- ✅ `oidcc-idtoken-unsigned` (skipped, VigiloAuth does not support `none` as a token signing algorithm)
- ✅ `oidcc-scope-address`
- ✅ `oidcc-scope-all`
- ✅ `oidcc-scope-email`
- ✅ `oidcc-scope-phone`
- ✅ `oidcc-scope-profile`
- ✅ `oidcc-ensure-other-scope-order-succeeds`
- ✅ `oidcc-userinfo-get`
- ✅ `oidcc-display-page`
- ✅ `oidcc-display-popup`
- ✅ `oidcc-userinfo-post-header`
- ✅ `oidcc-userinfo-post-body`
- ✅ `oidcc-ensure-request-with-unknown-parameter-succeeds`
- ✅ `oidcc-ensure-request-with-valid-pkce-succeeds`
- ✅ `oidcc-userinfo-get`
- ✅ `oidcc-response-type-missing`
- ✅ `oidcc-prompt-login`
- ✅ `oidcc-prompt-none-not-logged-in`
- ✅ `oidcc-prompt-none-logged-in`
- ✅ `oidcc-redirect-uri-regfrag`
- ✅ `oidcc-codereuse`
- ✅ `oidcc-codereuse-30seconds`
- ✅ `oidcc-ensure-registered-redirect-uri`
- ✅ `oidcc-registration-logo-uri`
- ✅ `oidcc-discovery-endpoint-verification`
- ✅ `oidcc-registration-policy-uri`
- ✅ `oidcc-registration-sector-uri`

- 🛠️ `oidcc-claims-locales`
- 🛠️ `oidcc-login-hint`
- 🛠️ `oidcc-registration-tos-uri`
- 🛠️ `oidcc-claims-essential`
- 🛠️ `oidcc-ensure-request-with-acr-values-succeeds`
- 🛠️ `oidcc-ui-locales`
- ❌ `oidcc-redirect-uri-query-OK`
- ❌ `oidcc-userinfo-rs256`
- ❌ `oidcc-refresh-token`
- ❌ `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported`
- ❌ `oidcc-request-uri-unsigned`
- ❌ `oidcc-request-uri-signed-rs256`
- ❌ `oidcc-server-rotate-keys`
- ❌ `oidcc-ensure-redirect-uri-in-authorization-request`
- ❌ `oidcc-id-token-hint`
- ❌ `oidcc-max-age-1`
- ❌ `oidcc-max-age-10000`
- ❌ `oidcc-ensure-request-object-with-redirect-uri`
- ❌ `oidcc-redirect-uri-query-mismatch`
- ❌ `oidcc-redirect-uri-query-added`
