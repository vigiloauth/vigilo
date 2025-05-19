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
- ✅ `oidcc-ui-locales`
- ✅ `oidcc-claims-locales`
- ✅ `oidcc-server-client-secret-post`
- ✅ `oidcc-ensure-request-object-with-redirect-uri`
- ✅ `oidcc-refresh-token`
- ✅ `oidcc-max-age-1` 
- ✅ `oidcc-max-age-10000` 

- 🛠️ `oidcc-claims-essential` (name not found in response)

- 🛠️ `oidcc-id-token-hint`
- 🛠️ `oidcc-login-hint`
- 🛠️ `oidcc-ensure-request-with-acr-values-succeeds` (An acr value was requested using acr_values, so the server 'SHOULD' return an acr claim, but it did not.)

- ❌ `oidcc-ensure-post-request-succeeds` (currently does not support post for client authorization)
- ❌ `oidcc-request-uri-unsigned-supported-correctly-or-rejected-as-unsupported` (Nonce values mismatch and no state is returned)
- ❌ `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported` (Nonce values mismatch, no state is returned, and 'request_parameter_supported' should be 'true', but is absent and the default value is 'false'.)


TODO 
pass requested claims through to UI
    - authenticate
    - consent