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
- 🛠️ OIDC Basic Certification Plan
    - ✅ `oidcc-server`
    - ✅ `oidcc-response-type-missing`
    - ✅ `oidcc-idtoken-signature`
    - ✅ `oidcc-idtoken-unsigned` (skipped, VigiloAuth does not support `none` as a token signing algorithm)
    - ❌ `oidcc-userinfo-get`
    - ✅ `oidcc-userinfo-post-header`
    - ✅ `oidcc-ensure-request-without-nonce-succeeds-for-code-flow`
    - ✅ `oidcc-scope-profile`
    - ✅ `oidcc-scope-email`
    - ✅ `oidcc-scope-address`
    - ✅ `oidcc-scope-phone`
    - ✅ `oidcc-scope-all`