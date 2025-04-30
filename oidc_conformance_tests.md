# OpenID Connect Conformance Tests Checklist

## Setup
1. Clone the repo: `git clone git@gitlab.com:openid/conformance-suite.git`
2. Install maven and docker.
3. Ensure you are using Java version 11 (any 11.0 version is fine).
4. Build the Java code using: `mvn clean package`.
5. Start the docker container using: `docker-compose up`. For development, use `-f docker-compose-dev.yml` or `docker-compose-dev-mac.yml`.
6. The UI will be available at `http://localhost:8443/`

You can visit OpenID's official [GitLab](https://gitlab.com/openid/conformance-suite/-/wikis/Developers/Build-&-Run) for more information on how to properly setup the conformance suite.

## Basic Configuration Tests
- ❌ Verify Discovery endpoint (/.well-known/openid-configuration)
- ❌ Validate JSON Web Key Set (JWKS) endpoint
- ❌ Check HTTPS for all endpoints
- ❌ Verify proper CORS headers on relevant endpoints
- ❌ Validate issuer identifier consistency

## Authentication Tests
- ❌ Test authorization code flow
- ❌ Test implicit flow
- ❌ Test hybrid flow
- ❌ Verify PKCE (Proof Key for Code Exchange) support
- ❌ Test client authentication methods (client_secret_basic, client_secret_post, client_secret_jwt, private_key_jwt)
- ❌ Validate request parameter support
- ❌ Test request_uri parameter support
- ❌ Verify prompt=none behavior
- ❌ Test prompt=login behavior
- ❌ Test max_age parameter
- ❌ Validate login_hint parameter
- ❌ Test id_token_hint parameter

## Token Endpoint Tests
- ❌ Verify token endpoint accepts valid authorization codes
- ❌ Test token endpoint rejects expired authorization codes
- ❌ Verify token endpoint rejects reused authorization codes
- ❌ Test refresh token issuance
- ❌ Validate refresh token usage
- ❌ Test token revocation endpoint
- ❌ Verify correct error responses for invalid requests

## ID Token Tests
- ❌ Validate ID token signature
- ❌ Verify required claims (iss, sub, aud, exp, iat)
- ❌ Test ID token with nonce
- ❌ Verify at_hash when access token is returned
- ❌ Validate c_hash when code is returned
- ❌ Test ID token expiration
- ❌ Verify ID token audience matches client ID
- ❌ Validate sub (subject) claim consistency across sessions

## UserInfo Endpoint Tests
- ❌ Test UserInfo endpoint with valid access token
- ❌ Verify UserInfo endpoint rejects invalid access tokens
- ❌ Validate UserInfo response claims
- ❌ Test UserInfo signed responses (if supported)
- ❌ Verify UserInfo encrypted responses (if supported)
- ❌ Test scope-restricted UserInfo responses

## Dynamic Client Registration Tests
- ❌ Verify basic client registration without authentication
- ❌ Test client registration with initial access token
- ❌ Validate client registration with software statement
- ❌ Test registration of all supported grant types
- ❌ Verify registration of all supported response types
- ❌ Test registration with redirect URIs
- ❌ Validate registration with different token endpoint auth methods
- ❌ Test registration with JWKS
- ❌ Verify registration with JWKS URI
- ❌ Test registration with sector identifier URI
- ❌ Validate subject type registration (pairwise vs public)
- ❌ Test registration with default ACR values
- ❌ Verify client metadata validation
- ❌ Test error responses for invalid registration requests
- ❌ Validate issued client_id format
- ❌ Test issued client_secret (if applicable)
- ❌ Verify client update endpoint (PUT/PATCH operations)
- ❌ Test client delete endpoint
- ❌ Validate client configuration endpoint (GET operation)
- ❌ Test registration access token usage and validation

## OAuth 2.0 Compatibility Tests
- ❌ Verify client credentials flow
- ❌ Test resource owner password credentials flow (if supported)
- ❌ Validate client registration endpoint (if supported)
- ❌ Test token introspection endpoint
- ❌ Verify token revocation endpoint

## Security Tests
- ❌ Test cross-site request forgery (CSRF) protection
- ❌ Verify state parameter validation
- ❌ Test redirect URI validation
- ❌ Validate response_type parameter
- ❌ Verify correct handling of unsupported response types
- ❌ Test session management (if supported)
- ❌ Validate front-channel logout (if supported)
- ❌ Test back-channel logout (if supported)
- ❌ Verify JWT signature validation
- ❌ Test JWT encryption (if supported)

## Advanced Features Tests
- ❌ Test aggregated claims (if supported)
- ❌ Verify distributed claims (if supported)
- ❌ Test pairwise subject identifiers (if supported)
- ❌ Validate request object encryption (if supported)
- ❌ Test authenticated requests to UserInfo endpoint
- ❌ Verify sector identifier URI validation (if supported)
- ❌ Test different subject types (public vs. pairwise)

## Conformance Profiles Tests
- ❌ Validate Basic OP conformance profile
- ❌ Test Implicit OP conformance profile
- ❌ Verify Hybrid OP conformance profile
- ❌ Test Config OP conformance profile
- ❌ Validate Dynamic OP conformance profile
- ❌ Test Form Post OP conformance profile