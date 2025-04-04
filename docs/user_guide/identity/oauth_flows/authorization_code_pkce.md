# OAuth 2.0 Authorization Code Flow with PKCE

## 1. What is PKCE?
PKCE (Proof Key for Code Exchange) is an extension to the OAuth 2.0 Authorization Code Flow that enhances security for public clients (e.g., mobile apps, SPAs). It prevents authorization code interception attacks by requiring the client to prove it initiated the authorization request.

---

## 2. How PKCE Works
![Authorization code flow with PKCE](../oauth_flows/images/authz_code_flow_pkce.png)

**1. Generate a Code Verifier**:
   - The client generates a random, high-entropy string called the `code_verifier`.

**2. Create a Code Challenge**:
   - The client hashes the `code_verifier` using SHA-256 (or uses the `plain` method) and Base64 URL-encodes the result to create the `code_challenge`.

**3. Send the Code Challenge**:
   - During the authorization request, the client sends the `code_challenge` and optionally the `code_challenge_method` (default is `plain`).

**4. Validate the Code Verifier**:
   - During the token exchange, the client sends the `code_verifier`.
   - VigiloAuth hashes the `code_verifier` (if `S256` is used) and compares it to the `code_challenge` stored during the authorization request.

---

## 3. Example Flow
### Authorization Request
```http
GET /oauth/authorize HTTP/1.1
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
Content-Type: application/x-www-form-urlencoded

client_id=abc123&
redirect_uri=https://client.example.com/callback&
scope=user:profile&
approved=true&
state=xyz&
response_type=code&
code_challenge=1234abc8902zz&
code_challenge_method=S256
```
---

### Token Exchange
```http
POST /oauth/token HTTP/1.1
Content-Type: application/json
```
```json
{
    "grant_type": "authorization_code",
    "code": "SplxlOBeZQQYbYS6WxSbIA",
    "redirect_uri": "https://client.example.com/callback",
    "client_id": "s6BhdRkqt3",
    "state": "xyz123",
    "code_verifier": "xyz456"
}
```

---

## 4. Supported Code Challenge Methods
- `plain`: The `code_verifier` is sent as-is.
- `S256`: The `code_verifier` is encrypted using SHA-256.

---

## 5. Security Benefits
- Prevents authorization code interception attacks.
- Eliminates the need for a `client_secret`. Allowing public clients to use the Authorization Code Flow.