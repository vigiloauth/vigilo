# Authorize Client

## Endpoint
```http
GET /identity/oauth2/authorize
```

---

**Description:**  
This endpoint is used to handle the authorization request in the OAuth 2.0 Authorization Code Flow. It validates the client's authorization request, checks the user session and consent, and redirects to the appropriate URL.

---

## Notes for Developers
- Ensure the `redirect_uri` matches the one registered with the client.
- Scopes should be space-separated strings.
- The `state` parameter is optional but recommended to prevent CSRF attacks.
- PKCE (Proof Key for Code Exchange) is an additional security mechanism for public clients (e.g., mobile or single-page applications) to prevent authorization code interception attacks.
- If the client is using PKCE, the `code_verifier` must be sent during the [token exchange](token_exchange.md) to validate the `code_challenge`.
- Confidential clients (e.g., server-side applications) are not required to use PKCE but may still use it for additional security
- When using PKCE, the client must create the `code_challenge` by either using the `code_verifier` itself, or encrypting it using `SHA-256`

#### Code Challenge Requirements
```
code-challenge = 43*128unreserved
unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
ALPHA = %x41-5A / %x61-7A
DIGIT = %x30-39
```

#### Code Verifier Requirements
```
code-challenge = 43*128unreserved
unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
ALPHA = %x41-5A / %x61-7A
DIGIT = %x30-39
```

---

## Query Parameters
| Parameter            | Type          | Required | Description                                                                 |
| :--------------------| :-------------| :--------| :--------------------------------------------------------------------------|
| `client_id`          | `string`      | Yes      | The unique identifier of the OAuth client.                                 |
| `redirect_uri`       | `string`      | Yes      | The URI to redirect to after authorization. Must match the registered URI. |
| `scope`              | `string`      | Yes      | The requested access scope(s), space-separated.                            |
| `approved`           | `boolean`     | Yes      | Indicates whether the user has approved the authorization request.         |
| `state`              | `string`      | No       | An opaque value used to maintain state between the request and callback. This helps prevent CSRF attacks. |
| `response_type`      | `string`      | Yes      | The client's response type.                                                |
| `code_challenge`     | `string`      | No       | The PKCE code challenge. Required if the client is using PKCE.             |
| `code_challenge_method` | `string`   | No       | The method used to generate the code challenge. Supported values are `plain` and `S256`. Defaults to `plain`. |
| `nonce` | `string` | No | String value used to associate a Client session with an ID token, and to mitigate replay attacks. Required if `id_token` is returned directly from the Authorization Endpoint (not applicable for pure `response_type=code`). |
| `display`| `string` | No | String value to determine the type of login page will be displayed if the user is not authenticated. Valid displays are `page`, `popup`, `touch`, and `wap`. |

---

## Required Headers
| Key    | Value                   | Description                   |
| :----- | :-----------------------| :-----------------------------|
| Cookie | session=<session_token> | Active user session cookie.   |

---

## Authorization Flow
1. The client initiates an authorization request with the required parameters.
2. If the client is using PKCE:
   - The client must include the `code_challenge` and optionally the `code_challenge_method` in the request.
   - If `code_challenge_method` is not provided, it defaults to `plain`.
3. The server checks if a valid user session exists.
4. If no session exists, the server returns a login required error with a login URL.
5. If the session exists, the server processes the user's consent to the authorization request.
6. If the request is valid, the server generates an authorization code. If PKCE is used, the server associates the `code_challenge` and `code_challenge_method` with the authorization code.
7. The server redirects to the specified `redirect_uri` with the authorization code or an error.


----

## Example Request
```http
GET /identity/oauth2/authorize HTTP/1.1
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
Content-Type: application/x-www-form-urlencoded

client_id=abc123&
redirect_uri=https://client.example.com/callback&
scope=users:manage&
approved=true&
state=xyz&
response_type=code
```

#### Example Request using PKCE
```http
GET /oauth/authorize HTTP/1.1
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
Content-Type: application/x-www-form-urlencoded

client_id=abc123&
redirect_uri=https://client.example.com/callback&
scope=users:manage&
approved=true&
state=xyz&
response_type=code&
code_challenge=1234abc8902zz&
code_challenge_method=S256
```

---

## Responses

### Success Response
#### HTTP Status Code: `302 Found`
- Redirects to the client's `redirect_uri` with an authorization code.
- Includes the authorization `code` as a request parameter.
- Includes the optional `state` parameter if provided in the original request.

```http
HTTP/1.1 302 Found
Location: https://client.example.com/callback?code=SplxlOBeZQQNuYZt&state=af0ifjsldkj
```

---

## Error Responses
Errors occurring at the Authorization Endpoint are returned to the client by redirecting the user agent back to the client's registered `redirect_uri`. The error details are included as query parameters in the redirect URL.

#### HTTP Status Code: `302 Found`
- Redirects the user agent to the client's `redirect_uri`.
- Includes the `error` parameter as a query parameter.
- Includes the `error_description` parameter as a query parameter.
- Includes the original `state` parameters as a query parameter if it was provided in the original request.

| Error Code (`error`)     | Description (`error_description`)               | Notes                            |
|:-------------------------|:------------------------------------------------|:---------------------------------|
| `invalid_request`        | The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. | This includes missing `client_id`, `redirect_uri`, `response_type` or `scope` (if `openid` is missing and no other scopes are request), or invalid values for these parameters. |
| `unauthorized_client` | The client is not authorized to request an authorization code using this method. | E.g., Client ID is unknown, client is not registered for this grant type, or a public client is not using PKCE when required. |
| `access_denied` | The resource owner or authorization server denied the request. | This typically occurs when the user denies consent. |