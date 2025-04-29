# JWKS Endpoint

## Endpoint
```http
GET /oauth2/.well-known/jwks.json
```

## Headers
| Key             | Value                         | Description                               |
| :-------------- | :---------------------------- | :---------------------------------------- |
| Content-Type    | application/json              | Indicates that the request body is JSON.  |
| Date            | Tue, 03 Dec 2024 19:38:16 GMT | The date and time the request was made.   |
| Content-Length  | [Content-Length]              | The length of the request body in bytes.  |

---

## Example Request
```http
GET /oauth2/.well-known/jwks.json HTTP/1.1
```

## Responses

#### HTTP Status Code: `200 OK`
#### Response Body:
```json
{
    "keys": [
        {
            "kty": "RSA",
            "kid": "abc123",
            "use": "sig",
            "alg": "RS256",
            "n": "modulus-base64url",
            "e": "exponent-base64url"
        }
    ]
}
```