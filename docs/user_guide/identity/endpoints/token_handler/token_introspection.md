# OAuth 2.0 Token Introspection

## Endpoint
```http
POST /oauth/token/introspect

```

---

## Request Headers

---

## Request Body

---

## Example Request

---

## Responses

### Success Response
#### HTTP Status Code: `200 OK`
#### Response Body:
```json
{
    "active": true,
    "exp": "1744310667",
    "iat": "1744310067",
    "subject": "client-id",
    "iss": "vigilo-auth-server",
    "jti": "1FF3ZcYmriDTmziexguayay90HCgHJYR2UUGNcEwvC0"
}
```

### Success Response
#### HTTP Status Code: `200 OK`
#### Response Body:
```json
{
    "active": false,
}
```

*Note:* If the token in the request is valid, but is either expired, or has been previously revoked, `active` will be set to false.

---

## Error Responses