# Verify Account

## Endpoint
```http
GET /identity/auth/verify
```

---

**Description:**
This endpoint is used when a new user needs to verify their email. During the registration process, the user will receive an email to verify their account.

---

## Query Parameters
| Parameter       | Type        | Required    | Description                                       |
:-----------------|:------------|:------------|:--------------------------------------------------|
| `token`         | `string`    | yes         | The verification code the user receives by email. |

---

## Example Request
```http
GET /identity/auth/verify HTTP/1.1
token=czZCaGRSa3F0MzpnWDFmQmF0M2JW
```

---

## Responses

### Success Response
#### HTTP Status Code: `200 OK`
>*Note:* There is no response body for successful validation.

---

## Error Responses

### 1. Missing Required Parameter
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
    "error": "invalid_request",
    "error_description": "failed to validate user account",
    "error_details": "missing one or more required parameters in the request"
}
```

### 2. Invalid Verification Code
#### HTTP Status Code: `401 Unauthorized`
#### Response Body:
```json
{
    "error": "unauthorized",
    "error_description": "failed to validate user account",
    "error_details": "the verification code is either expired or does not exist"
}
```

### 3. Verification Code does not match with the User
#### HTTP Status Code: `401 Unauthorized`
#### Response Body:
```json
{
    "error": "unauthorized",
    "error_description": "failed to validate user account",
    "error_details": "the verification code is invalid"
}
```
