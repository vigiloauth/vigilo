# Client Delete Request

## Endpoint
```http
DELETE /oauth2/client/register/{client_id}
```

--- 

**Description:**
This endpoint is a protected route which is responsible for deleting the current client configuration. The client makes an `HTTP DELETE` request to the client configuration endpoint, authenticating with its `registration_access_token`. Both the `registration_access_token` and the `client_configuration_endpoint` are generated during the dynamic client registration flow. Please view the Client Registration [endpoint](client_registration.md) for more information on how to properly generate a client.

Upon deletion, the `client_id`, `client_secret` (if applicable), and the `registration_access_token` are immediately revoked, thereby preventing the `client_id` from being used at the authorization endpoint or the token exchange endpoint.

---

## Required Headers
| Key             | Value                              | Description                                                                          |
| :-------------- | :----------------------------      | :------------------------------------------------------------------------------------|
| Authorization   | Bearer <registration_access_token> | The registration access token received in the response after registering the client. |

---

## URL Parameters
| Parameter            | Type          | Required | Description                                                                |
| :--------------------| :-------------| :--------| :--------------------------------------------------------------------------|
| `client_id`            | `string`        | Yes      | The unique identifier of the OAuth client.                                 |

---

## Example Request
```http
DELETE /oauth/client/register/s6BhdRkqt3 HTTP/1.1
Host: server.example.com
Authorization: Bearer reg-23410913-abewfq.123483
```

---

## Responses

### Success Response
#### HTTP Status Code: `204 No Content`
#### Response Headers
```http
HTTP/1.1 204 No Content
Cache-Control: no-store
Pragma: no-cache
```

---

## Error Responses
**Note:** The `registration_access_token` will immediately be revoked before returning the error responses.

### 1. Token Subject and Client ID Mismatch
#### HTTP Status Code: `401 Unauthorized`
#### Response Body
```json
{
    "error": "unauthorized",
    "error_description": "failed to validate and retrieve client information",
    "error_details": "the registration access token subject does not match with the client ID in the request"
}
```

### 2. Invalid Client ID
#### HTTP Status Code: `401 Unauthorized`
#### Response Body:
```json
{
    "error": "unauthorized",
    "error_description": "failed to validate and retrieve client information",
    "error_details": "the provided client ID is invalid or does not match the registered credentials"
}
```

### 3. Expired Registration Access Token
#### HTTP Status Code: `401 Unauthorized`
#### Response Body
```json
{
    "error": "token_expired",
    "error_description": "an error occurred validating the access token",
    "error_details": "the token is expired"
}
```
