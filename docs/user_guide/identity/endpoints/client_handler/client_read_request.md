# Client Read Request

## Endpoint
```http
GET /identity/oauth2/clients/register/{client_id}
```
---

**Description:**
This endpoint is a protected route which is responsible for retrieving the current client configuration. The client makes an `HTTP GET` request to the client configuration endpoint, authenticating with its `registration_access_token`. Both the `registration_access_token` and the `client_configuration_endpoint` are generated during the dynamic client registration flow. Please view the Client Registration [endpoint](client_registration.md) for more information on how to properly generate a client.

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
GET /identity/oauth2/clients/register/s6BhdRkqt3 HTTP/1.1
Accept: application/json
Authorization: Bearer reg-23410913-abewfq.123483
```

---

## Responses

### Success Response
#### HTTP Status Code: `200 OK`
#### Response Body:
```json
{
    "client_id": "s6BhdRkqt3",
    "registration_client_uri": "/client/register",
    "registration_access_token": "reg-23410913-abewfq.123483",
}
```
>**Note:** If the request is for a confidential client, the `client_secret` will be included in the response.

---

## Error Responses
**Note:** The `registration_access_token` will immediately be revoked before returning the error responses.

### 1. Invalid Client ID
#### HTTP Status Code: `401 Unauthorized`
#### Response Body:
```json
{
    "error": "unauthorized",
    "error_description": "failed to validate and retrieve client information",
    "error_details": "the provided client ID is invalid or does not match the registered credentials"
}
```

### 2. Token Subject and Client ID Mismatch
#### HTTP Status Code: `401 Unauthorized`
#### Response Body:
```json
{
    "error": "unauthorized",
    "error_description": "failed to validate and retrieve client information",
    "error_details": "the registration access token subject does not match with the client ID in the request"
}
```

### 3. Insufficient Scope
#### HTTP Status Code: `403 Forbidden`
#### Response Body:
```json
{
    "error": "insufficient_scope",
    "error_description": "failed to validate and update client",
    "error_details": "client does not have the required scopes for this request"
}
```

### 4. Expired Registration Access Token
#### HTTP Status Code: `401 Unauthorized`
#### Response Body
```json
{
    "error": "token_expired",
    "error_description": "an error occurred validating the access token",
    "error_details": "the token is expired"
}


