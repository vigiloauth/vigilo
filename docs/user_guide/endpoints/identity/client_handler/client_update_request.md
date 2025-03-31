# Client Update Request

## Endpoint
```
PUT /oauth/client/register/{client_id}
```

**Description:**
This endpoint is a protected route which is responsible for updating the current client configuration. The client makes an `HTTP PUT` request to the client configuration endpoint with the required request body, authenticating with its `registration_access_token`. Both the `registration_access_token` and the `client_configuration_endpoint` are generated during the dynamic client registration flow. Please view the Client Registration [endpoint](client_registration.md) for more information on how to properly generate a client. Valid values of client metadata fields in this request **MUST** replace, not augment, the values previously associated with the client. The `client_secret` is immutable once assigned. If a new secret is required, the client must re-register through the Client Registration [endpoint](client_registration.md), or regenerate their secret through the Client Secret Regeneration [endpoint](client_secret_regeneration.md).

---

## Required Headers
| Key             | Value                              | Description                                                                          |
| :-------------- | :----------------------------      | :------------------------------------------------------------------------------------|
| Authorization   | Bearer <registration_access_token> | The registration access token received in the response after registering the client. |

---

## URL Parameters
| Parameter            | Type          | Required | Description                                                                |
| :--------------------| :-------------| :--------| :--------------------------------------------------------------------------|
| client_id            | string        | Yes      | The unique identifier of the OAuth client.                                 |

---

## Request Body
| Field                | Type          | Required | Description                                                                |
| :--------------------| :-------------| :--------| :--------------------------------------------------------------------------|
| client_id            | string        | Yes      | The ID of the client application being updated.                         |
| client_secret        | string        | No       | The secret of the client application being updated.                         |
| client_name          | string        | No       | The name of the client application being updated.                        |
| redirect_uris        | string array  | No       | A list of URIs to which the authorization server will redirect the user after successful authorization. Public clients must use HTTPS. |
| grant_types          | string array  | No       | The grant types associated with the client. Supported values: `authorization_code`, `client_credentials`, `password`, `refresh_token`, `implicit`, `device_code`. |
| scopes               | string array  | No       | The scopes associated with the client. Supported values: `client:read`, `client:write`, `client:delete`, `client:manage`.  |
| response_types       | string array  | No       | The response types associated with the client. Supported values: `code`, `token`, `id_token`. |
| token_auth_endpoint  | string        | No       | The token authentication endpoint for the client credentials flow. Required for `client_credentials` grant type. |

---

## Example Request
```
PUT /oauth/client/register/s6BhdRkqt3 HTTP/1.1
Accept: application/json
Host: server.example.com
Authorization: Bearer reg-23410913-abewfq.123483
```
```json
{
    "client_id": "s6BhdRkqt3",
    "client_name": "My New Name",
    "redirect_uris": [
        "https://client.example.org/callback",
        "https://client.example.org/alt"
    ],
    "grant_types": ["authorization_code", "refresh_token"],
    "scopes": ["client:read", "client:delete"]
}
```

___

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
**Note:** If the request is for a confidential client, the `client_secret` will be included in the response.

___

## Error Responses
**Note:** The `registration_access_token` will immediately be revoked before returning the error responses.

### 1. Missing Required Fields in Request Body
#### HTTP Status Code: `400 Bad Request`
#### Response Body
```json
{
    "error": "bad_request",
    "error_description": "missing one or more required fields in the request"
}
```

### 2. Invalid Redirect URIs
#### HTTP Status Code: `400 Bad Request`
#### Response Body
```json
{
    "error": "validation_error",
    "error_description": "failed to update client",
    "error_details": "one or more validation errors occurred",
    "errors": [
        {
            "error": "invalid_redirect_uri",
            "error_description": "confidential clients must use HTTPS"
        },
        {
            "error": "invalid_redirect_uri",
            "error_description": "redirect URIs cannot have wildcards"
        }
    ]
}
```

### 3. Invalid Response Types
#### HTTP Status Code: `400 Bad Request`
#### Response Body
```json
{
    "error": "validation_error",
    "error_description": "failed to update client",
    "error_details": "one or more validation errors occurred",
    "errors": [
        {
            "error": "invalid_response_type",
			"error_description": "response types are not allowed for the client credentials, password grant, or refresh token grant types"
        },
	]
}
```
**Note:**
Certain grant types require specific response types. If these are missing, the response types are invalid:
- `authorization_code` or `device_code`: Must include `code`.
- `implicit_flow`: Must include `token`.
- `PKCE` must include `code`.

Some grant types do not allow any response types:
- `client_credentials`
- `password_grant`
- `refresh_token`

The `id_token` response type is not allowed with the following grant types:
- `authorization_code`
- `device_code`
- `implicit_flow`

### 4. Registration Access Token Subject and Client ID Mismatch
#### HTTP Status Code: `401 Unauthorized`
#### Response Body
```json
{
    "error": "unauthorized",
    "error_description": "failed to update client",
    "error_details": "the registration access token subject does not match with the client ID in the request"
}
```

### 5. Expired Registration Access Token
#### HTTP Status Code: `401 Unauthorized`
#### Response Body
```json
{
    "error": "token_expired",
    "error_description": "an error occurred validating the access token",
    "error_details": "the token is expired"
}
```

### 6. Invalid Client ID
#### HTTP Status Code: `401 Unauthorized`
#### Response Body
```json
{
    "error": "unauthorized",
    "error_description": "failed to update client",
    "error_details": "the provided client ID is invalid or does not match the registered credentials"
}
```

### 7. Client Secret Mismatch
#### HTTP Status Code: `401 Unauthorized`
#### Response Body
```json
{
    "error": "unauthorized",
    "error_description": "failed to update client",
    "error_details": "the provided client secret is invalid or does not match the registered credentials"
}
```

### 8. Insufficient Scopes
#### HTTP Status Code: `401 Unauthorized`
#### Response Body
```json
{
    "error": "insufficient_scope",
    "error_description": "failed to update client",
    "error_details": "client does not have the required scopes for this request"
}
```