# Password Reset Email Request
## Endpoint
```
POST /auth/reset-password
```
---
**Description:** This endpoint is used to for a user to request a link to reset their password.
### Headers
| Key             | Value                         |
|:----------------|-------------------------------|
| Content-Type    | application/json              | 
| Date            | Tue, 03 Dec 2024 19:38:16 GMT | 
| Content-Length  | 44                            | 
---
### Request Body
| Field      | Type    | Required  | Description                    |
| :----------|:--------|:----------|:-------------------------------|
| email      | string  | Yes          | The user's email address.     |
---
### Example Request
```json
{
    "email": "john.doe@mail.com",
}
```
---
## Responses
#### HTTP Status Code: `200 OK`
#### Response Body:
```json
{
    "message": "Password reset instructions have been sent to your email if an account exists."
}
```
#### Note: 
This response is returned even if the user does not exist to prevent user enumeration. The email sent to the user will contain a reset URL with a requestId query parameter containing the reset token.

#### Email Content:
The email will include a link with the format: [Base URL]?requestId=[Reset Token]. This link will redirect the user to a page where they can reset their password. The reset token will expire after a set period of time.

---
## Error Responses
### 1. Empty Base URL Configuration
#### HTTP Status Code: `400 Bad Request`
**Description:** Occurs when the server's base URL configuration is missing.
#### Response Body:
```json
{
    "error": "empty_field",
    "error_description": "Base URL cannot be empty",
}
```

### 2. Failed to Generate Reset Token
#### HTTP Status Code: `500 Internal Server Error`
**Description:** Occurs when there is an internal error generating the reset token.
#### Response Body:
```json
{
    "error": "internal_server_error",
    "error_description": "Failed to generate reset token"
}
```

### 3. Failed to Construct Reset URL
#### HTTP Status Code: `500 Internal Server Error`
**Description:** Occurs when there is an error constructing the password reset URL.
#### Response Body:
```json
{
    "error": "internal_server_error",
    "error_description": "Failed to construct reset URL"
}
```

### 4. Failed to Send Email
#### HTTP Status Code: `424 Failed Dependency`
**Description:** Occurs when there is an error sending the password reset email.
#### Response Body:
```json
{
    "error": "email_delivery_error",
    "error_description": "Failed to send email"
}
```

### 5. Empty Email Template
#### HTTP Status Code: `500 Internal Server Error`
**Description:** Occurs when the email template is missing.
#### Response Body:
```json
{
    "error": "empty_field",
    "error_description": "email template cannot be empty",
}
```

### 6. Template Rendering Error
#### HTTP Status Code: `500 Internal Server Error`
**Description:** Occurs when there is an error rendering the email template.
#### Response Body:
```json
{
    "error": "template_rendering_error",
    "error_description": "Failed to render the email template"
}
```

### 7. Invalid Template Format
#### HTTP Status Code: `422 Unprocessable Entity`
**Description:** Occurs when the email template file is invalid or cannot be parsed.
#### Response Body:
```json
{
    "error": "invalid_format",
    "error_description": "failed to parse email template: <error message>",
}
```

### 8. Failed to Parse Default Email Template
#### HTTP Status Code: `500 Internal Server Error`
**Description:** Occurs when there is an error parsing the default email template in the system.
#### Response Body:
```json
{
    "error": "internal_server_error",
    "error_description": "Failed to parse default email template"
}
```

---
### Notes:
- The `200 OK` response is consistent whether the user exists or not, to prevent user enumeration.
- Error messages may include additional details within the `description` field.
- The `field` field indicates which input caused the error, where applicable.
