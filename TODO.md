## 🔹1. Update Client Registration
- [x] Include a `registration_access_token` in the response 
- [x] Store token in the database
- [x] Ensure the token has an expiration time.
- [x] Construct the `client_configuration_endpoint`: `BASE_URL + /register/{client_id}`
- [x] Include the token, and the endpoint in the response.
- [x] Ensure response format follows [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591)
- [x] Include `client_id_issued_at` in the response.
---

## 🔹 2. Client Read Endpoint (Self-Access) → `GET /register/{client_id}`
- [x] **Protected Route**: Requires `registration_access_token`
- [x] Create a route `GET /register/{client_id}`
- [x] Extract `client_id` from the request URL
- [x] Validate the **registration access token** (ensures only the client itself can access its details)
- [x] Fetch client details from the database
- [x] Return client metadata in JSON format
- [x] Ensure response format follows [RFC 7592](https://www.rfc-editor.org/rfc/rfc7592.html#section-3) 
- [x] Returns `200 OK` if successful.
- [x] Return an error as described in [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) for an invalid `registration_access_token`
- [x] Return a `401 Unauthorized` if the client does not exist, and revoke the `registration_access_token`
- [x] Integration test
- [x] DOCS

---

## 🔹 3. Client Update Endpoint → `PUT /register/{client_id}`
- [x] **Protected Route**: Requires `registration_access_token`
- [x] Create a route `PUT /register/{client_id}`
- [x] Extract `client_id` from the request URL
- [x] Validate the **registration access token** (ensures only the client itself can modify its data)
- [x] Parse and validate the request body
- [x] Ensure `client_id` and `client_secret` **cannot be modified**
- [x] Update allowed fields (`client_name`, `redirect_uris`, `grant_types`, etc.)
- [x] Save updated client data to the database
- [x] Return the updated client metadata
- [x] The request must include JSON containing `client_id`, `client_secret`, `redirect_uris`, `grant_types`, and can include any other metadata.
- [x] Returns `200 OK` if successful.
- [x] Return an error as described in [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) for an invalid `registration_access_token`
- [x] Return a `401 Unauthorized` if the client does not exist, and revoke the `registration_access_token`
- [x] Ensure response format follows [RFC 7592](https://www.rfc-editor.org/rfc/rfc7592.html#section-3) 
- [x] Return a `403 Forbidden` if the client is not allowed to update its records.
- [x] Integration test
- [x] DOCS

---

## 🔹 4. Client Delete Endpoint → `DELETE /register/{client_id}`
- [x] **Protected Route**: Requires `registration_access_token`
- [x] Create a route `DELETE /register/{client_id}`
- [x] Extract `client_id` from the request URL
- [x] Validate the **registration access token** (ensures only the client itself can delete its data)
- [x] Delete the client record from the database
- [x] Invalidate the `client_id`
- [x] Invalidate the `client_secret`
- [x] Invalidate the `registration_access_token`
- [x] Return `204 No Content` on success
- [x] Integration test
- [ ] DOCS

---

## 🔹 5. Registration Access Token Handling
- [x] Generate a **secure** `registration_access_token` on client creation
- [x] Store the token securely in the database with the client record
- [x] Require the token for `GET`, `PUT`, and `DELETE` requests
- [x] Validate the token on incoming requests
- [x] Implement proper token expiration or revocation mechanisms
- [x] Return an error as described in [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) for an invalid `registration_access_token`
- [x] Return a `403 Forbidden` error if the client cannot delete itself.
- [x] If the client does not exist, respond with `401 Unauthorized` and revoke the token immediately.
- [x] Integration tests
- [x] Docs

---

## 🔹 6. Documentation
- [x] Client Registration
- [x] Client Read (Self-Access)
- [x] Client Update 
- [x] Client Delete
- [ ] Create docs explaining the dynamic client configuration flow.
    - [ ] Include the valid grant types
    - [ ] Include the valid scopes
    - [ ] Include the valid response types
- [ ] Implement worker pool for go routines
- [ ] Logging configuration
- [ ] E2E tests for Authorization Code Flow.
- [ ] Refactor OAuth Login
- [ ] Refactor Oauth UserConsent
---