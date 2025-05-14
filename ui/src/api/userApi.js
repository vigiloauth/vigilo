import URL_PARAMS from "../constants/urlParams";
import ENDPOINT from "../constants/endpoints";

export async function authenticateUser({
  username,
  password,
  clientID,
  redirectURI,
  state,
  scope,
  responseType,
  nonce,
  display,
}) {
  const urlParams = new URLSearchParams();
  urlParams.set(URL_PARAMS.CLIENT_ID, clientID);
  urlParams.set(URL_PARAMS.REDIRECT_URI, redirectURI);

  if (state !== "") urlParams.set(URL_PARAMS.STATE, state);
  if (scope !== "") urlParams.set(URL_PARAMS.SCOPE, scope);
  if (responseType !== "")
    urlParams.set(URL_PARAMS.RESPONSE_TYPE, responseType);
  if (nonce !== "") urlParams.set(URL_PARAMS.NONCE, nonce);
  if (display !== "") urlParams.set(URL_PARAMS.DISPLAY, display);

  const endpoint = `${ENDPOINT.USER_AUTH}?${urlParams.toString()}`;

  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({ username, password }),
    credentials: "include",
  });

  const data = await response.json();
  if (!response.ok) {
    let errorMessage = "Something went wrong";
    switch (response.status) {
      case 401:
        errorMessage =
          "Your username or password are incorrect. Please try again.";
      case 400:
        errorMessage =
          "Your username or password are incorrect. Please try again.";
        break;
      default:
        errorMessage = "Something went wrong. Please try again later.";
        break;
    }

    throw new Error(errorMessage);
  }

  return data;
}

export async function handleUserConsent({
  clientID,
  redirectURI,
  scope,
  responseType,
  state,
  nonce,
  display,
  approved,
  scopes,
  method = "POST",
}) {
  const urlParams = new URLSearchParams();
  urlParams.set(URL_PARAMS.CLIENT_ID, clientID);
  urlParams.set(URL_PARAMS.REDIRECT_URI, redirectURI);

  if (state !== "") urlParams.set(URL_PARAMS.STATE, state);
  if (scope !== "") urlParams.set(URL_PARAMS.SCOPE, scope);
  if (responseType !== "")
    urlParams.set(URL_PARAMS.RESPONSE_TYPE, responseType);
  if (nonce !== "") urlParams.set(URL_PARAMS.NONCE, nonce);
  if (display !== "") urlParams.set(URL_PARAMS.DISPLAY, display);

  const endpoint = `${ENDPOINT.USER_CONSENT}?${urlParams.toString()}`;

  const fetchOptions = {
    method,
    headers: {
      Accept: "application/json",
    },
    credentials: "include",
  };

  if (method === "POST") {
    fetchOptions.headers["Content-Type"] = "application/json";
    fetchOptions.body = JSON.stringify({ approved, scopes });
  }

  const response = await fetch(endpoint, fetchOptions);
  if (!response.ok) {
    let errorMessage = "Something went wrong";
    switch (response.statue) {
      case 401:
        errorMessage = "Invalid credentials";
        break;
      default:
        errorMessage = "Something went wrong. Please try again later.";
        break;
    }
    throw new Error(errorMessage);
  }

  return await response.json();
}
