import URL from "../constants/urlParams";
import ENDPOINT from "../constants/endpoints";

export async function authenticateUser(
  username,
  password,
  clientID,
  redirectURI,
  state,
  scope,
  responseType,
  nonce,
  display,
) {
  const urlParams = new URLSearchParams();
  urlParams.set(URL.CLIENT_ID, clientID);
  urlParams.set(URL.REDIRECT_URI, redirectURI);

  if (state.length !== 0) urlParams.set(URL.STATE, state);
  if (scope.length !== 0) urlParams.set(URL.SCOPE, scope);
  if (responseType.length !== 0) urlParams.set(URL.RESPONSE_TYPE, responseType);
  if (nonce.length !== 0) urlParams.set(URL.NONCE, nonce);
  if (display.length !== 0) urlParams.set(URL.DISPLAY, display);

  const endpoint = `${ENDPOINT.USER_AUTH}?${urlParams.toString()}`;

  try {
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
    console.log("data:", data);

    if (!response.ok) {
      let errorMessage = "Something went wrong";

      switch (response.status) {
        case (401, 400):
          errorMessage =
            "Your username or password are incorrect. Please try again.";
          break;
        case 404:
          errorMessage =
            "API endpoint not found. Please check the configuration.";
          break;
        case 500:
          errorMessage = "Something went wrong. Please try again later.";
          break;
        default:
          errorMessage = "Something went wrong. Please try again later.";
          break;
      }

      throw new Error(errorMessage);
    }

    return data;
  } catch (fetchError) {
    if (
      fetchError.name === "TypeError" &&
      (fetchError.message.includes("Failed to fetch") ||
        fetchError.message.includes("NetworkError") ||
        fetchError.message.includes("Network request failed"))
    ) {
      throw new Error("Something went wrong. Please try again later.");
    }

    if (
      fetchError.name === "SyntaxError" &&
      (fetchError.message.includes("Unexpected token") ||
        fetchError.message.includes("<!DOCTYPE") ||
        fetchError.message.includes("<html"))
    ) {
      throw new Error("Something went wrong. Please try again later.");
    }

    throw fetchError;
  }
}

export async function postConsent(
  clientID,
  redirectURI,
  scope,
  responseType,
  state,
  nonce,
  display,
  approved,
  approvedScopes,
) {
  const urlParams = new URLSearchParams();
  urlParams.set(URL.CLIENT_ID, clientID);
  urlParams.set(URL.REDIRECT_URI, redirectURI);

  if (state.length !== 0) urlParams.set(URL.STATE, state);
  if (scope.length !== 0) urlParams.set(URL.SCOPE, scope);
  if (responseType.length !== 0) urlParams.set(URL.RESPONSE_TYPE, responseType);
  if (nonce.length !== 0) urlParams.set(URL.NONCE, nonce);
  if (display.length !== 0) urlParams.set(URL.DISPLAY, display);

  const endpoint = `${ENDPOINT.USER_CONSENT}?${urlParams.toString()}`;
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ approved, approvedScopes }),
      credentials: "include",
    });

    if (!response.ok) {
      let errorMessage = "Something went wrong";
      switch (response.statue) {
        case 401:
          errorMessage = "Invalid credentials";
          break;
      }

      throw new Error(errorMessage);
    }

    return await response.json();
  } catch (fetchError) {
    throw new Error("Something went wrong. Please try again later.");
  }
}
