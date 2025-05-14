import ENDPOINT from "../constants/endpoints";

export async function getClientByID({ clientID }) {
  const endpoint = `${ENDPOINT.GET_CLIENT_BY_ID}/${clientID}`;
  try {
    const response = await fetch(endpoint, {
      method: "GET",
    });
    return await response.json();
  } catch (err) {
    throw new Error("Something went wrong retrieving the client's logo.");
  }
}
