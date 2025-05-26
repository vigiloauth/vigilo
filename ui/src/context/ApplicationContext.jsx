import { createContext, useContext, useState, useEffect } from "react";
import { getClientByID } from "../api/clientApi";

import URL_PARAMS from "../constants/urlParams";

const ApplicationContext = createContext(null);

export const ApplicationContextProvider = ({ children }) => {
  const queryParams = new URLSearchParams(window.location.search);

  const [queryValues, setQueryValues] = useState({
    clientID: queryParams.get(URL_PARAMS.CLIENT_ID),
    redirectURI: queryParams.get(URL_PARAMS.REDIRECT_URI),
    state: queryParams.get(URL_PARAMS.STATE) || "",
    scope: queryParams.get(URL_PARAMS.SCOPE) || "",
    responseType: queryParams.get(URL_PARAMS.RESPONSE_TYPE) || "",
    nonce: queryParams.get(URL_PARAMS.NONCE) || "",
    display: queryParams.get(URL_PARAMS.DISPLAY) || "",
    acrValues: queryParams.get(URL_PARAMS.ACR) || "",
    claims: queryParams.get(URL_PARAMS.CLAIMS) || "",
  });

  const [clientInfo, setClientInfo] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!queryValues.clientID) return;
    const fetchClientInfo = async () => {
      // try {
      //   setClientInfo({
      //     logo_uri: "https://www.certification.openid.net/images/openid.png",
      //     policy_uri: "https://www.certification.openid.net/login.html",
      //   });
      // } catch (err) {
      //   console.log(err);
      // } finally {
      //   setLoading(false);
      // }
      try {
        const data = await getClientByID({ clientID: queryValues.clientID });
        setClientInfo(data);
      } catch (err) {
        console.error("Error fetching client info:", err);
      } finally {
        setLoading(false);
      }
    };

    fetchClientInfo();
  }, [queryValues.clientID]);

  return (
    <ApplicationContext.Provider
      value={{ ...queryValues, clientInfo, loading }}
    >
      {children}
    </ApplicationContext.Provider>
  );
};

export const useApplicationContext = () => useContext(ApplicationContext);
