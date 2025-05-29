import { BrowserRouter, Routes, Route } from "react-router-dom";
import "./index.css";
import AuthenticationPage from "./pages/AuthenticationPage";
import ConsentPage from "./pages/ConsentPage";
import { ApplicationContextProvider } from "./context/ApplicationContext";
import URL_PARAMS from "./constants/urlParams";
import ErrorPage from "./pages/ErrorPage";

function App() {
  const queryParams = new URLSearchParams(window.location.search);
  const display = queryParams.get(URL_PARAMS.DISPLAY);
  const errorType = queryParams.get(URL_PARAMS.TYPE);

  return (
    <BrowserRouter>
      <ApplicationContextProvider>
        <div className="App">
          <Routes>
            <Route
              path="/authenticate"
              element={<AuthenticationPage display={display} />}
            />
            <Route
              path="/consent"
              element={<ConsentPage display={display} />}
            />
            <Route
              path="/error"
              element={<ErrorPage errorType={errorType} />}
            />
          </Routes>
        </div>
      </ApplicationContextProvider>
    </BrowserRouter>
  );
}

export default App;
