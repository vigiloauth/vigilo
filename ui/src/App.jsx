import { BrowserRouter, Routes, Route } from "react-router-dom";
import "./index.css";
import ConsentPopup from "./popups/ConsentPopup";
import AuthenticationPage from "./pages/AuthenticationPage";
import ConsentPage from "./pages/ConsentPage";
import URL_PARAMS from "./constants/urlParams";

function App() {
  const queryParams = new URLSearchParams(window.location.search);
  const display = queryParams.get(URL_PARAMS.DISPLAY);

  return (
    <BrowserRouter>
      <div className="App">
        <Routes>
          <Route
            path="/authenticate"
            element={<AuthenticationPage display={display} />}
          />
          <Route path="/consent" element={<ConsentPage display={display} />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}

export default App;
