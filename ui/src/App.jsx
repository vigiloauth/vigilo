import React from "react";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import AuthenticationForm from "./forms/AuthenticationForm";
import "./index.css";
import ConsentForm from "./forms/ConsentForm";

function App() {
  return (
    <BrowserRouter>
      <div className="App">
        <Routes>
          <Route path="/authenticate" element={<AuthenticationForm />} />
          <Route path="/consent" element={<ConsentForm />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}

export default App;
