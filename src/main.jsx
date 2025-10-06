import React from "react";
 import ReactDOM from "react-dom/client";
 import App from "./App.jsx";
 import "./index.css";
import { Authenticator } from "@aws-amplify/ui-react";
import { BrowserRouter } from 'react-router-dom';
 ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
   <Authenticator>
    <BrowserRouter>
      <App />
    </BrowserRouter>
   </Authenticator>
  </React.StrictMode>
 );