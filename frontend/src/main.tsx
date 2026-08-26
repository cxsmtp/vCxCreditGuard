import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { App } from "./App";
import "./index.css";
import { ThemeProvider, ToastProvider, applyTheme, readInitialTheme } from "./lib/ui-context";

// Applied before the first render, which is the earliest point available without
// an inline script. The strict CSP forbids inline scripts, and there is no
// server rendered markup to flash, so this is the right place for it.
applyTheme(readInitialTheme());

const container = document.getElementById("root");
if (!container) {
  throw new Error("The #root element is missing from index.html");
}

createRoot(container).render(
  <StrictMode>
    <ThemeProvider>
      <ToastProvider>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </ToastProvider>
    </ThemeProvider>
  </StrictMode>,
);
