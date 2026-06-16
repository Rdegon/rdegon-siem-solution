import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import "./styles.css";

const root = ReactDOM.createRoot(document.getElementById("root")!);

function renderBootstrapFallback(title: string, message: string) {
  const errorId = `UI-${Date.now().toString(36).slice(-6).toUpperCase()}`;
  root.render(
    <div className="react-bootstrap-error">
      <div className="react-bootstrap-error-card">
        <div className="react-top-kicker">Rdegon Sentinel</div>
        <h1>{title}</h1>
        <p>{message}</p>
        <div className="react-inline-note">Error id: {errorId}</div>
        <div className="react-actions react-wrap">
          <a className="react-link-button" href="/auth/login">Login</a>
          <a className="react-link-button" href="/app/dashboards">Open /app/dashboards</a>
        </div>
      </div>
    </div>,
  );
}

window.addEventListener("error", (event) => {
  const message = String(event.error?.message || event.message || "Unknown frontend error");
  console.error("window.onerror", event.error || event.message);
  renderBootstrapFallback("React shell runtime error", message);
});

window.addEventListener("unhandledrejection", (event) => {
  const reason = event.reason as Error | string | undefined;
  const message = String((reason as Error)?.message || reason || "Unhandled promise rejection");
  console.error("unhandledrejection", event.reason);
  renderBootstrapFallback("React shell promise error", message);
});

renderBootstrapFallback("Loading Rdegon Sentinel", "Preparing instrument-grade React shell...");

import("./shell/App")
  .then(({ App }) => {
    root.render(
      <BrowserRouter basename="/app">
        <App />
      </BrowserRouter>,
    );
  })
  .catch((error) => {
    console.error("bootstrap import failed", error);
    renderBootstrapFallback("Unable to load React shell", String(error?.message || error || "Unknown import error"));
  });
