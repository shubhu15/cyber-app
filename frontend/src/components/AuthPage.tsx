import { FormEvent } from "react";
import type { AuthMode } from "../types";

export function AuthPage(props: {
  authMode: AuthMode;
  setAuthMode: (mode: AuthMode) => void;
  email: string;
  setEmail: (value: string) => void;
  password: string;
  setPassword: (value: string) => void;
  pendingAction: string | null;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  onLogin: () => void;
}) {
  return (
    <section className="shell">
      <div className="hero-copy">
        <p className="eyebrow">Simple Flow Analyser</p>
        <h1>Upload VPC Flow Logs, then review the network signal.</h1>
        <p className="intro">
          Sign in once, upload an AWS VPC Flow Log file, and let the worker turn raw flow rows
          into findings, charts, and a concise analyst summary.
        </p>
      </div>

      <section className="panel auth-card">
        <div className="segmented">
          <button
            className={props.authMode === "login" ? "active" : ""}
            type="button"
            onClick={() => props.setAuthMode("login")}
          >
            Login
          </button>
          <button
            className={props.authMode === "register" ? "active" : ""}
            type="button"
            onClick={() => props.setAuthMode("register")}
          >
            Register
          </button>
        </div>

        <form className="stack-form" onSubmit={props.onSubmit}>
          <label className="field">
            <span>Email</span>
            <input
              autoComplete="email"
              value={props.email}
              onChange={(event) => props.setEmail(event.target.value)}
              placeholder="analyst@example.com"
            />
          </label>

          <label className="field">
            <span>Password</span>
            <input
              autoComplete={props.authMode === "login" ? "current-password" : "new-password"}
              type="password"
              value={props.password}
              onChange={(event) => props.setPassword(event.target.value)}
              placeholder="Enter password"
            />
          </label>

          <div className="actions">
            {props.authMode === "register" ? (
              <button type="submit" disabled={props.pendingAction !== null}>
                {props.pendingAction === "register" ? "Registering..." : "Create account"}
              </button>
            ) : (
              <button
                type="button"
                disabled={props.pendingAction !== null}
                onClick={() => props.onLogin()}
              >
                {props.pendingAction === "login" ? "Logging in..." : "Login"}
              </button>
            )}
          </div>
        </form>
      </section>
    </section>
  );
}
