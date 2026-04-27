import { FormEvent, useState } from "react";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8080";

type StatusMessage = {
  kind: "success" | "error";
  text: string;
};

async function parseResponse(response: Response) {
  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    return response.json() as Promise<{ message?: string }>;
  }

  return { message: await response.text() };
}

export default function App() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [status, setStatus] = useState<StatusMessage | null>(null);
  const [pendingAction, setPendingAction] = useState<"register" | "login" | null>(null);

  const hasCredentials = username.trim() !== "" && password !== "";

  async function handleRegister(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!hasCredentials) {
      setStatus({ kind: "error", text: "Enter a username and password." });
      return;
    }

    setPendingAction("register");
    setStatus(null);

    try {
      const response = await fetch(`${API_BASE_URL}/register`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          username: username.trim(),
          password
        })
      });

      const payload = await parseResponse(response);
      if (!response.ok) {
        throw new Error(payload.message ?? "Registration failed.");
      }

      setStatus({
        kind: "success",
        text: payload.message ?? "User registered successfully."
      });
    } catch (error) {
      setStatus({
        kind: "error",
        text: error instanceof Error ? error.message : "Registration failed."
      });
    } finally {
      setPendingAction(null);
    }
  }

  async function handleLogin() {
    if (!hasCredentials) {
      setStatus({ kind: "error", text: "Enter a username and password." });
      return;
    }

    setPendingAction("login");
    setStatus(null);

    try {
      const encodedCredentials = window.btoa(`${username.trim()}:${password}`);
      const response = await fetch(`${API_BASE_URL}/login`, {
        method: "POST",
        headers: {
          Authorization: `Basic ${encodedCredentials}`
        }
      });

      const payload = await parseResponse(response);
      if (!response.ok) {
        throw new Error(payload.message ?? "Login failed.");
      }

      setStatus({
        kind: "success",
        text: payload.message ?? "Login successful."
      });
    } catch (error) {
      setStatus({
        kind: "error",
        text: error instanceof Error ? error.message : "Login failed."
      });
    } finally {
      setPendingAction(null);
    }
  }

  return (
    <main className="page-shell">
      <section className="auth-panel">
        <p className="eyebrow">Simple Log Analyser</p>
        <h1>Basic Auth Access</h1>
        <p className="intro">
          Register a user first, then log in with the same credentials.
        </p>

        <form className="auth-form" onSubmit={handleRegister}>
          <label className="field">
            <span>User name</span>
            <input
              autoComplete="username"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              placeholder="Enter username"
            />
          </label>

          <label className="field">
            <span>Password</span>
            <input
              autoComplete="current-password"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="Enter password"
            />
          </label>

          <div className="actions">
            <button type="submit" disabled={pendingAction !== null}>
              {pendingAction === "register" ? "Registering..." : "Register"}
            </button>
            <button
              type="button"
              className="secondary"
              disabled={pendingAction !== null}
              onClick={handleLogin}
            >
              {pendingAction === "login" ? "Logging in..." : "Login"}
            </button>
          </div>
        </form>

        {status ? (
          <p className={`status ${status.kind}`} role="status">
            {status.text}
          </p>
        ) : null}
      </section>
    </main>
  );
}
