import { FormEvent, useEffect, useRef, useState } from "react";
import type {
  AIAnalysisReport,
  AuthMode,
  Route,
  SessionState,
  StatusMessage,
  UploadListItem,
  UploadResults,
  UploadStatus,
} from "./types";
import { apiFetch, MAX_UPLOAD_SIZE } from "./lib/api";
import { navigateTo, parseRoute } from "./lib/routing";
import { normalizeResults } from "./lib/format";
import { AuthPage } from "./components/AuthPage";
import { UploadPage } from "./components/UploadPage";
import { HistoryPage } from "./components/HistoryPage";
import { StatusPage } from "./components/StatusPage";
import { ResultsPage } from "./components/ResultsPage";

export default function App() {
  const [route, setRoute] = useState<Route>(() => parseRoute(window.location.pathname));
  const [sessionState, setSessionState] = useState<SessionState>("checking");
  const [userEmail, setUserEmail] = useState("");
  const [authMode, setAuthMode] = useState<AuthMode>("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [statusMessage, setStatusMessage] = useState<StatusMessage | null>(null);
  const [pendingAction, setPendingAction] = useState<string | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadStatus, setUploadStatus] = useState<UploadStatus | null>(null);
  const [uploadResults, setUploadResults] = useState<UploadResults | null>(null);
  const [aiAnalysis, setAIAnalysis] = useState<AIAnalysisReport | null>(null);
  const [aiAnalysisLoading, setAIAnalysisLoading] = useState(false);
  const [aiAnalysisError, setAIAnalysisError] = useState<string | null>(null);
  const [uploadHistory, setUploadHistory] = useState<UploadListItem[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyVersion, setHistoryVersion] = useState(0);

  // Keep a ref so the visibilitychange handler can read current sessionState without
  // re-registering the listener on every render.
  const sessionStateRef = useRef(sessionState);
  useEffect(() => {
    sessionStateRef.current = sessionState;
  }, [sessionState]);

  // ── popstate listener ──────────────────────────────────────────────────────
  useEffect(() => {
    const onPopState = () => setRoute(parseRoute(window.location.pathname));
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  // ── session:expired → force logout ────────────────────────────────────────
  useEffect(() => {
    const onExpired = () => {
      setSessionState("anonymous");
      setUserEmail("");
      setUploadHistory([]);
      setUploadResults(null);
      setUploadStatus(null);
      setAIAnalysis(null);
      setAIAnalysisError(null);
      navigateTo("/");
    };
    window.addEventListener("session:expired", onExpired);
    return () => window.removeEventListener("session:expired", onExpired);
  }, []);

  // ── initial session check (runs once on mount) ─────────────────────────────
  useEffect(() => {
    let cancelled = false;

    async function checkSession() {
      try {
        const me = await apiFetch<{ id: number; email: string }>("/me");
        if (cancelled) return;
        setUserEmail(me.email);
        setSessionState("authenticated");
        if (route.name === "auth") {
          navigateTo("/app");
        }
      } catch {
        if (cancelled) return;
        setSessionState("anonymous");
        if (route.name !== "auth") {
          navigateTo("/");
        }
      }
    }

    void checkSession();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ── tab-focus session refresh ─────────────────────────────────────────────
  // Re-extends the server-side session when the user returns to the tab.
  // 401 from the refresh call will fire session:expired and force logout.
  useEffect(() => {
    function onVisible() {
      if (document.visibilityState === "visible" && sessionStateRef.current === "authenticated") {
        apiFetch("/session/refresh", { method: "POST" }).catch(() => {
          // session:expired event is dispatched inside apiFetch on 401
        });
      }
    }
    document.addEventListener("visibilitychange", onVisible);
    return () => document.removeEventListener("visibilitychange", onVisible);
  }, []);

  // ── upload status polling ──────────────────────────────────────────────────
  useEffect(() => {
    if (sessionState !== "authenticated" || route.name !== "status") {
      return;
    }

    const uploadId = route.uploadId;
    let cancelled = false;
    let timer: number | undefined;

    async function pollStatus() {
      try {
        const currentStatus = await apiFetch<UploadStatus>(`/uploads/${uploadId}`);
        if (cancelled) return;
        setUploadStatus(currentStatus);
        if (currentStatus.status === "completed") {
          navigateTo(`/uploads/${uploadId}/results`);
          return;
        }
        if (currentStatus.status === "failed") {
          setStatusMessage({
            kind: "error",
            text: currentStatus.error_message || "Processing failed.",
          });
          return;
        }
        timer = window.setTimeout(pollStatus, 2000);
      } catch (error) {
        if (cancelled) return;
        setStatusMessage({
          kind: "error",
          text: error instanceof Error ? error.message : "Unable to check upload status.",
        });
      }
    }

    void pollStatus();
    return () => {
      cancelled = true;
      if (timer) window.clearTimeout(timer);
    };
  }, [route, sessionState]);

  // ── results loader ─────────────────────────────────────────────────────────
  useEffect(() => {
    if (sessionState !== "authenticated" || route.name !== "results") {
      return;
    }

    const uploadId = route.uploadId;
    let cancelled = false;

    async function loadResults() {
      try {
        const [status, results] = await Promise.all([
          apiFetch<UploadStatus>(`/uploads/${uploadId}`),
          apiFetch<UploadResults>(`/uploads/${uploadId}/results`),
        ]);
        if (cancelled) return;
        setUploadStatus(status);
        setUploadResults(normalizeResults(results));
        setAIAnalysis(null);
        setAIAnalysisError(null);
      } catch (error) {
        if (cancelled) return;
        if (error instanceof Error && error.message.includes("not completed")) {
          navigateTo(`/uploads/${uploadId}`);
          return;
        }
        setStatusMessage({
          kind: "error",
          text: error instanceof Error ? error.message : "Unable to load upload results.",
        });
      }
    }

    void loadResults();
    return () => {
      cancelled = true;
    };
  }, [route, sessionState]);

  // ── history loader ─────────────────────────────────────────────────────────
  useEffect(() => {
    if (sessionState !== "authenticated" || route.name !== "history") {
      return;
    }

    let cancelled = false;
    setHistoryLoading(true);

    apiFetch<UploadListItem[]>("/uploads")
      .then((items) => {
        if (!cancelled) setUploadHistory(items);
      })
      .catch(() => {
        // 401 handled via session:expired; other errors surface through status message
      })
      .finally(() => {
        if (!cancelled) setHistoryLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [route, sessionState, historyVersion]);

  // ── derived state ──────────────────────────────────────────────────────────
  const hasCredentials = email.trim() !== "" && password !== "";
  const statusToneClass = statusMessage ? `status ${statusMessage.kind}` : "status";
  const canSubmitUpload = selectedFile !== null && pendingAction !== "upload";

  // ── handlers ──────────────────────────────────────────────────────────────

  async function handleRegister(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!hasCredentials) {
      setStatusMessage({ kind: "error", text: "Enter your email and password." });
      return;
    }

    setPendingAction("register");
    setStatusMessage(null);
    try {
      const payload = await apiFetch<{ message: string }>("/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim(), password }),
      });
      setStatusMessage({ kind: "success", text: payload.message || "Registration successful." });
      setAuthMode("login");
    } catch (error) {
      setStatusMessage({
        kind: "error",
        text: error instanceof Error ? error.message : "Registration failed.",
      });
    } finally {
      setPendingAction(null);
    }
  }

  async function handleLogin() {
    if (!hasCredentials) {
      setStatusMessage({ kind: "error", text: "Enter your email and password." });
      return;
    }

    setPendingAction("login");
    setStatusMessage(null);
    try {
      await apiFetch("/login", {
        method: "POST",
        headers: {
          Authorization: `Basic ${window.btoa(`${email.trim()}:${password}`)}`,
        },
      });
      // Fetch identity so the email shows in the header right away.
      const me = await apiFetch<{ id: number; email: string }>("/me");
      setUserEmail(me.email);
      setSessionState("authenticated");
      setStatusMessage({ kind: "success", text: "Login successful." });
      navigateTo("/app");
    } catch (error) {
      setStatusMessage({
        kind: "error",
        text: error instanceof Error ? error.message : "Login failed.",
      });
    } finally {
      setPendingAction(null);
    }
  }

  async function handleLogout() {
    setPendingAction("logout");
    try {
      await apiFetch("/logout", { method: "POST" });
    } catch {
      // Always clear client state on logout regardless of server response.
    } finally {
      setPendingAction(null);
      setSessionState("anonymous");
      setUserEmail("");
      setUploadStatus(null);
      setUploadResults(null);
      setAIAnalysis(null);
      setAIAnalysisError(null);
      setSelectedFile(null);
      setUploadHistory([]);
      setStatusMessage({ kind: "info", text: "Session ended." });
      navigateTo("/");
    }
  }

  async function handleUpload(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedFile) {
      setStatusMessage({ kind: "error", text: "Choose a VPC flow-log file first." });
      return;
    }

    if (selectedFile.size > MAX_UPLOAD_SIZE) {
      setStatusMessage({ kind: "error", text: "File exceeds the 10 MB upload limit." });
      return;
    }

    setPendingAction("upload");
    setStatusMessage(null);
    try {
      const form = new FormData();
      form.append("file", selectedFile);
      form.append("log_type", "vpc_flow");
      const payload = await apiFetch<{ upload_id: number; status: string }>("/uploads", {
        method: "POST",
        body: form,
      });
      setUploadResults(null);
      setUploadStatus(null);
      setAIAnalysis(null);
      setAIAnalysisError(null);
      setSelectedFile(null);
      setStatusMessage({ kind: "success", text: "Upload accepted. Processing has started." });
      navigateTo(`/uploads/${payload.upload_id}`);
    } catch (error) {
      setStatusMessage({
        kind: "error",
        text: error instanceof Error ? error.message : "Upload failed.",
      });
    } finally {
      setPendingAction(null);
    }
  }

  async function handleAuthSubmit(event: FormEvent<HTMLFormElement>) {
    if (authMode === "register") {
      await handleRegister(event);
      return;
    }
    event.preventDefault();
    await handleLogin();
  }

  async function handleGenerateAIAnalysis() {
    if (!uploadResults) return;

    setAIAnalysisLoading(true);
    setAIAnalysisError(null);
    try {
      const report = await apiFetch<AIAnalysisReport>(
        `/uploads/${uploadResults.upload.id}/ai-analysis`,
        { method: "POST" },
      );
      setAIAnalysis(report);
    } catch (error) {
      setAIAnalysisError(
        error instanceof Error ? error.message : "Unable to generate AI analysis.",
      );
    } finally {
      setAIAnalysisLoading(false);
    }
  }

  // ── Root render ────────────────────────────────────────────────────────────

  if (sessionState === "checking") {
    return (
      <main className="page-shell">
        <section className="panel loading-card">
          <p className="eyebrow">Simple Flow Analyser</p>
          <h1>Checking session</h1>
          <p className="intro">Connecting the frontend to the upload pipeline.</p>
        </section>
      </main>
    );
  }

  const onLogout = () => {
    void handleLogout();
  };

  return (
    <main className="page-shell">
      {route.name === "auth" || sessionState === "anonymous" ? (
        <AuthPage
          authMode={authMode}
          setAuthMode={setAuthMode}
          email={email}
          setEmail={setEmail}
          password={password}
          setPassword={setPassword}
          pendingAction={pendingAction}
          onSubmit={handleAuthSubmit}
          onLogin={() => {
            void handleLogin();
          }}
        />
      ) : null}
      {route.name === "upload" && sessionState === "authenticated" ? (
        <UploadPage
          userEmail={userEmail}
          selectedFile={selectedFile}
          setSelectedFile={setSelectedFile}
          pendingAction={pendingAction}
          canSubmitUpload={canSubmitUpload}
          onUpload={handleUpload}
          onLogout={onLogout}
        />
      ) : null}
      {route.name === "history" && sessionState === "authenticated" ? (
        <HistoryPage
          userEmail={userEmail}
          uploadHistory={uploadHistory}
          historyLoading={historyLoading}
          pendingAction={pendingAction}
          onRefresh={() => setHistoryVersion((v) => v + 1)}
          onLogout={onLogout}
        />
      ) : null}
      {route.name === "status" && sessionState === "authenticated" ? (
        <StatusPage uploadStatus={uploadStatus} uploadId={route.uploadId} />
      ) : null}
      {route.name === "results" && sessionState === "authenticated" ? (
        <ResultsPage
          uploadResults={uploadResults}
          aiAnalysis={aiAnalysis}
          aiAnalysisLoading={aiAnalysisLoading}
          aiAnalysisError={aiAnalysisError}
          onGenerateAIAnalysis={() => {
            void handleGenerateAIAnalysis();
          }}
          onLogout={onLogout}
        />
      ) : null}

      {statusMessage ? (
        <div className={statusToneClass} role="status">
          {statusMessage.text}
        </div>
      ) : null}
    </main>
  );
}
