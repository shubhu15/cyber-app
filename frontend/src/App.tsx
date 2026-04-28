import { FormEvent, useEffect, useMemo, useState } from "react";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8080";
const MAX_UPLOAD_SIZE = 10 * 1024 * 1024;

type StatusMessage = {
  kind: "success" | "error" | "info";
  text: string;
};

type SessionState = "checking" | "anonymous" | "authenticated";
type AuthMode = "login" | "register";

type UploadStatus = {
  id: number;
  log_type: string;
  file_name: string;
  status: "pending" | "processing" | "completed" | "failed";
  created_at: string;
  started_at?: string;
  finished_at?: string;
  error_message?: string;
  total_lines: number;
  parsed_lines: number;
  progress_percentage: number;
};

type Finding = {
  type: string;
  severity: string;
  title: string;
  description: string;
  first_seen_at?: string;
  last_seen_at?: string;
  count: number;
  metadata: Record<string, unknown>;
};

type TimelineEntry = {
  timestamp: string;
  type: string;
  severity: string;
  title: string;
  description: string;
  src_addr?: string;
  dst_port?: number;
  count?: number;
};

type ChartPoint = {
  label: string;
  count: number;
};

type BurstWindow = {
  bucket: string;
  count: number;
};

type ChartData = {
  action_counts: ChartPoint[];
  top_src_ips: ChartPoint[];
  top_dst_ports: ChartPoint[];
  top_rejected_src_ips: ChartPoint[];
  top_interfaces: ChartPoint[];
  burst_windows: BurstWindow[];
};

type EventRecord = {
  id: number;
  version: number;
  account_id?: string;
  interface_id?: string;
  src_addr?: string;
  dst_addr?: string;
  src_port?: number;
  dst_port?: number;
  protocol?: number;
  protocol_label: string;
  packets?: number;
  bytes?: number;
  start_time?: string;
  end_time?: string;
  action?: string;
  log_status: string;
  raw_line: string;
};

type UploadResults = {
  upload: UploadStatus;
  summary: {
    total_records: number;
    accepted_count: number;
    rejected_count: number;
    parse_errors: number;
    ai_summary: string;
  };
  findings: Finding[];
  timeline: TimelineEntry[];
  charts: ChartData;
  events: EventRecord[];
};

const EMPTY_CHARTS: ChartData = {
  action_counts: [],
  top_src_ips: [],
  top_dst_ports: [],
  top_rejected_src_ips: [],
  top_interfaces: [],
  burst_windows: []
};

type Route =
  | { name: "auth" }
  | { name: "upload" }
  | { name: "status"; uploadId: number }
  | { name: "results"; uploadId: number };

function parseRoute(pathname: string): Route {
  if (pathname === "/app" || pathname === "/upload") {
    return { name: "upload" };
  }

  const resultsMatch = pathname.match(/^\/uploads\/(\d+)\/results\/?$/);
  if (resultsMatch) {
    return { name: "results", uploadId: Number(resultsMatch[1]) };
  }

  const uploadMatch = pathname.match(/^\/uploads\/(\d+)\/?$/);
  if (uploadMatch) {
    return { name: "status", uploadId: Number(uploadMatch[1]) };
  }

  return { name: "auth" };
}

async function parseResponse<T>(response: Response): Promise<T | { message?: string }> {
  const contentType = response.headers.get("content-type") ?? "";
  if (response.status === 204) {
    return {};
  }
  if (contentType.includes("application/json")) {
    return response.json() as Promise<T | { message?: string }>;
  }
  return { message: await response.text() };
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    credentials: "include",
    ...init
  });

  const payload = await parseResponse<T>(response);
  if (!response.ok) {
    const message =
      payload && typeof payload === "object" && "message" in payload
        ? String(payload.message ?? "Request failed.")
        : "Request failed.";
    throw new Error(message);
  }

  return payload as T;
}

function navigateTo(path: string) {
  window.history.pushState({}, "", path);
  window.dispatchEvent(new PopStateEvent("popstate"));
}

function ChartBars(props: { title: string; items: ChartPoint[] }) {
  const max = props.items.reduce((highest, item) => Math.max(highest, item.count), 1);
  return (
    <section className="panel">
      <div className="panel-header">
        <h3>{props.title}</h3>
      </div>
      <div className="bar-list">
        {props.items.length === 0 ? <p className="muted">No data yet.</p> : null}
        {props.items.map((item) => (
          <div className="bar-row" key={`${props.title}-${item.label}`}>
            <div className="bar-label">
              <span>{item.label}</span>
              <strong>{item.count}</strong>
            </div>
            <div className="bar-track">
              <div className="bar-fill" style={{ width: `${Math.max((item.count / max) * 100, 6)}%` }} />
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

function normalizeResults(results: UploadResults): UploadResults {
  return {
    ...results,
    findings: results.findings ?? [],
    timeline: results.timeline ?? [],
    charts: {
      action_counts: results.charts?.action_counts ?? [],
      top_src_ips: results.charts?.top_src_ips ?? [],
      top_dst_ports: results.charts?.top_dst_ports ?? [],
      top_rejected_src_ips: results.charts?.top_rejected_src_ips ?? [],
      top_interfaces: results.charts?.top_interfaces ?? [],
      burst_windows: results.charts?.burst_windows ?? []
    },
    events: results.events ?? []
  };
}

function formatOptionalDate(value?: string) {
  return value ? new Date(value).toLocaleString() : "-";
}

function formatOptionalNumber(value?: number) {
  return value === undefined ? "-" : String(value);
}

export default function App() {
  const [route, setRoute] = useState<Route>(() => parseRoute(window.location.pathname));
  const [sessionState, setSessionState] = useState<SessionState>("checking");
  const [authMode, setAuthMode] = useState<AuthMode>("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [statusMessage, setStatusMessage] = useState<StatusMessage | null>(null);
  const [pendingAction, setPendingAction] = useState<string | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadStatus, setUploadStatus] = useState<UploadStatus | null>(null);
  const [uploadResults, setUploadResults] = useState<UploadResults | null>(null);

  useEffect(() => {
    const onPopState = () => setRoute(parseRoute(window.location.pathname));
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function checkSession() {
      try {
        await apiFetch<UploadStatus[]>("/uploads");
        if (cancelled) {
          return;
        }
        setSessionState("authenticated");
        if (route.name === "auth") {
          navigateTo("/app");
        }
      } catch {
        if (cancelled) {
          return;
        }
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
  }, []);

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
        if (cancelled) {
          return;
        }
        setUploadStatus(currentStatus);
        if (currentStatus.status === "completed") {
          navigateTo(`/uploads/${uploadId}/results`);
          return;
        }
        if (currentStatus.status === "failed") {
          setStatusMessage({
            kind: "error",
            text: currentStatus.error_message || "Processing failed."
          });
          return;
        }
        timer = window.setTimeout(pollStatus, 2000);
      } catch (error) {
        if (cancelled) {
          return;
        }
        setStatusMessage({
          kind: "error",
          text: error instanceof Error ? error.message : "Unable to check upload status."
        });
      }
    }

    void pollStatus();
    return () => {
      cancelled = true;
      if (timer) {
        window.clearTimeout(timer);
      }
    };
  }, [route, sessionState]);

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
          apiFetch<UploadResults>(`/uploads/${uploadId}/results`)
        ]);
        if (cancelled) {
          return;
        }
        setUploadStatus(status);
        setUploadResults(normalizeResults(results));
      } catch (error) {
        if (cancelled) {
          return;
        }
        if (error instanceof Error && error.message.includes("not completed")) {
          navigateTo(`/uploads/${uploadId}`);
          return;
        }
        setStatusMessage({
          kind: "error",
          text: error instanceof Error ? error.message : "Unable to load upload results."
        });
      }
    }

    void loadResults();
    return () => {
      cancelled = true;
    };
  }, [route, sessionState]);

  const hasCredentials = email.trim() !== "" && password !== "";
  const statusToneClass = statusMessage ? `status ${statusMessage.kind}` : "status";
  const canSubmitUpload = selectedFile !== null && pendingAction !== "upload";

  const resultMetrics = useMemo(() => {
    if (!uploadResults) {
      return [];
    }
    return [
      { label: "Total records", value: uploadResults.summary.total_records },
      { label: "Accepted", value: uploadResults.summary.accepted_count },
      { label: "Rejected", value: uploadResults.summary.rejected_count },
      { label: "Parse errors", value: uploadResults.summary.parse_errors }
    ];
  }, [uploadResults]);

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
        body: JSON.stringify({ email: email.trim(), password })
      });
      setStatusMessage({ kind: "success", text: payload.message || "Registration successful." });
      setAuthMode("login");
    } catch (error) {
      setStatusMessage({
        kind: "error",
        text: error instanceof Error ? error.message : "Registration failed."
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
          Authorization: `Basic ${window.btoa(`${email.trim()}:${password}`)}`
        }
      });
      setSessionState("authenticated");
      setStatusMessage({ kind: "success", text: "Login successful." });
      navigateTo("/app");
    } catch (error) {
      setStatusMessage({
        kind: "error",
        text: error instanceof Error ? error.message : "Login failed."
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
      // Ignore logout errors and clear client state anyway.
    } finally {
      setPendingAction(null);
      setSessionState("anonymous");
      setUploadStatus(null);
      setUploadResults(null);
      setSelectedFile(null);
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
        body: form
      });
      setUploadResults(null);
      setUploadStatus(null);
      setSelectedFile(null);
      setStatusMessage({ kind: "success", text: "Upload accepted. Processing has started." });
      navigateTo(`/uploads/${payload.upload_id}`);
    } catch (error) {
      setStatusMessage({
        kind: "error",
        text: error instanceof Error ? error.message : "Upload failed."
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

  function renderAuthPage() {
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
              className={authMode === "login" ? "active" : ""}
              type="button"
              onClick={() => setAuthMode("login")}
            >
              Login
            </button>
            <button
              className={authMode === "register" ? "active" : ""}
              type="button"
              onClick={() => setAuthMode("register")}
            >
              Register
            </button>
          </div>

          <form className="stack-form" onSubmit={handleAuthSubmit}>
            <label className="field">
              <span>Email</span>
              <input
                autoComplete="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                placeholder="analyst@example.com"
              />
            </label>

            <label className="field">
              <span>Password</span>
              <input
                autoComplete={authMode === "login" ? "current-password" : "new-password"}
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="Enter password"
              />
            </label>

            <div className="actions">
              {authMode === "register" ? (
                <button type="submit" disabled={pendingAction !== null}>
                  {pendingAction === "register" ? "Registering..." : "Create account"}
                </button>
              ) : (
                <button
                  type="button"
                  disabled={pendingAction !== null}
                  onClick={() => {
                    void handleLogin();
                  }}
                >
                  {pendingAction === "login" ? "Logging in..." : "Login"}
                </button>
              )}
            </div>
          </form>
        </section>
      </section>
    );
  }

  function renderUploadPage() {
    return (
      <section className="workspace">
        <header className="page-header">
          <div>
            <p className="eyebrow">Simple Flow Analyser</p>
            <h1>Upload VPC Flow Logs</h1>
            <p className="intro">
              The API stores your file immediately, then the worker parses it asynchronously and
              builds a network-triage view over the resulting flow records.
            </p>
          </div>
          <button className="ghost-button" type="button" onClick={() => void handleLogout()}>
            {pendingAction === "logout" ? "Signing out..." : "Logout"}
          </button>
        </header>

        <section className="panel">
          <div className="panel-header">
            <h2>New upload</h2>
            <span className="chip">vpc_flow</span>
          </div>
          <form className="stack-form" onSubmit={handleUpload}>
            <label className="upload-dropzone">
              <input
                type="file"
                accept=".log,.txt,text/plain"
                onChange={(event) => setSelectedFile(event.target.files?.[0] ?? null)}
              />
              <span>{selectedFile ? selectedFile.name : "Choose a flow-log file to analyse"}</span>
              <small>{selectedFile ? `${Math.round(selectedFile.size / 1024)} KB selected` : "10 MB max"}</small>
            </label>
            <div className="actions">
              <button type="submit" disabled={!canSubmitUpload}>
                {pendingAction === "upload" ? "Uploading..." : "Start processing"}
              </button>
            </div>
          </form>
        </section>
      </section>
    );
  }

  function renderStatusPage() {
    return (
      <section className="workspace">
        <header className="page-header">
          <div>
            <p className="eyebrow">Processing upload</p>
            <h1>{uploadStatus?.file_name || `Upload #${route.name === "status" ? route.uploadId : ""}`}</h1>
            <p className="intro">
              The worker is reading the flow-log file, parsing records, and building the summary.
            </p>
          </div>
          <button className="ghost-button" type="button" onClick={() => navigateTo("/app")}>
            Back to upload
          </button>
        </header>

        <section className="status-grid">
          <article className="panel stat-card">
            <span>Status</span>
            <strong>{uploadStatus?.status || "pending"}</strong>
          </article>
          <article className="panel stat-card">
            <span>Progress</span>
            <strong>{uploadStatus ? `${uploadStatus.progress_percentage}%` : "0%"}</strong>
          </article>
          <article className="panel stat-card">
            <span>Parsed rows</span>
            <strong>
              {uploadStatus ? `${uploadStatus.parsed_lines}/${uploadStatus.total_lines || 0}` : "0/0"}
            </strong>
          </article>
        </section>

        <section className="panel">
          <div className="panel-header">
            <h2>Worker progress</h2>
          </div>
          <div className="progress-strip">
            <div className={`progress-state ${uploadStatus?.status === "pending" ? "active" : "done"}`}>
              Pending
            </div>
            <div
              className={`progress-state ${
                uploadStatus?.status === "processing"
                  ? "active"
                  : uploadStatus?.status === "completed"
                    ? "done"
                    : ""
              }`}
            >
              Processing
            </div>
            <div className={`progress-state ${uploadStatus?.status === "completed" ? "done" : ""}`}>Results</div>
          </div>
          <p className="muted">
            The page polls every two seconds and moves to the results screen as soon as processing
            completes.
          </p>
        </section>
      </section>
    );
  }

  function renderResultsPage() {
    if (!uploadResults) {
      return (
        <section className="workspace">
          <section className="panel loading-card wide-card">
            <p className="eyebrow">Analysis results</p>
            <h1>Loading results</h1>
            <p className="intro">Fetching flow records, findings, charts, and summary data.</p>
          </section>
        </section>
      );
    }

    const charts = uploadResults.charts ?? EMPTY_CHARTS;

    return (
      <section className="workspace">
        <header className="page-header">
          <div>
            <p className="eyebrow">Analysis results</p>
            <h1>{uploadResults.upload.file_name || "Completed upload"}</h1>
            <p className="intro">{uploadResults.summary.ai_summary}</p>
          </div>
          <div className="header-actions">
            <button className="ghost-button" type="button" onClick={() => navigateTo("/app")}>
              Upload another
            </button>
            <button className="ghost-button" type="button" onClick={() => void handleLogout()}>
              Logout
            </button>
          </div>
        </header>

        <section className="status-grid">
          {resultMetrics.map((metric) => (
            <article className="panel stat-card" key={metric.label}>
              <span>{metric.label}</span>
              <strong>{metric.value}</strong>
            </article>
          ))}
        </section>

        <section className="results-layout">
          <section className="panel">
            <div className="panel-header">
              <h2>Top findings</h2>
            </div>
            <div className="finding-list">
              {uploadResults.findings.length ? null : <p className="muted">No notable findings were generated.</p>}
              {uploadResults.findings.map((finding) => (
                <article className={`finding-card severity-${finding.severity}`} key={`${finding.type}-${finding.title}`}>
                  <div className="finding-topline">
                    <span className="chip">{finding.severity}</span>
                    <strong>{finding.count}</strong>
                  </div>
                  <h3>{finding.title}</h3>
                  <p>{finding.description}</p>
                </article>
              ))}
            </div>
          </section>

          <section className="panel">
            <div className="panel-header">
              <h2>Timeline</h2>
            </div>
            <div className="timeline-list">
              {uploadResults.timeline.length ? null : <p className="muted">No notable timeline entries were generated.</p>}
              {uploadResults.timeline.map((item, index) => (
                <article className="timeline-item" key={`${item.timestamp}-${item.type}-${index}`}>
                  <div className="timeline-meta">
                    <span>{item.timestamp ? new Date(item.timestamp).toLocaleString() : "No timestamp"}</span>
                    <span>{item.type}</span>
                  </div>
                  <strong>{item.title}</strong>
                  <p>{item.description}</p>
                </article>
              ))}
            </div>
          </section>
        </section>

        <section className="chart-grid">
          <ChartBars title="Accept vs reject" items={charts.action_counts} />
          <ChartBars title="Top source IPs" items={charts.top_src_ips} />
          <ChartBars title="Top destination ports" items={charts.top_dst_ports} />
          <ChartBars title="Top rejected sources" items={charts.top_rejected_src_ips} />
          <ChartBars title="Top interfaces" items={charts.top_interfaces} />
          <section className="panel">
            <div className="panel-header">
              <h3>Burst windows</h3>
            </div>
            <div className="bar-list">
              {charts.burst_windows.length ? null : <p className="muted">No burst windows were detected.</p>}
              {charts.burst_windows.map((burst) => (
                <div className="bar-row" key={burst.bucket}>
                  <div className="bar-label">
                    <span>{new Date(burst.bucket).toLocaleString()}</span>
                    <strong>{burst.count}</strong>
                  </div>
                  <div className="bar-track">
                    <div className="bar-fill" style={{ width: `${Math.min(burst.count * 12, 100)}%` }} />
                  </div>
                </div>
              ))}
            </div>
          </section>
        </section>

        <section className="panel">
          <div className="panel-header">
            <h2>Parsed flow records</h2>
            <span className="chip">{uploadResults.events.length} rows</span>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Start</th>
                  <th>End</th>
                  <th>Source</th>
                  <th>Src port</th>
                  <th>Destination</th>
                  <th>Dst port</th>
                  <th>Protocol</th>
                  <th>Action</th>
                  <th>Packets</th>
                  <th>Bytes</th>
                  <th>Interface</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {uploadResults.events.map((event) => (
                  <tr key={event.id}>
                    <td>{formatOptionalDate(event.start_time)}</td>
                    <td>{formatOptionalDate(event.end_time)}</td>
                    <td>{event.src_addr || "-"}</td>
                    <td>{formatOptionalNumber(event.src_port)}</td>
                    <td>{event.dst_addr || "-"}</td>
                    <td>{formatOptionalNumber(event.dst_port)}</td>
                    <td>{event.protocol_label}</td>
                    <td>{event.action || "-"}</td>
                    <td>{formatOptionalNumber(event.packets)}</td>
                    <td>{formatOptionalNumber(event.bytes)}</td>
                    <td>{event.interface_id || "-"}</td>
                    <td>{event.log_status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </section>
    );
  }

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

  return (
    <main className="page-shell">
      {route.name === "auth" || sessionState === "anonymous" ? renderAuthPage() : null}
      {route.name === "upload" && sessionState === "authenticated" ? renderUploadPage() : null}
      {route.name === "status" && sessionState === "authenticated" ? renderStatusPage() : null}
      {route.name === "results" && sessionState === "authenticated" ? renderResultsPage() : null}

      {statusMessage ? (
        <div className={statusToneClass} role="status">
          {statusMessage.text}
        </div>
      ) : null}
    </main>
  );
}
