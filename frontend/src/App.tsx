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

type FindingInstance = {
  description: string;
  first_seen_at?: string;
  last_seen_at?: string;
  count: number;
  metadata: Record<string, unknown>;
};

type FindingGroup = {
  type: string;
  severity: string;
  title: string;
  instance_count: number;
  total_count: number;
  instances: FindingInstance[];
};

type SeverityBucket = {
  severity: string;
  groups: FindingGroup[];
};

type TimelineEntry = {
  type: string;
  severity: string;
  title: string;
  first_seen_at: string;
  last_seen_at: string;
  instance_count: number;
  total_count: number;
};

type ChartPoint = {
  label: string;
  count: number;
};

type BurstWindow = {
  bucket: string;
  count: number;
};

type Conversation = {
  src_addr: string;
  dst_addr: string;
  dst_port: number | null;
  bytes: number;
  flows: number;
};

type InternalExternalBucket = {
  bucket: string;
  flows: number;
  bytes: number;
};

type ChartData = {
  top_src_ips: ChartPoint[];
  top_dst_ports: ChartPoint[];
  top_rejected_src_ips: ChartPoint[];
  top_interfaces: ChartPoint[];
  top_talkers_by_bytes: ChartPoint[];
  top_conversations: Conversation[];
  internal_external_split: InternalExternalBucket[];
  burst_windows: BurstWindow[];
};

type UploadResults = {
  upload: UploadStatus;
  summary: {
    total_lines: number;
    total_records: number;
    parsed_percent: number;
    accepted_count: number;
    rejected_count: number;
    nodata_count: number;
    skipdata_count: number;
    parse_errors: number;
    ai_summary: string;
  };
  findings: SeverityBucket[];
  timeline: TimelineEntry[];
  charts: ChartData;
};

const EMPTY_CHARTS: ChartData = {
  top_src_ips: [],
  top_dst_ports: [],
  top_rejected_src_ips: [],
  top_interfaces: [],
  top_talkers_by_bytes: [],
  top_conversations: [],
  internal_external_split: [],
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

function ChartBars(props: {
  title: string;
  items: ChartPoint[];
  valueFormatter?: (value: number) => string;
}) {
  const max = props.items.reduce((highest, item) => Math.max(highest, item.count), 1);
  const formatValue = props.valueFormatter ?? ((value: number) => value.toLocaleString());
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
              <strong>{formatValue(item.count)}</strong>
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

const INTERNAL_EXTERNAL_LABELS: Record<string, string> = {
  internal_to_internal: "Internal → Internal",
  internal_to_external: "Internal → External",
  external_to_internal: "External → Internal",
  external_to_external: "External → External"
};

function formatBytes(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  let scaled = value;
  let unit = 0;
  while (scaled >= 1024 && unit < units.length - 1) {
    scaled /= 1024;
    unit++;
  }
  const precision = scaled >= 100 ? 0 : scaled >= 10 ? 1 : 2;
  return `${scaled.toFixed(precision)} ${units[unit]}`;
}

function InternalExternalChart(props: { buckets: InternalExternalBucket[] }) {
  const total = props.buckets.reduce((sum, bucket) => sum + bucket.flows, 0);
  return (
    <section className="panel">
      <div className="panel-header">
        <h3>Internal vs external traffic</h3>
      </div>
      <div className="ie-list">
        {props.buckets.length === 0 || total === 0 ? (
          <p className="muted">No traffic to classify.</p>
        ) : null}
        {props.buckets.map((bucket) => {
          const label = INTERNAL_EXTERNAL_LABELS[bucket.bucket] ?? bucket.bucket;
          const pct = total > 0 ? Math.round((bucket.flows / total) * 100) : 0;
          return (
            <div className="ie-row" key={bucket.bucket}>
              <div className="ie-meta">
                <strong>{label}</strong>
                <span className="muted">
                  {bucket.flows.toLocaleString()} flows · {formatBytes(bucket.bytes)} · {pct}%
                </span>
              </div>
              <div className="bar-track">
                <div className="bar-fill" style={{ width: `${Math.max(pct, 2)}%` }} />
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}

function ConversationsChart(props: { conversations: Conversation[] }) {
  return (
    <section className="panel">
      <div className="panel-header">
        <h3>Top conversations (by bytes)</h3>
      </div>
      <div className="convo-list">
        {props.conversations.length === 0 ? <p className="muted">No conversations yet.</p> : null}
        {props.conversations.map((convo, idx) => {
          const port = convo.dst_port == null ? "" : `:${convo.dst_port}`;
          return (
            <div className="convo-row" key={`${convo.src_addr}->${convo.dst_addr}${port}-${idx}`}>
              <div className="convo-pair">
                <span>{convo.src_addr}</span>
                <span className="convo-arrow">→</span>
                <span>
                  {convo.dst_addr}
                  {port}
                </span>
              </div>
              <div className="convo-meta">
                <strong>{formatBytes(convo.bytes)}</strong>
                <span className="muted">{convo.flows.toLocaleString()} flows</span>
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}

function FindingsView(props: { buckets: SeverityBucket[] }) {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  if (props.buckets.length === 0) {
    return <p className="muted">No notable findings were generated.</p>;
  }

  return (
    <div className="findings-view">
      {props.buckets.map((bucket) => (
        <section className={`severity-section severity-${bucket.severity}`} key={bucket.severity}>
          <header className="severity-header">
            <span className="chip">{bucket.severity}</span>
            <span className="muted">
              {bucket.groups.length} {bucket.groups.length === 1 ? "type" : "types"}
            </span>
          </header>
          <div className="finding-group-list">
            {bucket.groups.map((group) => {
              const key = `${bucket.severity}-${group.type}`;
              const isOpen = expanded[key] ?? false;
              const shown = group.instances.length;
              return (
                <article className="finding-group" key={key}>
                  <button
                    type="button"
                    className="finding-group-header"
                    onClick={() => setExpanded((prev) => ({ ...prev, [key]: !isOpen }))}
                  >
                    <div className="finding-group-meta">
                      <strong>{group.title}</strong>
                      <span className="muted">
                        {group.instance_count} {group.instance_count === 1 ? "instance" : "instances"} · total count {group.total_count}
                      </span>
                    </div>
                    <span className="caret">{isOpen ? "−" : "+"}</span>
                  </button>
                  {isOpen ? (
                    <div className="finding-instance-list">
                      {group.instances.map((instance, idx) => (
                        <div className="finding-instance" key={`${key}-${idx}`}>
                          <p>{instance.description}</p>
                          <div className="finding-instance-meta">
                            <span>count {instance.count}</span>
                            {instance.first_seen_at ? (
                              <span>first {new Date(instance.first_seen_at).toLocaleString()}</span>
                            ) : null}
                            {instance.last_seen_at ? (
                              <span>last {new Date(instance.last_seen_at).toLocaleString()}</span>
                            ) : null}
                          </div>
                        </div>
                      ))}
                      {group.instance_count > shown ? (
                        <p className="muted">
                          Showing top {shown} of {group.instance_count} instances.
                        </p>
                      ) : null}
                    </div>
                  ) : null}
                </article>
              );
            })}
          </div>
        </section>
      ))}
    </div>
  );
}

function TimelineGantt(props: { entries: TimelineEntry[] }) {
  if (props.entries.length === 0) {
    return <p className="muted">No notable timeline entries were generated.</p>;
  }

  const stamps = props.entries.flatMap((entry) => {
    const list: number[] = [];
    const first = Date.parse(entry.first_seen_at);
    const last = Date.parse(entry.last_seen_at);
    if (!Number.isNaN(first)) list.push(first);
    if (!Number.isNaN(last)) list.push(last);
    return list;
  });

  if (stamps.length === 0) {
    return <p className="muted">Timeline entries are missing timestamps.</p>;
  }

  const minTime = Math.min(...stamps);
  const maxTime = Math.max(...stamps);
  const span = Math.max(maxTime - minTime, 1);

  return (
    <div className="timeline-gantt">
      <div className="timeline-axis">
        <span>{new Date(minTime).toLocaleString()}</span>
        <span>{new Date(maxTime).toLocaleString()}</span>
      </div>
      <div className="timeline-rows">
        {props.entries.map((entry) => {
          const first = Date.parse(entry.first_seen_at);
          const last = Date.parse(entry.last_seen_at);
          const safeFirst = Number.isNaN(first) ? minTime : first;
          const safeLast = Number.isNaN(last) ? safeFirst : last;
          const left = ((safeFirst - minTime) / span) * 100;
          const width = Math.max(((safeLast - safeFirst) / span) * 100, 1);
          return (
            <div className="timeline-row" key={entry.type}>
              <div className="timeline-label">
                <strong>{entry.title}</strong>
                <span className="muted">
                  {entry.instance_count} {entry.instance_count === 1 ? "instance" : "instances"} · total {entry.total_count}
                </span>
              </div>
              <div className="timeline-track">
                <div
                  className={`timeline-bar severity-${entry.severity}`}
                  style={{ left: `${left}%`, width: `${width}%` }}
                  title={`${entry.first_seen_at} → ${entry.last_seen_at}`}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function normalizeResults(results: UploadResults): UploadResults {
  return {
    ...results,
    findings: results.findings ?? [],
    timeline: results.timeline ?? [],
    charts: {
      top_src_ips: results.charts?.top_src_ips ?? [],
      top_dst_ports: results.charts?.top_dst_ports ?? [],
      top_rejected_src_ips: results.charts?.top_rejected_src_ips ?? [],
      top_interfaces: results.charts?.top_interfaces ?? [],
      top_talkers_by_bytes: results.charts?.top_talkers_by_bytes ?? [],
      top_conversations: results.charts?.top_conversations ?? [],
      internal_external_split: results.charts?.internal_external_split ?? [],
      burst_windows: results.charts?.burst_windows ?? []
    }
  };
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
    const summary = uploadResults.summary;
    return [
      {
        label: "Parsed",
        value: `${summary.total_records.toLocaleString()} / ${summary.total_lines.toLocaleString()} (${summary.parsed_percent}%)`
      },
      { label: "Accepted", value: summary.accepted_count.toLocaleString() },
      { label: "Rejected", value: summary.rejected_count.toLocaleString() },
      { label: "NODATA", value: summary.nodata_count.toLocaleString() },
      { label: "SKIPDATA", value: summary.skipdata_count.toLocaleString() },
      { label: "Parse errors", value: summary.parse_errors.toLocaleString() }
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
              <h2>Findings</h2>
            </div>
            <FindingsView buckets={uploadResults.findings} />
          </section>

          <section className="panel">
            <div className="panel-header">
              <h2>Timeline</h2>
            </div>
            <TimelineGantt entries={uploadResults.timeline} />
          </section>
        </section>

        <section className="chart-grid">
          <InternalExternalChart buckets={charts.internal_external_split} />
          <ChartBars title="Top source IPs" items={charts.top_src_ips} />
          <ChartBars title="Top destination ports" items={charts.top_dst_ports} />
          <ChartBars title="Top rejected sources" items={charts.top_rejected_src_ips} />
          <ChartBars title="Top interfaces" items={charts.top_interfaces} />
          <ChartBars title="Top talkers (bytes)" items={charts.top_talkers_by_bytes} valueFormatter={formatBytes} />
          <ConversationsChart conversations={charts.top_conversations} />
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
