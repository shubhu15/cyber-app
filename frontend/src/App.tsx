import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import {
  Bar,
  BarChart,
  Cell,
  LabelList,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8080";
const MAX_UPLOAD_SIZE = 10 * 1024 * 1024;

// ── Types ─────────────────────────────────────────────────────────────────────

type StatusMessage = {
  kind: "success" | "error" | "info";
  text: string;
};

type SessionState = "checking" | "anonymous" | "authenticated";
type AuthMode = "login" | "register";

type UploadListItem = {
  id: number;
  log_type: string;
  file_name: string;
  status: string;
  created_at: string;
  finished_at?: string;
};

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

type AIAnalysisReport = {
  summary: string;
  threats: string[];
  false_positives: string[];
  recommended_actions: string[];
  model: string;
  generated_at: string;
};

type Route =
  | { name: "auth" }
  | { name: "upload" }
  | { name: "history" }
  | { name: "status"; uploadId: number }
  | { name: "results"; uploadId: number };

// ── Routing ───────────────────────────────────────────────────────────────────

function parseRoute(pathname: string): Route {
  if (pathname === "/app" || pathname === "/upload") {
    return { name: "upload" };
  }
  // exact /uploads match = history; /uploads/:id/* are handled below
  if (pathname === "/uploads" || pathname === "/history") {
    return { name: "history" };
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

// ── API helpers ───────────────────────────────────────────────────────────────

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
    ...init,
  });

  // Dispatch a global event so the App can reset session state without prop drilling.
  if (response.status === 401) {
    window.dispatchEvent(new CustomEvent("session:expired"));
    throw new Error("Authentication required.");
  }

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

// ── Formatting helpers ────────────────────────────────────────────────────────

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

// ── Chart constants ───────────────────────────────────────────────────────────

const PIE_COLORS = ["#1e537d", "#3a87c9", "#79b8e8", "#b3d9f5"];

const INTERNAL_EXTERNAL_LABELS: Record<string, string> = {
  internal_to_internal: "Int → Int",
  internal_to_external: "Int → Ext",
  external_to_internal: "Ext → Int",
  external_to_external: "Ext → Ext",
};

const EMPTY_CHARTS: ChartData = {
  top_src_ips: [],
  top_dst_ports: [],
  top_rejected_src_ips: [],
  top_interfaces: [],
  top_talkers_by_bytes: [],
  top_conversations: [],
  internal_external_split: [],
  burst_windows: [],
};

// ── Chart components ──────────────────────────────────────────────────────────

type PiePayload = {
  name: string;
  value: number;
  bytes: number;
  fill: string;
};

function HorizontalBarChart(props: {
  title: string;
  items: ChartPoint[];
  valueFormatter?: (value: number) => string;
}) {
  const formatValue = props.valueFormatter ?? ((v: number) => v.toLocaleString());
  return (
    <section className="panel">
      <div className="panel-header">
        <h3>{props.title}</h3>
      </div>
      {props.items.length === 0 ? (
        <p className="muted">No data yet.</p>
      ) : (
        <ResponsiveContainer width="100%" height={Math.max(props.items.length * 44, 80)}>
          <BarChart
            layout="vertical"
            data={props.items}
            margin={{ left: 8, right: 64, top: 4, bottom: 4 }}
          >
            <XAxis type="number" hide />
            <YAxis
              type="category"
              dataKey="label"
              width={130}
              tick={{ fontSize: 12, fill: "#4e6178" }}
            />
            <Tooltip
              formatter={(value) => [
                formatValue(value != null ? Number(value) : 0),
                props.title,
              ]}
              contentStyle={{ fontSize: 12 }}
            />
            <Bar dataKey="count" fill="#1e537d" radius={[0, 6, 6, 0]}>
              <LabelList
                dataKey="count"
                position="right"
                formatter={(value) =>
                  formatValue(typeof value === "number" ? value : Number(value) || 0)
                }
                style={{ fontSize: 11, fill: "#5e7084" }}
              />
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      )}
    </section>
  );
}

function TrafficPieChart(props: { buckets: InternalExternalBucket[] }) {
  const data: PiePayload[] = props.buckets
    .filter((b) => b.flows > 0)
    .map((b, i) => ({
      name: INTERNAL_EXTERNAL_LABELS[b.bucket] ?? b.bucket,
      value: b.flows,
      bytes: b.bytes,
      fill: PIE_COLORS[i] ?? "#aaa",
    }));
  const total = data.reduce((s, d) => s + d.value, 0);

  return (
    <section className="panel">
      <div className="panel-header">
        <h3>Internal vs external traffic</h3>
      </div>
      {data.length === 0 || total === 0 ? (
        <p className="muted">No traffic to classify.</p>
      ) : (
        <ResponsiveContainer width="100%" height={230}>
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="45%"
              innerRadius={60}
              outerRadius={88}
              dataKey="value"
              paddingAngle={2}
            >
              {data.map((entry, i) => (
                <Cell key={i} fill={entry.fill} />
              ))}
            </Pie>
            <Tooltip
              content={(tooltipProps) => {
                const { active, payload } = tooltipProps as {
                  active?: boolean;
                  payload?: ReadonlyArray<{ payload?: unknown }>;
                };
                if (!active || !payload?.length) return null;
                const item = payload[0]?.payload as PiePayload | undefined;
                if (!item) return null;
                return (
                  <div className="recharts-custom-tooltip">
                    <strong>{item.name}</strong>
                    <p>
                      {item.value.toLocaleString()} flows · {formatBytes(item.bytes)}
                    </p>
                  </div>
                );
              }}
            />
            <Legend
              formatter={(value: string) => (
                <span style={{ fontSize: 12, color: "#4e6178" }}>{value}</span>
              )}
            />
          </PieChart>
        </ResponsiveContainer>
      )}
    </section>
  );
}

function BurstWindowChart(props: { windows: BurstWindow[] }) {
  const data = [...props.windows]
    .sort((a, b) => (a.bucket < b.bucket ? -1 : 1))
    .map((w) => ({
      time: new Date(w.bucket).toLocaleString(undefined, {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      }),
      count: w.count,
    }));

  return (
    <section className="panel">
      <div className="panel-header">
        <h3>
          Burst windows
          <span className="muted" style={{ fontSize: "0.78em", fontWeight: 400, marginLeft: 8 }}>
            top 5 busiest 5-min windows
          </span>
        </h3>
      </div>
      {data.length === 0 ? (
        <p className="muted">No burst windows were detected.</p>
      ) : (
        <ResponsiveContainer width="100%" height={190}>
          <BarChart data={data} margin={{ left: 0, right: 12, top: 8, bottom: 52 }}>
            <XAxis
              dataKey="time"
              tick={{ fontSize: 10, fill: "#4e6178" }}
              angle={-30}
              textAnchor="end"
              interval={0}
            />
            <YAxis tick={{ fontSize: 11, fill: "#4e6178" }} />
            <Tooltip
              formatter={(value) => [
                (value != null ? Number(value) : 0).toLocaleString(),
                "Flows",
              ]}
              contentStyle={{ fontSize: 12 }}
            />
            <Bar dataKey="count" fill="#c54848" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      )}
    </section>
  );
}

// ── Findings & timeline components ───────────────────────────────────────────

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
                        {group.instance_count}{" "}
                        {group.instance_count === 1 ? "instance" : "instances"} · total count{" "}
                        {group.total_count}
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
                  {entry.instance_count} {entry.instance_count === 1 ? "instance" : "instances"} ·
                  total {entry.total_count}
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

function ConversationsChart(props: { conversations: Conversation[] }) {
  return (
    <section className="panel">
      <div className="panel-header">
        <h3>Top conversations (by bytes)</h3>
      </div>
      <div className="convo-list">
        {props.conversations.length === 0 ? (
          <p className="muted">No conversations yet.</p>
        ) : null}
        {props.conversations.map((convo, idx) => {
          const port = convo.dst_port == null ? "" : `:${convo.dst_port}`;
          return (
            <div
              className="convo-row"
              key={`${convo.src_addr}->${convo.dst_addr}${port}-${idx}`}
            >
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

// ── AI analysis components ────────────────────────────────────────────────────

function AIAnalysisSection(props: { title: string; items: string[]; emptyText: string }) {
  return (
    <div className="ai-section">
      <h3>{props.title}</h3>
      {props.items.length === 0 ? <p className="muted">{props.emptyText}</p> : null}
      {props.items.length > 0 ? (
        <ul>
          {props.items.map((item, idx) => (
            <li key={`${props.title}-${idx}`}>{item}</li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

function AIAnalysisPanel(props: {
  report: AIAnalysisReport | null;
  loading: boolean;
  error: string | null;
  onGenerate: () => void;
}) {
  return (
    <section className="panel ai-analysis-panel">
      <div className="panel-header">
        <div>
          <h2>AI Analysis</h2>
          <p className="muted">
            Generated from deterministic summary, findings, charts, and timeline data only.
          </p>
        </div>
        <button
          className="ghost-button"
          type="button"
          disabled={props.loading}
          onClick={props.onGenerate}
        >
          {props.loading ? "Generating..." : "Generate AI Analysis"}
        </button>
      </div>

      {props.error ? <p className="status-inline error">{props.error}</p> : null}

      {props.report ? (
        <div className="ai-report">
          <div className="ai-section">
            <h3>AI Summary</h3>
            <p>{props.report.summary}</p>
          </div>
          <AIAnalysisSection
            title="Threats"
            items={props.report.threats}
            emptyText="No high-confidence threats were reported."
          />
          <AIAnalysisSection
            title="False Positives"
            items={props.report.false_positives}
            emptyText="No probable false positives were reported."
          />
          <AIAnalysisSection
            title="Recommended Actions"
            items={props.report.recommended_actions}
            emptyText="No recommended actions were returned."
          />
          <p className="muted ai-meta">
            Model {props.report.model} · generated{" "}
            {new Date(props.report.generated_at).toLocaleString()}
          </p>
        </div>
      ) : (
        <p className="muted">
          Generate an analyst report with AI summary, threats, probable false positives, and
          recommended actions.
        </p>
      )}
    </section>
  );
}

// ── Normalisation ─────────────────────────────────────────────────────────────

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
      burst_windows: results.charts?.burst_windows ?? [],
    },
  };
}

// ── App ───────────────────────────────────────────────────────────────────────

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

  const resultMetrics = useMemo(() => {
    if (!uploadResults) return [];
    const summary = uploadResults.summary;
    return [
      {
        label: "Parsed",
        value: `${summary.total_records.toLocaleString()} / ${summary.total_lines.toLocaleString()} (${summary.parsed_percent}%)`,
      },
      { label: "Accepted", value: summary.accepted_count.toLocaleString() },
      { label: "Rejected", value: summary.rejected_count.toLocaleString() },
      { label: "NODATA", value: summary.nodata_count.toLocaleString() },
      { label: "SKIPDATA", value: summary.skipdata_count.toLocaleString() },
      { label: "Parse errors", value: summary.parse_errors.toLocaleString() },
    ];
  }, [uploadResults]);

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

  // ── Render helpers ─────────────────────────────────────────────────────────

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
            {userEmail ? <p className="user-email-line">{userEmail}</p> : null}
            <p className="intro">
              The API stores your file immediately, then the worker parses it asynchronously and
              builds a network-triage view over the resulting flow records.
            </p>
          </div>
          <div className="header-actions">
            <button
              className="ghost-button"
              type="button"
              onClick={() => navigateTo("/uploads")}
            >
              My Uploads
            </button>
            <button
              className="ghost-button"
              type="button"
              onClick={() => void handleLogout()}
            >
              {pendingAction === "logout" ? "Signing out..." : "Logout"}
            </button>
          </div>
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
              <span>
                {selectedFile ? selectedFile.name : "Choose a flow-log file to analyse"}
              </span>
              <small>
                {selectedFile
                  ? `${Math.round(selectedFile.size / 1024)} KB selected`
                  : "10 MB max"}
              </small>
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

  function renderHistoryPage() {
    return (
      <section className="workspace">
        <header className="page-header">
          <div>
            <p className="eyebrow">Simple Flow Analyser</p>
            <h1>Upload History</h1>
            {userEmail ? <p className="user-email-line">{userEmail}</p> : null}
          </div>
          <div className="header-actions">
            <button
              className="ghost-button"
              type="button"
              onClick={() => navigateTo("/app")}
            >
              New Upload
            </button>
            <button
              className="ghost-button"
              type="button"
              onClick={() => void handleLogout()}
            >
              {pendingAction === "logout" ? "Signing out..." : "Logout"}
            </button>
          </div>
        </header>

        <section className="panel">
          <div className="panel-header">
            <h2>Your uploads</h2>
            <button
              className="ghost-button"
              type="button"
              style={{ fontSize: "0.85rem" }}
              onClick={() => setHistoryVersion((v) => v + 1)}
            >
              Refresh
            </button>
          </div>

          {historyLoading ? (
            <p className="muted">Loading uploads...</p>
          ) : uploadHistory.length === 0 ? (
            <div className="history-empty">
              <p className="muted">No uploads yet. Start by uploading a VPC flow log.</p>
              <button type="button" onClick={() => navigateTo("/app")}>
                Upload your first file
              </button>
            </div>
          ) : (
            <div className="history-list">
              {uploadHistory.map((item) => (
                <div className="history-item" key={item.id}>
                  <div className="history-meta">
                    <span className="history-filename" title={item.file_name}>
                      {item.file_name}
                    </span>
                    <span className="history-date">
                      {new Date(item.created_at).toLocaleString()}
                      {item.finished_at
                        ? ` · done ${new Date(item.finished_at).toLocaleString()}`
                        : ""}
                    </span>
                  </div>
                  <div className="history-actions">
                    <span className={`chip status-chip-${item.status}`}>{item.status}</span>
                    {item.status === "completed" ? (
                      <button
                        type="button"
                        className="ghost-button"
                        onClick={() => navigateTo(`/uploads/${item.id}/results`)}
                      >
                        View results
                      </button>
                    ) : item.status === "failed" ? (
                      <span className="muted history-note">Failed</span>
                    ) : (
                      <button
                        type="button"
                        className="ghost-button"
                        onClick={() => navigateTo(`/uploads/${item.id}`)}
                      >
                        Check status
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
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
            <h1>
              {uploadStatus?.file_name ||
                `Upload #${route.name === "status" ? route.uploadId : ""}`}
            </h1>
            <p className="intro">
              The worker is reading the flow-log file, parsing records, and building the summary.
            </p>
          </div>
          <div className="header-actions">
            <button
              className="ghost-button"
              type="button"
              onClick={() => navigateTo("/uploads")}
            >
              My Uploads
            </button>
            <button className="ghost-button" type="button" onClick={() => navigateTo("/app")}>
              New Upload
            </button>
          </div>
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
              {uploadStatus
                ? `${uploadStatus.parsed_lines}/${uploadStatus.total_lines || 0}`
                : "0/0"}
            </strong>
          </article>
        </section>

        <section className="panel">
          <div className="panel-header">
            <h2>Worker progress</h2>
          </div>
          <div className="progress-strip">
            <div
              className={`progress-state ${uploadStatus?.status === "pending" ? "active" : "done"}`}
            >
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
            <div
              className={`progress-state ${uploadStatus?.status === "completed" ? "done" : ""}`}
            >
              Results
            </div>
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
            <button
              className="ghost-button"
              type="button"
              onClick={() => navigateTo("/uploads")}
            >
              My Uploads
            </button>
            <button className="ghost-button" type="button" onClick={() => navigateTo("/app")}>
              Upload another
            </button>
            <button
              className="ghost-button"
              type="button"
              onClick={() => void handleLogout()}
            >
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

        <AIAnalysisPanel
          report={aiAnalysis}
          loading={aiAnalysisLoading}
          error={aiAnalysisError}
          onGenerate={() => {
            void handleGenerateAIAnalysis();
          }}
        />

        <section className="chart-grid">
          <TrafficPieChart buckets={charts.internal_external_split} />
          <HorizontalBarChart title="Top source IPs" items={charts.top_src_ips} />
          <HorizontalBarChart title="Top destination ports" items={charts.top_dst_ports} />
          <HorizontalBarChart title="Top rejected sources" items={charts.top_rejected_src_ips} />
          <HorizontalBarChart title="Top interfaces" items={charts.top_interfaces} />
          <HorizontalBarChart
            title="Top talkers (bytes)"
            items={charts.top_talkers_by_bytes}
            valueFormatter={formatBytes}
          />
          <ConversationsChart conversations={charts.top_conversations} />
          <BurstWindowChart windows={charts.burst_windows} />
        </section>
      </section>
    );
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

  return (
    <main className="page-shell">
      {route.name === "auth" || sessionState === "anonymous" ? renderAuthPage() : null}
      {route.name === "upload" && sessionState === "authenticated" ? renderUploadPage() : null}
      {route.name === "history" && sessionState === "authenticated" ? renderHistoryPage() : null}
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
