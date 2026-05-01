export type StatusMessage = {
  kind: "success" | "error" | "info";
  text: string;
};

export type SessionState = "checking" | "anonymous" | "authenticated";
export type AuthMode = "login" | "register";

export type UploadListItem = {
  id: number;
  log_type: string;
  file_name: string;
  status: string;
  created_at: string;
  finished_at?: string;
};

export type UploadStatus = {
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

export type FindingInstance = {
  description: string;
  first_seen_at?: string;
  last_seen_at?: string;
  count: number;
  metadata: Record<string, unknown>;
};

export type FindingGroup = {
  type: string;
  severity: string;
  title: string;
  instance_count: number;
  total_count: number;
  instances: FindingInstance[];
};

export type SeverityBucket = {
  severity: string;
  groups: FindingGroup[];
};

export type TimelineEntry = {
  type: string;
  severity: string;
  title: string;
  first_seen_at: string;
  last_seen_at: string;
  instance_count: number;
  total_count: number;
};

export type ChartPoint = {
  label: string;
  count: number;
};

export type BurstWindow = {
  bucket: string;
  count: number;
};

export type Conversation = {
  src_addr: string;
  dst_addr: string;
  dst_port: number | null;
  bytes: number;
  flows: number;
};

export type InternalExternalBucket = {
  bucket: string;
  flows: number;
  bytes: number;
};

export type ChartData = {
  top_src_ips: ChartPoint[];
  top_dst_ports: ChartPoint[];
  top_rejected_src_ips: ChartPoint[];
  top_interfaces: ChartPoint[];
  top_talkers_by_bytes: ChartPoint[];
  top_conversations: Conversation[];
  internal_external_split: InternalExternalBucket[];
  burst_windows: BurstWindow[];
};

export type UploadResults = {
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

export type AIAnalysisReport = {
  summary: string;
  threats: string[];
  false_positives: string[];
  recommended_actions: string[];
  model: string;
  generated_at: string;
};

export type Route =
  | { name: "auth" }
  | { name: "upload" }
  | { name: "history" }
  | { name: "status"; uploadId: number }
  | { name: "results"; uploadId: number };
