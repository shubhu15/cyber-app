import { useMemo } from "react";
import type { AIAnalysisReport, UploadResults } from "../types";
import { EMPTY_CHARTS, formatBytes } from "../lib/format";
import { navigateTo } from "../lib/routing";
import { FindingsView } from "./FindingsView";
import { TimelineGantt } from "./TimelineGantt";
import { AIAnalysisPanel } from "./AIAnalysisPanel";
import { HorizontalBarChart } from "./charts/HorizontalBarChart";
import { TrafficPieChart } from "./charts/TrafficPieChart";
import { BurstWindowChart } from "./charts/BurstWindowChart";
import { ConversationsChart } from "./charts/ConversationsChart";

export function ResultsPage(props: {
  uploadResults: UploadResults | null;
  aiAnalysis: AIAnalysisReport | null;
  aiAnalysisLoading: boolean;
  aiAnalysisError: string | null;
  onGenerateAIAnalysis: () => void;
  onLogout: () => void;
}) {
  const resultMetrics = useMemo(() => {
    if (!props.uploadResults) return [];
    const summary = props.uploadResults.summary;
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
  }, [props.uploadResults]);

  if (!props.uploadResults) {
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

  const charts = props.uploadResults.charts ?? EMPTY_CHARTS;

  return (
    <section className="workspace">
      <header className="page-header">
        <div>
          <p className="eyebrow">Analysis results</p>
          <h1>{props.uploadResults.upload.file_name || "Completed upload"}</h1>
          <p className="intro">{props.uploadResults.summary.ai_summary}</p>
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
            onClick={() => props.onLogout()}
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
          <FindingsView buckets={props.uploadResults.findings} />
        </section>

        <section className="panel">
          <div className="panel-header">
            <h2>Timeline</h2>
          </div>
          <TimelineGantt entries={props.uploadResults.timeline} />
        </section>
      </section>

      <AIAnalysisPanel
        report={props.aiAnalysis}
        loading={props.aiAnalysisLoading}
        error={props.aiAnalysisError}
        onGenerate={props.onGenerateAIAnalysis}
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
