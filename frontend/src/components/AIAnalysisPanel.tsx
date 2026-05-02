import type { AIAnalysisReport } from "../types";

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

export function AIAnalysisPanel(props: {
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
