import type { UploadStatus } from "../types";
import { navigateTo } from "../lib/routing";

export function StatusPage(props: {
  uploadStatus: UploadStatus | null;
  uploadId: number;
}) {
  return (
    <section className="workspace">
      <header className="page-header">
        <div>
          <p className="eyebrow">Processing upload</p>
          <h1>{props.uploadStatus?.file_name || `Upload #${props.uploadId}`}</h1>
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
          <strong>{props.uploadStatus?.status || "pending"}</strong>
        </article>
        <article className="panel stat-card">
          <span>Progress</span>
          <strong>
            {props.uploadStatus ? `${props.uploadStatus.progress_percentage}%` : "0%"}
          </strong>
        </article>
        <article className="panel stat-card">
          <span>Parsed rows</span>
          <strong>
            {props.uploadStatus
              ? `${props.uploadStatus.parsed_lines}/${props.uploadStatus.total_lines || 0}`
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
            className={`progress-state ${props.uploadStatus?.status === "pending" ? "active" : "done"}`}
          >
            Pending
          </div>
          <div
            className={`progress-state ${
              props.uploadStatus?.status === "processing"
                ? "active"
                : props.uploadStatus?.status === "completed"
                  ? "done"
                  : ""
            }`}
          >
            Processing
          </div>
          <div
            className={`progress-state ${props.uploadStatus?.status === "completed" ? "done" : ""}`}
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
