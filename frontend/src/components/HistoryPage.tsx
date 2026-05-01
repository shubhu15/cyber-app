import type { UploadListItem } from "../types";
import { navigateTo } from "../lib/routing";

export function HistoryPage(props: {
  userEmail: string;
  uploadHistory: UploadListItem[];
  historyLoading: boolean;
  pendingAction: string | null;
  onRefresh: () => void;
  onLogout: () => void;
}) {
  return (
    <section className="workspace">
      <header className="page-header">
        <div>
          <p className="eyebrow">Simple Flow Analyser</p>
          <h1>Upload History</h1>
          {props.userEmail ? <p className="user-email-line">{props.userEmail}</p> : null}
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
            onClick={() => props.onLogout()}
          >
            {props.pendingAction === "logout" ? "Signing out..." : "Logout"}
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
            onClick={props.onRefresh}
          >
            Refresh
          </button>
        </div>

        {props.historyLoading ? (
          <p className="muted">Loading uploads...</p>
        ) : props.uploadHistory.length === 0 ? (
          <div className="history-empty">
            <p className="muted">No uploads yet. Start by uploading a VPC flow log.</p>
            <button type="button" onClick={() => navigateTo("/app")}>
              Upload your first file
            </button>
          </div>
        ) : (
          <div className="history-list">
            {props.uploadHistory.map((item) => (
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
