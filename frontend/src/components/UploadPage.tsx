import { FormEvent } from "react";
import { navigateTo } from "../lib/routing";

export function UploadPage(props: {
  userEmail: string;
  selectedFile: File | null;
  setSelectedFile: (file: File | null) => void;
  pendingAction: string | null;
  canSubmitUpload: boolean;
  onUpload: (event: FormEvent<HTMLFormElement>) => void;
  onLogout: () => void;
}) {
  return (
    <section className="workspace">
      <header className="page-header">
        <div>
          <p className="eyebrow">Simple Flow Analyser</p>
          <h1>Upload VPC Flow Logs</h1>
          {props.userEmail ? <p className="user-email-line">{props.userEmail}</p> : null}
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
            onClick={() => props.onLogout()}
          >
            {props.pendingAction === "logout" ? "Signing out..." : "Logout"}
          </button>
        </div>
      </header>

      <section className="panel">
        <div className="panel-header">
          <h2>New upload</h2>
          <span className="chip">vpc_flow</span>
        </div>
        <form className="stack-form" onSubmit={props.onUpload}>
          <label className="upload-dropzone">
            <input
              type="file"
              accept=".log,.txt,text/plain"
              onChange={(event) => props.setSelectedFile(event.target.files?.[0] ?? null)}
            />
            <span>
              {props.selectedFile ? props.selectedFile.name : "Choose a flow-log file to analyse"}
            </span>
            <small>
              {props.selectedFile
                ? `${Math.round(props.selectedFile.size / 1024)} KB selected`
                : "10 MB max"}
            </small>
          </label>
          <div className="actions">
            <button type="submit" disabled={!props.canSubmitUpload}>
              {props.pendingAction === "upload" ? "Uploading..." : "Start processing"}
            </button>
          </div>
        </form>
      </section>
    </section>
  );
}
