import type { Conversation } from "../../types";
import { formatBytes } from "../../lib/format";

export function ConversationsChart(props: { conversations: Conversation[] }) {
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
