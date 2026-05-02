import type { TimelineEntry } from "../types";

export function TimelineGantt(props: { entries: TimelineEntry[] }) {
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
