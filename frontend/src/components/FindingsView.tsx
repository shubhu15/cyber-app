import { useState } from "react";
import type { SeverityBucket } from "../types";

export function FindingsView(props: { buckets: SeverityBucket[] }) {
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
