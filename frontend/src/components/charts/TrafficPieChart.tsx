import { Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import type { InternalExternalBucket } from "../../types";
import { formatBytes } from "../../lib/format";

const PIE_COLORS = ["#1e537d", "#3a87c9", "#79b8e8", "#b3d9f5"];

const INTERNAL_EXTERNAL_LABELS: Record<string, string> = {
  internal_to_internal: "Int → Int",
  internal_to_external: "Int → Ext",
  external_to_internal: "Ext → Int",
  external_to_external: "Ext → Ext",
};

type PiePayload = {
  name: string;
  value: number;
  bytes: number;
  fill: string;
};

export function TrafficPieChart(props: { buckets: InternalExternalBucket[] }) {
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
