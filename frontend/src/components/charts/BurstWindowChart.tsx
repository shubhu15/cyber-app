import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { BurstWindow } from "../../types";

export function BurstWindowChart(props: { windows: BurstWindow[] }) {
  const data = [...props.windows]
    .sort((a, b) => (a.bucket < b.bucket ? -1 : 1))
    .map((w) => ({
      time: new Date(w.bucket).toLocaleString(undefined, {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      }),
      count: w.count,
    }));

  return (
    <section className="panel">
      <div className="panel-header">
        <h3>
          Burst windows
          <span className="muted" style={{ fontSize: "0.78em", fontWeight: 400, marginLeft: 8 }}>
            top 5 busiest 5-min windows
          </span>
        </h3>
      </div>
      {data.length === 0 ? (
        <p className="muted">No burst windows were detected.</p>
      ) : (
        <ResponsiveContainer width="100%" height={190}>
          <BarChart data={data} margin={{ left: 0, right: 12, top: 8, bottom: 52 }}>
            <XAxis
              dataKey="time"
              tick={{ fontSize: 10, fill: "#4e6178" }}
              angle={-30}
              textAnchor="end"
              interval={0}
            />
            <YAxis tick={{ fontSize: 11, fill: "#4e6178" }} />
            <Tooltip
              formatter={(value) => [
                (value != null ? Number(value) : 0).toLocaleString(),
                "Flows",
              ]}
              contentStyle={{ fontSize: 12 }}
            />
            <Bar dataKey="count" fill="#c54848" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      )}
    </section>
  );
}
