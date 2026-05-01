import {
  Bar,
  BarChart,
  LabelList,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { ChartPoint } from "../../types";

export function HorizontalBarChart(props: {
  title: string;
  items: ChartPoint[];
  valueFormatter?: (value: number) => string;
}) {
  const formatValue = props.valueFormatter ?? ((v: number) => v.toLocaleString());
  return (
    <section className="panel">
      <div className="panel-header">
        <h3>{props.title}</h3>
      </div>
      {props.items.length === 0 ? (
        <p className="muted">No data yet.</p>
      ) : (
        <ResponsiveContainer width="100%" height={Math.max(props.items.length * 44, 80)}>
          <BarChart
            layout="vertical"
            data={props.items}
            margin={{ left: 8, right: 64, top: 4, bottom: 4 }}
          >
            <XAxis type="number" hide />
            <YAxis
              type="category"
              dataKey="label"
              width={130}
              tick={{ fontSize: 12, fill: "#4e6178" }}
            />
            <Tooltip
              formatter={(value) => [
                formatValue(value != null ? Number(value) : 0),
                props.title,
              ]}
              contentStyle={{ fontSize: 12 }}
            />
            <Bar dataKey="count" fill="#1e537d" radius={[0, 6, 6, 0]}>
              <LabelList
                dataKey="count"
                position="right"
                formatter={(value) =>
                  formatValue(typeof value === "number" ? value : Number(value) || 0)
                }
                style={{ fontSize: 11, fill: "#5e7084" }}
              />
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      )}
    </section>
  );
}
