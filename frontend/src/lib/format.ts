import type { ChartData, UploadResults } from "../types";

export function formatBytes(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  let scaled = value;
  let unit = 0;
  while (scaled >= 1024 && unit < units.length - 1) {
    scaled /= 1024;
    unit++;
  }
  const precision = scaled >= 100 ? 0 : scaled >= 10 ? 1 : 2;
  return `${scaled.toFixed(precision)} ${units[unit]}`;
}

export const EMPTY_CHARTS: ChartData = {
  top_src_ips: [],
  top_dst_ports: [],
  top_rejected_src_ips: [],
  top_interfaces: [],
  top_talkers_by_bytes: [],
  top_conversations: [],
  internal_external_split: [],
  burst_windows: [],
};

export function normalizeResults(results: UploadResults): UploadResults {
  return {
    ...results,
    findings: results.findings ?? [],
    timeline: results.timeline ?? [],
    charts: {
      top_src_ips: results.charts?.top_src_ips ?? [],
      top_dst_ports: results.charts?.top_dst_ports ?? [],
      top_rejected_src_ips: results.charts?.top_rejected_src_ips ?? [],
      top_interfaces: results.charts?.top_interfaces ?? [],
      top_talkers_by_bytes: results.charts?.top_talkers_by_bytes ?? [],
      top_conversations: results.charts?.top_conversations ?? [],
      internal_external_split: results.charts?.internal_external_split ?? [],
      burst_windows: results.charts?.burst_windows ?? [],
    },
  };
}
