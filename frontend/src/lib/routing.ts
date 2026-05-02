import type { Route } from "../types";

export function parseRoute(pathname: string): Route {
  if (pathname === "/app" || pathname === "/upload") {
    return { name: "upload" };
  }
  // exact /uploads match = history; /uploads/:id/* are handled below
  if (pathname === "/uploads" || pathname === "/history") {
    return { name: "history" };
  }
  const resultsMatch = pathname.match(/^\/uploads\/(\d+)\/results\/?$/);
  if (resultsMatch) {
    return { name: "results", uploadId: Number(resultsMatch[1]) };
  }
  const uploadMatch = pathname.match(/^\/uploads\/(\d+)\/?$/);
  if (uploadMatch) {
    return { name: "status", uploadId: Number(uploadMatch[1]) };
  }
  return { name: "auth" };
}

export function navigateTo(path: string) {
  window.history.pushState({}, "", path);
  window.dispatchEvent(new PopStateEvent("popstate"));
}
