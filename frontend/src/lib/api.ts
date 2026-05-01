export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8080";
export const MAX_UPLOAD_SIZE = 10 * 1024 * 1024;

async function parseResponse<T>(response: Response): Promise<T | { message?: string }> {
  const contentType = response.headers.get("content-type") ?? "";
  if (response.status === 204) {
    return {};
  }
  if (contentType.includes("application/json")) {
    return response.json() as Promise<T | { message?: string }>;
  }
  return { message: await response.text() };
}

export async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    credentials: "include",
    ...init,
  });

  // Dispatch a global event so the App can reset session state without prop drilling.
  if (response.status === 401) {
    window.dispatchEvent(new CustomEvent("session:expired"));
    throw new Error("Authentication required.");
  }

  const payload = await parseResponse<T>(response);
  if (!response.ok) {
    const message =
      payload && typeof payload === "object" && "message" in payload
        ? String(payload.message ?? "Request failed.")
        : "Request failed.";
    throw new Error(message);
  }
  return payload as T;
}
