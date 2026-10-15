// Thin fetch wrapper for the FyberFlix gateway. Errors always become ApiError.

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public retryAfter?: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export type User = {
  id: string;
  fyberflix_number: string;
  fyber_cable_name: string;
  status: string;
  profile_url: string;
  profile_url_number: string;
};

export type Tokens = {
  token_type: string;
  access_token: string;
  access_expires_at: string;
  refresh_token: string;
  refresh_expires_at: string;
};

export type Challenge = {
  challenge_id: string;
  steps: string[];
  expires_in: number;
  purpose: string;
};

type Opts = {
  method?: string;
  token?: string;
  json?: unknown;
  form?: FormData;
  signal?: AbortSignal;
};

type ErrBody = { error?: { code?: string; message?: string } };

export async function api<T>(path: string, o: Opts = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (o.token) headers.Authorization = `Bearer ${o.token}`;
  let body: BodyInit | undefined;
  if (o.form) {
    body = o.form; // browser sets the multipart boundary itself
  } else if (o.json !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(o.json);
  }
  let res: Response;
  try {
    res = await fetch(path, {
      method: o.method ?? (body ? "POST" : "GET"),
      headers,
      body,
      signal: o.signal,
      credentials: "omit",
    });
  } catch (e) {
    if (e instanceof DOMException && e.name === "AbortError") throw e;
    throw new ApiError(0, "network", "Cannot reach FyberFlix. Check your internet connection.");
  }
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  let data: unknown = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = null;
  }
  if (!res.ok) {
    const e = (data as ErrBody | null)?.error;
    const ra = Number(res.headers.get("Retry-After"));
    throw new ApiError(
      res.status,
      e?.code ?? `http_${res.status}`,
      e?.message ?? (res.status === 429 ? "Too many attempts. Please wait a bit." : `Request failed (${res.status})`),
      Number.isFinite(ra) && ra > 0 ? ra : undefined,
    );
  }
  return data as T;
}

export function errMessage(e: unknown): string {
  if (e instanceof ApiError) return e.message;
  return "Something went wrong. Please try again.";
}
