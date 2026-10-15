// Token handling.
// - access token: memory only (10 min life).
// - refresh token: localStorage. NOTE: readable by any script on this origin, so XSS
//   would steal it. For maximum safety move it to an HttpOnly cookie behind a small
//   same-site BFF; the API contract here does not change.
// Refresh tokens ROTATE and re-use of an old one revokes the session, so refreshes are
// single-flight in this tab and serialized across tabs with the Web Locks API.
import { api, ApiError, type Tokens } from "./api";

const RT_KEY = "ff.rt";
let access: { token: string; exp: number } | null = null;
let inflight: Promise<string | null> | null = null;
const cleared = new Set<() => void>();

function readRT(): string | null {
  try {
    return localStorage.getItem(RT_KEY);
  } catch {
    return null;
  }
}
function writeRT(v: string | null) {
  try {
    if (v === null) localStorage.removeItem(RT_KEY);
    else localStorage.setItem(RT_KEY, v);
  } catch {
    /* storage blocked: session lasts until the tab closes */
  }
}

export function setTokens(t: Tokens) {
  access = { token: t.access_token, exp: Date.parse(t.access_expires_at) };
  writeRT(t.refresh_token);
}

export function clearTokens() {
  access = null;
  writeRT(null);
  cleared.forEach((f) => f());
}

export function onSessionCleared(f: () => void) {
  cleared.add(f);
  return () => {
    cleared.delete(f);
  };
}

export function hasStoredSession(): boolean {
  return access !== null || readRT() !== null;
}

export function refreshTokenForLogout(): string | null {
  return readRT();
}

async function doRefresh(): Promise<string | null> {
  const rt = readRT();
  if (!rt) return null;
  try {
    const t = await api<Tokens>("/v1/token/refresh", { json: { refresh_token: rt } });
    setTokens(t);
    return t.access_token;
  } catch (e) {
    if (e instanceof ApiError && (e.status === 401 || e.status === 403)) clearTokens();
    return null; // network trouble: keep the refresh token, try again later
  }
}

export function getAccessToken(): Promise<string | null> {
  if (access && access.exp - Date.now() > 30_000) return Promise.resolve(access.token);
  if (!inflight) {
    const run = () => doRefresh();
    const p = navigator.locks ? navigator.locks.request("ff-refresh", run) : run();
    inflight = p.finally(() => {
      inflight = null;
    });
  }
  return inflight;
}

type AuthedOpts = { method?: string; json?: unknown; form?: FormData; signal?: AbortSignal };

export async function authed<T>(path: string, o: AuthedOpts = {}): Promise<T> {
  let t = await getAccessToken();
  if (!t) throw new ApiError(401, "no_session", "Please log in.");
  try {
    return await api<T>(path, { ...o, token: t });
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) {
      access = null; // force a refresh once, then give up
      t = await getAccessToken();
      if (!t) throw e;
      return api<T>(path, { ...o, token: t });
    }
    throw e;
  }
}
