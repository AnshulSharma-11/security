const BASE: string = (import.meta as any).env?.VITE_API_URL ?? "/api";
type Tokens = { access_token: string; refresh_token: string };
let tokens: Tokens | null = JSON.parse(sessionStorage.getItem("sentinel.tokens") || "null");

export class ApiError extends Error { status: number; constructor(m: string, s: number) { super(m); this.status = s; } }
export function setTokens(t: Tokens | null) {
  tokens = t;
  t ? sessionStorage.setItem("sentinel.tokens", JSON.stringify(t)) : sessionStorage.removeItem("sentinel.tokens");
}
export const hasTokens = () => !!tokens;

async function refresh(): Promise<boolean> {
  if (!tokens) return false;
  const r = await fetch(`${BASE}/auth/refresh`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ refresh_token: tokens.refresh_token }) });
  if (!r.ok) { setTokens(null); return false; }
  setTokens(await r.json());
  return true;
}
function msg(d: any): string {
  const x = d?.detail;
  if (typeof x === "string") return x;
  if (Array.isArray(x)) return x.map((e) => e.msg).join("; ");
  return "Something went wrong";
}
export async function api(path: string, opts: { method?: string; body?: any; raw?: boolean } = {}, retry = true): Promise<any> {
  const r = await fetch(`${BASE}${path}`, {
    method: opts.method ?? (opts.body ? "POST" : "GET"),
    headers: { ...(opts.body ? { "Content-Type": "application/json" } : {}), ...(tokens ? { Authorization: `Bearer ${tokens.access_token}` } : {}) },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  if (r.status === 401 && retry && tokens && !path.startsWith("/auth/") && (await refresh())) return api(path, opts, false);
  if (r.status === 401 && !path.startsWith("/auth/login")) { setTokens(null); window.dispatchEvent(new Event("sentinel:logout")); }
  if (!r.ok) throw new ApiError(msg(await r.json().catch(() => ({}))), r.status);
  if (opts.raw) return r;
  return r.status === 204 ? null : r.json();
}
export const qs = (o: Record<string, any>) => {
  const p = new URLSearchParams();
  Object.entries(o).forEach(([k, v]) => v !== undefined && v !== "" && v !== null && p.set(k, String(v)));
  return p.toString();
};
