import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import { errMessage } from "../api";
import { useAuth } from "../auth";
import { authed } from "../session";
import CopyButton from "../components/CopyButton";
import { groupNumber, SITE } from "../format";

type Sess = { id: string; user_agent: string; ip: string; created_at: string; last_used_at: string; current: boolean };

const when = (iso: string) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleString();
};

export default function Account() {
  const { status, user, signOut } = useAuth();
  const nav = useNavigate();
  const [sessions, setSessions] = useState<Sess[]>([]);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [sent, setSent] = useState(false);
  const [busy, setBusy] = useState(false);

  const loadSessions = useCallback(async () => {
    try {
      const r = await authed<{ sessions: Sess[] }>("/v1/me/sessions");
      setSessions(r.sessions);
    } catch (e) {
      setErr(errMessage(e));
    }
  }, []);

  useEffect(() => {
    if (status === "in") void loadSessions();
  }, [status, loadSessions]);

  if (status === "loading") return <div className="wrap"><p className="lead">Loading…</p></div>;
  if (status === "out" || !user) return <Navigate to="/login" replace />;

  async function act(fn: () => Promise<void>) {
    if (busy) return;
    setBusy(true);
    setErr("");
    setMsg("");
    try {
      await fn();
    } catch (e) {
      setErr(errMessage(e));
    } finally {
      setBusy(false);
    }
  }

  const sendCode = (ev: FormEvent) => {
    ev.preventDefault();
    void act(async () => {
      await authed("/v1/me/email", { json: { email: email.trim() } });
      setSent(true);
      setMsg("We sent a 6-digit code. It expires soon.");
    });
  };
  const verify = (ev: FormEvent) => {
    ev.preventDefault();
    void act(async () => {
      const r = await authed<{ email: string }>("/v1/me/email/verify", { json: { code: code.trim() } });
      setSent(false);
      setCode("");
      setEmail("");
      setMsg(`Email ${r.email} is verified.`);
    });
  };
  const removeEmail = () =>
    act(async () => {
      await authed<void>("/v1/me/email", { method: "DELETE" });
      setMsg("Email removed.");
    });
  const revoke = (id: string) =>
    act(async () => {
      await authed<void>(`/v1/me/sessions/${id}`, { method: "DELETE" });
      await loadSessions();
    });
  const logoutAll = () =>
    act(async () => {
      await authed<void>("/v1/logout-all", { method: "POST" });
      await signOut();
      nav("/", { replace: true });
    });

  return (
    <div className="wrap narrow">
      <p className="eyebrow">Your account</p>
      <section className="card">
        <h1>@{user.fyber_cable_name}</h1>
        <dl className="facts">
          <div><dt>FyberFlix Number</dt><dd>{groupNumber(user.fyberflix_number)} <CopyButton text={user.fyberflix_number} /></dd></div>
          <div><dt>Your page</dt><dd>{SITE}/{user.fyber_cable_name} <CopyButton text={`https://${SITE}/${user.fyber_cable_name}`} /></dd></div>
          <div><dt>Same page by number</dt><dd>{SITE}/{user.fyberflix_number}</dd></div>
        </dl>
      </section>

      <section className="card">
        <h2>Recovery email <span className="fine">(optional)</span></h2>
        <p className="lead">Only used to recover your account if your face stops working. We verify it with a code.</p>
        {!sent ? (
          <form onSubmit={sendCode} className="stack">
            <label htmlFor="em">Email address</label>
            <input id="em" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" />
            <div className="row">
              <button className="btn primary" disabled={busy || !email.includes("@")}>Send code</button>
              <button type="button" className="btn ghost" disabled={busy} onClick={removeEmail}>Remove email</button>
            </div>
          </form>
        ) : (
          <form onSubmit={verify} className="stack">
            <label htmlFor="otp">6-digit code</label>
            <input id="otp" inputMode="numeric" autoComplete="one-time-code" maxLength={6} value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} />
            <div className="row">
              <button className="btn primary" disabled={busy || code.length !== 6}>Verify</button>
              <button type="button" className="btn ghost" onClick={() => setSent(false)}>Back</button>
            </div>
          </form>
        )}
      </section>

      <section className="card">
        <h2>Devices logged in</h2>
        <ul className="sessions">
          {sessions.map((s) => (
            <li key={s.id}>
              <div>
                <strong>{s.current ? "This device" : "Another device"}</strong>
                <span className="fine">{s.user_agent.slice(0, 80)}</span>
                <span className="fine">Last used {when(s.last_used_at)}</span>
              </div>
              {!s.current && <button className="btn small ghost" disabled={busy} onClick={() => revoke(s.id)}>Log out</button>}
            </li>
          ))}
        </ul>
        <div className="row">
          <button className="btn ghost" disabled={busy} onClick={async () => { await signOut(); nav("/", { replace: true }); }}>Log out here</button>
          <button className="btn danger" disabled={busy} onClick={logoutAll}>Log out everywhere</button>
        </div>
      </section>

      {msg && <p className="notice" role="status">{msg}</p>}
      {err && <p className="error" role="alert">{err}</p>}
    </div>
  );
}
