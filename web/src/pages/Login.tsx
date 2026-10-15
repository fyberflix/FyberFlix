import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, errMessage, type Tokens, type User } from "../api";
import { useAuth } from "../auth";
import FaceCapture from "../components/FaceCapture";

type Attempt = { login_token: string; steps: string[]; expires_in: number };

export default function Login() {
  const nav = useNavigate();
  const { signIn } = useAuth();
  const [ident, setIdent] = useState("");
  const [attempt, setAttempt] = useState<Attempt | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function begin(ev?: FormEvent) {
    ev?.preventDefault();
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      const a = await api<Attempt>("/v1/login/start", { json: { identifier: ident.trim().replace(/^@/, "").replace(/\s+/g, "") } });
      setAttempt(a);
    } catch (e) {
      setError(errMessage(e));
    } finally {
      setBusy(false);
    }
  }

  async function submit(frames: Blob[]) {
    if (!attempt) return;
    setBusy(true);
    setError("");
    const form = new FormData();
    frames.forEach((f, i) => form.append("frames", f, `f${i}.jpg`));
    try {
      const r = await api<{ user: User; tokens: Tokens }>("/v1/login/face", { token: attempt.login_token, form });
      signIn(r.tokens, r.user);
      nav("/account", { replace: true });
    } catch (e) {
      setError(errMessage(e));
      setAttempt(null); // one try per login token: start a fresh attempt
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="wrap narrow">
      <p className="eyebrow">Log in</p>
      {!attempt ? (
        <form className="card" onSubmit={begin} noValidate>
          <h1>Welcome back</h1>
          <p className="lead">Enter your Fyber Cable name or your 9-digit FyberFlix Number. Then a quick face check.</p>
          <label htmlFor="ident">Fyber Cable name or FyberFlix Number</label>
          <input
            id="ident"
            value={ident}
            onChange={(e) => setIdent(e.target.value)}
            autoComplete="username"
            autoCapitalize="off"
            spellCheck={false}
            inputMode="text"
          />
          <button className="btn primary" disabled={busy || ident.trim().length < 3}>
            {busy ? "Please wait…" : "Continue"}
          </button>
          <p className="fine">New here? <Link to="/signup">Create your Fyber Cable</Link></p>
        </form>
      ) : (
        <FaceCapture key={attempt.login_token} steps={attempt.steps} busy={busy} onDone={submit} title="Face check" />
      )}
      {error && <p className="error" role="alert">{error}</p>}
    </div>
  );
}
