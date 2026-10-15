import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, ApiError, errMessage, type Challenge, type Tokens, type User } from "../api";
import { useAuth } from "../auth";
import FaceCapture from "../components/FaceCapture";
import CopyButton from "../components/CopyButton";
import { groupNumber, isValidNameShape, SITE } from "../format";

type Step = "intro" | "number" | "name" | "consent" | "enroll" | "verify" | "done";
type Avail = { state: "idle" | "checking" | "ok" | "bad"; reason?: string };

// DRAFT consent wording. Have it reviewed by a lawyer (India DPDP Act) before launch,
// and bump TERMS_VERSION whenever the text changes.
const TERMS_VERSION = "2026-10-draft";

const STEP_LABEL: Record<Step, string> = {
  intro: "Start",
  number: "1 of 5 · FyberFlix Number",
  name: "2 of 5 · Fyber Cable name",
  consent: "3 of 5 · Face consent",
  enroll: "4 of 5 · Face check",
  verify: "5 of 5 · Confirm it is you",
  done: "Welcome",
};

export default function Signup() {
  const nav = useNavigate();
  const { signIn, status } = useAuth();
  const [step, setStep] = useState<Step>("intro");
  const [token, setToken] = useState("");
  const [offers, setOffers] = useState<string[]>([]);
  const [chosen, setChosen] = useState("");
  const [name, setName] = useState("");
  const [avail, setAvail] = useState<Avail>({ state: "idle" });
  const [agree, setAgree] = useState(false);
  const [challenge, setChallenge] = useState<Challenge | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [needsAccount, setNeedsAccount] = useState(false);
  const [user, setUser] = useState<User | null>(null);
  const nameSeq = useRef(0);
  const accountDone = useRef(false);

  function fail(e: unknown) {
    setError(errMessage(e));
  }

  function reset() {
    setStep("intro");
    setToken("");
    setOffers([]);
    setChosen("");
    setName("");
    setAvail({ state: "idle" });
    setAgree(false);
    setChallenge(null);
    setNeedsAccount(false);
    accountDone.current = false;
    setError("");
  }

  async function run(fn: () => Promise<void>) {
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      await fn();
    } catch (e) {
      fail(e);
    } finally {
      setBusy(false);
    }
  }

  // ---- 1. session + numbers
  const start = () =>
    run(async () => {
      const r = await api<{ session_token: string; number_offers: string[] }>("/v1/signup/sessions", { method: "POST" });
      setToken(r.session_token);
      setOffers(r.number_offers);
      setStep("number");
    });

  const moreOffers = () =>
    run(async () => {
      const r = await api<{ number_offers: string[] }>("/v1/signup/number-offers/refresh", { method: "POST", token });
      setOffers(r.number_offers);
      setChosen("");
    });

  const pickNumber = () =>
    run(async () => {
      await api("/v1/signup/number", { token, json: { number: chosen } });
      setStep("name");
    });

  // ---- 2. cable name with live availability
  useEffect(() => {
    if (step !== "name") return;
    const seq = ++nameSeq.current;
    if (name === "") {
      setAvail({ state: "idle" });
      return;
    }
    if (!isValidNameShape(name)) {
      setAvail({ state: "bad", reason: "Use 3–30 letters, digits, '.', '_' or '-', and at least one letter." });
      return;
    }
    setAvail({ state: "checking" });
    const t = setTimeout(async () => {
      try {
        const r = await api<{ available: boolean; reason?: string }>(
          `/v1/signup/cable-name/check?name=${encodeURIComponent(name)}`,
          { token },
        );
        if (seq === nameSeq.current) setAvail(r.available ? { state: "ok" } : { state: "bad", reason: r.reason ?? "Not available" });
      } catch (e) {
        if (seq === nameSeq.current) setAvail({ state: "bad", reason: errMessage(e) });
      }
    }, 400);
    return () => clearTimeout(t);
  }, [name, step, token]);

  const submitName = (ev: FormEvent) => {
    ev.preventDefault();
    if (avail.state !== "ok") return;
    void run(async () => {
      const r = await api<{ fyber_cable_name: string }>("/v1/signup/cable-name", { token, json: { name } });
      setName(r.fyber_cable_name);
      setStep("consent");
    });
  };

  // ---- 3. consent -> 4. enroll challenge
  const loadChallenge = async () => {
    const c = await api<Challenge>("/v1/signup/face/challenge", { token, method: "POST" });
    setChallenge(c);
  };

  const giveConsent = () =>
    run(async () => {
      await api("/v1/signup/consent", { token, json: { biometric_consent: true, terms_version: TERMS_VERSION } });
      await loadChallenge();
      setStep("enroll");
    });

  // ---- create account, then confirm the face a second time
  async function finishEnroll() {
    if (!accountDone.current) {
      await api("/v1/signup/account", { token, method: "POST" });
      accountDone.current = true;
    }
    await loadChallenge();
    setNeedsAccount(false);
    setStep("verify");
  }

  const retryAccount = () => run(finishEnroll);

  async function submitFrames(frames: Blob[]) {
    if (!challenge) return;
    setBusy(true);
    setError("");
    const form = new FormData();
    form.append("challenge_id", challenge.challenge_id);
    frames.forEach((f, i) => form.append("frames", f, `f${i}.jpg`));
    let faceStage = true;
    try {
      if (step === "enroll") {
        await api("/v1/signup/face", { token, form });
        faceStage = false;
        setNeedsAccount(true);
        await finishEnroll();
      } else {
        const r = await api<{ user: User; tokens: Tokens }>("/v1/signup/face", { token, form });
        signIn(r.tokens, r.user);
        setUser(r.user);
        setChallenge(null);
        setStep("done");
      }
    } catch (e) {
      fail(e);
      // A challenge is single-use: after a failed face step fetch a fresh one so "try again" works.
      if (faceStage && !(e instanceof ApiError && e.code === "face_locked")) {
        try {
          await loadChallenge();
        } catch {
          /* the error above is already shown */
        }
      }
    } finally {
      setBusy(false);
    }
  }

  const sessionLost = error.toLowerCase().includes("session") || error.toLowerCase().includes("expired");

  return (
    <div className="wrap narrow">
      <p className="eyebrow">{STEP_LABEL[step]}</p>

      {step === "intro" && (
        <section className="card">
          <h1>Create your Fyber Cable</h1>
          <p className="lead">Five quick steps. You will need a camera. There is no password to remember.</p>
          {status === "in" && <p className="notice">You are already logged in. <Link to="/account">Go to your account</Link>.</p>}
          <button className="btn primary" onClick={start} disabled={busy}>
            {busy ? "Starting…" : "Start"}
          </button>
        </section>
      )}

      {step === "number" && (
        <section className="card">
          <h1>Choose your FyberFlix Number</h1>
          <p className="lead">9 digits, yours for life. Staff use it to find your account; calls and messages will use it later. Pick one of these ten.</p>
          <div className="numgrid" role="radiogroup" aria-label="FyberFlix Number options">
            {offers.map((n) => (
              <button
                key={n}
                type="button"
                role="radio"
                aria-checked={chosen === n}
                className={`num ${chosen === n ? "sel" : ""}`}
                onClick={() => setChosen(n)}
              >
                {groupNumber(n)}
              </button>
            ))}
          </div>
          <div className="row">
            <button className="btn primary" disabled={!chosen || busy} onClick={pickNumber}>Use this number</button>
            <button className="btn ghost" disabled={busy} onClick={moreOffers}>Show other numbers</button>
          </div>
        </section>
      )}

      {step === "name" && (
        <form className="card" onSubmit={submitName} noValidate>
          <h1>Name your Fyber Cable</h1>
          <p className="lead">This is your channel name and your web address. It must be unique.</p>
          <label htmlFor="cable">Fyber Cable name</label>
          <input
            id="cable"
            value={name}
            onChange={(e) => setName(e.target.value.trim())}
            autoComplete="off"
            autoCapitalize="off"
            spellCheck={false}
            maxLength={30}
            aria-describedby="cable-hint"
          />
          <p className="url">{SITE}/<strong>{name || "yourname"}</strong></p>
          <p id="cable-hint" className={`hint ${avail.state}`} role="status" aria-live="polite">
            {avail.state === "checking" && "Checking…"}
            {avail.state === "ok" && "✓ Available"}
            {avail.state === "bad" && (avail.reason ?? "Not available")}
          </p>
          <p className="fine">Your number <strong>{groupNumber(chosen)}</strong> opens the same page: {SITE}/{chosen}</p>
          <button className="btn primary" disabled={avail.state !== "ok" || busy}>Continue</button>
        </form>
      )}

      {step === "consent" && (
        <section className="card">
          <h1>Face check consent</h1>
          <p className="lead">FyberFlix uses your face instead of a password, so we need your clear permission.</p>
          <div className="terms" tabIndex={0} aria-label="Consent details">
            <ul>
              <li>We turn your face into an encrypted numeric template. We do not store your photo or video.</li>
              <li>The template is used only to check it is you when you log in or confirm sensitive actions.</li>
              <li>You can delete your account at any time; your template is erased when you do.</li>
              <li>Withdrawing consent means you can no longer log in, because your face is your password.</li>
            </ul>
          </div>
          <label className="check">
            <input type="checkbox" checked={agree} onChange={(e) => setAgree(e.target.checked)} />
            <span>I agree to FyberFlix processing my face as described above.</span>
          </label>
          <button className="btn primary" disabled={!agree || busy} onClick={giveConsent}>I agree, continue</button>
        </section>
      )}

      {(step === "enroll" || step === "verify") && (
        <>
          {challenge && !needsAccount ? (
            <FaceCapture
              key={challenge.challenge_id}
              steps={challenge.steps}
              busy={busy}
              onDone={submitFrames}
              title={step === "enroll" ? "Register your face" : "Confirm it is you"}
            />
          ) : (
            <section className="card">
              <h1>{needsAccount ? "Finishing your account…" : "Preparing…"}</h1>
              {needsAccount && !busy && (
                <button className="btn primary" onClick={retryAccount}>Retry</button>
              )}
            </section>
          )}
        </>
      )}

      {step === "done" && user && (
        <section className="card">
          <h1>Welcome to FyberFlix 🎉</h1>
          <dl className="facts">
            <div><dt>FyberFlix Number</dt><dd>{groupNumber(user.fyberflix_number)}</dd></div>
            <div><dt>Fyber Cable</dt><dd>@{user.fyber_cable_name}</dd></div>
            <div>
              <dt>Your page</dt>
              <dd>{SITE}/{user.fyber_cable_name} <CopyButton text={`https://${SITE}/${user.fyber_cable_name}`} /></dd>
            </div>
          </dl>
          <p className="fine">Save your number somewhere safe. If you ever need help, support will ask for it.</p>
          <button className="btn primary" onClick={() => nav("/account")}>Go to my account</button>
        </section>
      )}

      {error && (
        <p className="error" role="alert">
          {error}{" "}
          {step !== "intro" && step !== "done" && sessionLost && (
            <button className="link" onClick={reset}>Start over</button>
          )}
        </p>
      )}
      {step !== "intro" && step !== "done" && (
        <p className="fine"><button className="link" onClick={reset}>Cancel and start over</button></p>
      )}
    </div>
  );
}
