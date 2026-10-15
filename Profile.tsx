import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, ApiError } from "../api";
import { groupNumber, SITE } from "../format";
import CopyButton from "../components/CopyButton";

type P = {
  id: string;
  fyber_cable_name: string;
  fyberflix_number: string;
  profile_url: string;
  member_since: string;
};
type State = { kind: "loading" } | { kind: "ok"; p: P } | { kind: "missing" } | { kind: "error"; msg: string };

export default function Profile() {
  const { ident = "" } = useParams();
  const [s, setS] = useState<State>({ kind: "loading" });

  useEffect(() => {
    const ac = new AbortController();
    setS({ kind: "loading" });
    api<P>(`/v1/profiles/${encodeURIComponent(ident)}`, { signal: ac.signal })
      .then((p) => setS({ kind: "ok", p }))
      .catch((e) => {
        if (ac.signal.aborted) return;
        if (e instanceof ApiError && e.status === 404) setS({ kind: "missing" });
        else setS({ kind: "error", msg: e instanceof ApiError ? e.message : "Could not load this page." });
      });
    return () => ac.abort();
  }, [ident]);

  useEffect(() => {
    document.title = s.kind === "ok" ? `${s.p.fyber_cable_name} · FyberFlix` : "FyberFlix";
    return () => {
      document.title = "FyberFlix";
    };
  }, [s]);

  if (s.kind === "loading") return <div className="wrap"><p className="lead">Loading…</p></div>;
  if (s.kind === "missing")
    return (
      <div className="wrap narrow">
        <section className="card">
          <h1>This page does not exist</h1>
          <p className="lead">No Fyber Cable matches “{ident}”. It may be free: you could claim it.</p>
          <Link className="btn primary" to="/signup">Create your Fyber Cable</Link>
        </section>
      </div>
    );
  if (s.kind === "error")
    return <div className="wrap"><p className="error" role="alert">{s.msg}</p></div>;

  const { p } = s;
  return (
    <div className="wrap">
      <section className="channel">
        <div className="avatar" aria-hidden="true">{p.fyber_cable_name.slice(0, 1).toUpperCase()}</div>
        <div>
          <h1>@{p.fyber_cable_name}</h1>
          <p className="fine">FyberFlix Number {groupNumber(p.fyberflix_number)} · Member since {p.member_since}</p>
          <p className="url">{SITE}/{p.fyber_cable_name} <CopyButton text={`https://${SITE}/${p.fyber_cable_name}`} /></p>
        </div>
      </section>
      <section className="empty card">
        <h2>No videos or reels yet</h2>
        <p className="lead">Uploading comes in the next build. This page is already live at its permanent address.</p>
      </section>
    </div>
  );
}
