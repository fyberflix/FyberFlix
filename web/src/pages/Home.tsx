import { Link } from "react-router-dom";
import { useAuth } from "../auth";

export default function Home() {
  const { status } = useAuth();
  return (
    <div className="wrap hero">
      <p className="eyebrow">Videos · Reels · Creators</p>
      <h1>Your face is your password.</h1>
      <p className="lead">
        No email. No password. Pick your own 9-digit FyberFlix Number, name your Fyber Cable, and
        sign in with a quick head-turn check.
      </p>
      <div className="row">
        {status === "in" ? (
          <Link className="btn primary" to="/account">Go to my account</Link>
        ) : (
          <>
            <Link className="btn primary" to="/signup">Create your Fyber Cable</Link>
            <Link className="btn ghost" to="/login">Log in</Link>
          </>
        )}
      </div>
      <ul className="features">
        <li><strong>FyberFlix Number</strong><span>A permanent 9-digit ID you choose, like a SIM number. Not a username.</span></li>
        <li><strong>Fyber Cable</strong><span>Your channel name and web address: FyberFlix.zeaipc.in/yourname</span></li>
        <li><strong>Private by design</strong><span>Only an encrypted numeric face template is stored, never your photo.</span></li>
      </ul>
    </div>
  );
}
