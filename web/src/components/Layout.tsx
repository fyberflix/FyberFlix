import { Link, NavLink, Outlet } from "react-router-dom";
import { useAuth } from "../auth";

export default function Layout() {
  const { status, user } = useAuth();
  return (
    <>
      <header className="top">
        <Link to="/" className="brand" aria-label="FyberFlix home">
          <span className="logo" aria-hidden="true">F</span>
          <span>FyberFlix</span>
        </Link>
        <nav aria-label="Main">
          {status === "in" && user ? (
            <NavLink to="/account" className="btn small">
              @{user.fyber_cable_name}
            </NavLink>
          ) : status === "loading" ? null : (
            <>
              <NavLink to="/login" className="btn small ghost">Log in</NavLink>
              <NavLink to="/signup" className="btn small primary">Sign up</NavLink>
            </>
          )}
        </nav>
      </header>
      <main id="main">
        <Outlet />
      </main>
      <footer className="foot">
        <p>© ZEAIPC · Zikr-e-Ameen Innovations &amp; Programming Corporation</p>
        <p>Reoti, Ballia, Uttar Pradesh 277209, India</p>
      </footer>
    </>
  );
}
