import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api, type Tokens, type User } from "./api";
import {
  authed,
  clearTokens,
  hasStoredSession,
  onSessionCleared,
  refreshTokenForLogout,
  setTokens,
} from "./session";

type Status = "loading" | "out" | "in";
type Ctx = {
  status: Status;
  user: User | null;
  signIn: (tokens: Tokens, user: User) => void;
  signOut: () => Promise<void>;
};

const AuthCtx = createContext<Ctx | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<Status>(hasStoredSession() ? "loading" : "out");
  const [user, setUser] = useState<User | null>(null);

  useEffect(() => {
    let live = true;
    if (hasStoredSession()) {
      authed<{ user: User }>("/v1/me")
        .then((r) => {
          if (live) {
            setUser(r.user);
            setStatus("in");
          }
        })
        .catch(() => {
          if (live) setStatus("out");
        });
    }
    const off = onSessionCleared(() => {
      setUser(null);
      setStatus("out");
    });
    return () => {
      live = false;
      off();
    };
  }, []);

  const signIn = useCallback((tokens: Tokens, u: User) => {
    setTokens(tokens);
    setUser(u);
    setStatus("in");
  }, []);

  const signOut = useCallback(async () => {
    const rt = refreshTokenForLogout();
    if (rt) {
      try {
        await api<void>("/v1/logout", { json: { refresh_token: rt } });
      } catch {
        /* still log out locally */
      }
    }
    clearTokens();
  }, []);

  const value = useMemo(() => ({ status, user, signIn, signOut }), [status, user, signIn, signOut]);
  return <AuthCtx.Provider value={value}>{children}</AuthCtx.Provider>;
}

export function useAuth(): Ctx {
  const c = useContext(AuthCtx);
  if (!c) throw new Error("useAuth outside AuthProvider");
  return c;
}
