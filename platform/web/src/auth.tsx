import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

import { api, clearToken, getRuntimeEnvironment, getStoredToken, setRuntimeEnvironment, storeToken, type RuntimeEnvironment } from "./api";
import type { AuthUser } from "./types";

type AuthContextValue = {
  user: AuthUser | null;
  environment: RuntimeEnvironment;
  loading: boolean;
  error: string | null;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string) => Promise<void>;
  logout: () => void;
  setEnvironment: (environment: RuntimeEnvironment) => void;
};

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [environment, setEnvironmentState] = useState<RuntimeEnvironment>(getRuntimeEnvironment());
  const [loading, setLoading] = useState(Boolean(getStoredToken()));
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadUser() {
      if (!getStoredToken()) {
        setLoading(false);
        return;
      }
      try {
        const response = await api.me();
        setUser(response.user);
      } catch {
        clearToken();
        setUser(null);
      } finally {
        setLoading(false);
      }
    }
    void loadUser();
  }, [environment]);

  async function authenticate(mode: "login" | "register", email: string, password: string) {
    setLoading(true);
    setError(null);
    try {
      const response = mode === "login" ? await api.login(email, password) : await api.register(email, password);
      storeToken(response.token);
      setUser(response.user);
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Authentication failed.");
    } finally {
      setLoading(false);
    }
  }

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      environment,
      loading,
      error,
      login: (email, password) => authenticate("login", email, password),
      register: (email, password) => authenticate("register", email, password),
      logout: () => {
        clearToken();
        setUser(null);
      },
      setEnvironment: (next) => {
        setRuntimeEnvironment(next);
        setEnvironmentState(next);
        if (next !== environment) {
          clearToken();
          setUser(null);
        }
      }
    }),
    [environment, error, loading, user]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used inside AuthProvider");
  return value;
}
