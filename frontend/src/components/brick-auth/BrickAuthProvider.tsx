import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from "react";
import { useRouter } from "@tanstack/react-router";

/* ─── Constants ─── */
const API_URL = "http://localhost:8080/api/v1";
const SESSION_KEY = "brick_session";
const ACTIVE_ORG_KEY = "brick_active_org";
// Refresh the access token when it has < 3 minutes remaining
const REFRESH_THRESHOLD_MS = 3 * 60 * 1000;

/* ─── TypeScript Interfaces ─── */

/** Mirrors Go backend models.User */
export interface BrickUser {
  id: string;
  email: string;
  name: string;
  role: "admin" | "user" | "auditor";
  active: boolean;
  created_at: string;
  updated_at: string;
}

/** Mirrors Go backend ledger.Identity */
export interface FabricIdentity {
  userId: string;
  orgId: string;
  role: string;
  status: "active" | "suspended" | "revoked";
  identityHash: string;
  mspId: string;
  attributes: Record<string, string>;
  createdAt: string;
  updatedAt: string;
}

/** Full client-side session stored in localStorage */
export interface BrickSession {
  token: string;
  user: BrickUser;
  identity: FabricIdentity | null;
}

/** What useBrickAuth() exposes to consumers */
export interface BrickAuthContextType {
  session: BrickSession | null;
  user: BrickUser | null;
  token: string | null;
  activeOrg: string;
  isLoading: boolean;
  isRevoked: boolean;
  requestOtp: (email: string, name?: string, orgId?: string) => Promise<void>;
  verifyOtp: (email: string, code: string, orgId?: string) => Promise<void>;
  switchOrg: (orgId: string) => void;
  logout: () => void;
}

/* ─── Context ─── */
const BrickAuthContext = createContext<BrickAuthContextType | undefined>(
  undefined
);

/* ─── JWT Helpers (client-side only — no crypto, just parsing) ─── */
function decodeJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const [, payloadB64] = token.split(".");
    return JSON.parse(atob(payloadB64.replace(/-/g, "+").replace(/_/g, "/")));
  } catch {
    return null;
  }
}

function tokenExpiresAt(token: string): number {
  const payload = decodeJwtPayload(token);
  if (!payload || typeof payload.exp !== "number") return 0;
  return payload.exp * 1000; // convert to ms
}

function isTokenValid(token: string): boolean {
  return tokenExpiresAt(token) > Date.now() + 1000;
}

/* ─── BrickAuthProvider ─── */
export function BrickAuthProvider({
  children,
}: {
  children: React.ReactNode;
}) {
  const [session, setSession] = useState<BrickSession | null>(null);
  const [activeOrg, setActiveOrg] = useState<string>("Org1");
  const [isLoading, setIsLoading] = useState(true);
  const [isRevoked, setIsRevoked] = useState(false);
  const refreshTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const router = useRouter();

  /* ─ Silent token refresh ─ */
  const silentRefresh = useCallback(async (): Promise<string | null> => {
    try {
      const res = await fetch(`${API_URL}/auth/refresh`, {
        method: "POST",
        credentials: "include", // sends HttpOnly brick_refresh_token cookie
        headers: { "Content-Type": "application/json" },
      });
      if (!res.ok) return null;
      const data = await res.json();
      return data.token ?? null;
    } catch {
      return null;
    }
  }, []);

  /* ─ Schedule next auto-refresh ─ */
  const scheduleRefresh = useCallback(
    (token: string) => {
      if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
      const expiresAt = tokenExpiresAt(token);
      const delay = Math.max(expiresAt - Date.now() - REFRESH_THRESHOLD_MS, 0);

      refreshTimerRef.current = setTimeout(async () => {
        const newToken = await silentRefresh();
        if (newToken) {
          setSession((prev) => {
            if (!prev) return prev;
            const updated = { ...prev, token: newToken };
            localStorage.setItem(SESSION_KEY, JSON.stringify(updated));
            scheduleRefresh(newToken);
            return updated;
          });
        } else {
          // Refresh failed — session expired or revoked
          clearSession();
        }
      }, delay);
    },
    [silentRefresh]
  );

  const clearSession = useCallback(() => {
    setSession(null);
    localStorage.removeItem(SESSION_KEY);
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
  }, []);

  /* ─ Restore session on mount ─ */
  useEffect(() => {
    const stored = localStorage.getItem(SESSION_KEY);
    const storedOrg = localStorage.getItem(ACTIVE_ORG_KEY);
    if (storedOrg) setActiveOrg(storedOrg);

    (async () => {
      if (stored) {
        try {
          const parsed: BrickSession = JSON.parse(stored);

          if (isTokenValid(parsed.token)) {
            // Token still valid — restore immediately and schedule refresh
            setSession(parsed);
            scheduleRefresh(parsed.token);
          } else {
            // Token expired — attempt silent refresh via cookie
            const newToken = await silentRefresh();
            if (newToken) {
              const refreshed = { ...parsed, token: newToken };
              setSession(refreshed);
              localStorage.setItem(SESSION_KEY, JSON.stringify(refreshed));
              scheduleRefresh(newToken);
            } else {
              localStorage.removeItem(SESSION_KEY);
            }
          }
        } catch {
          localStorage.removeItem(SESSION_KEY);
        }
      }
      setIsLoading(false);
    })();

    return () => {
      if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
    };
  }, [scheduleRefresh, silentRefresh]);

  /* ─ requestOtp ─ */
  const requestOtp = useCallback(
    async (email: string, name = "", orgId = "Org1") => {
      setIsLoading(true);
      try {
        const res = await fetch(`${API_URL}/auth/request-otp`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, name, orgId }),
        });
        const data = await res.json();
        if (!res.ok)
          throw new Error(data.message ?? "Failed to send verification code");
      } finally {
        setIsLoading(false);
      }
    },
    []
  );

  /* ─ verifyOtp ─ */
  const verifyOtp = useCallback(
    async (email: string, code: string, orgId?: string) => {
      setIsLoading(true);
      const resolvedOrg = orgId ?? activeOrg;
      try {
        const res = await fetch(`${API_URL}/auth/verify-otp`, {
          method: "POST",
          credentials: "include", // receive HttpOnly refresh cookie
          headers: {
            "Content-Type": "application/json",
            "X-Org-ID": resolvedOrg,
          },
          body: JSON.stringify({ email, code }),
        });
        const data = await res.json();
        if (!res.ok)
          throw new Error(data.message ?? "Invalid verification code");

        // Check for revoked/suspended identity
        if (
          data.identity?.status === "revoked" ||
          data.identity?.status === "suspended"
        ) {
          setIsRevoked(true);
          throw new Error(
            `Identity is ${data.identity.status} on the blockchain ledger`
          );
        }

        const newSession: BrickSession = {
          token: data.token,
          user: data.user,
          identity: data.identity ?? null,
        };

        setSession(newSession);
        localStorage.setItem(SESSION_KEY, JSON.stringify(newSession));
        setActiveOrg(resolvedOrg);
        localStorage.setItem(ACTIVE_ORG_KEY, resolvedOrg);
        scheduleRefresh(data.token);

        router.navigate({ to: "/dashboard" });
      } finally {
        setIsLoading(false);
      }
    },
    [activeOrg, router, scheduleRefresh]
  );

  /* ─ switchOrg ─ */
  const switchOrg = useCallback((orgId: string) => {
    setActiveOrg(orgId);
    localStorage.setItem(ACTIVE_ORG_KEY, orgId);
  }, []);

  /* ─ logout ─ */
  const logout = useCallback(() => {
    clearSession();
    setIsRevoked(false);
    router.navigate({ to: "/" });
  }, [clearSession, router]);

  return (
    <BrickAuthContext.Provider
      value={{
        session,
        user: session?.user ?? null,
        token: session?.token ?? null,
        activeOrg,
        isLoading,
        isRevoked,
        requestOtp,
        verifyOtp,
        switchOrg,
        logout,
      }}
    >
      {children}
    </BrickAuthContext.Provider>
  );
}

/* ─── useBrickAuth hook ─── */
export function useBrickAuth(): BrickAuthContextType {
  const ctx = useContext(BrickAuthContext);
  if (!ctx)
    throw new Error("useBrickAuth must be used within <BrickAuthProvider>");
  return ctx;
}
