import React, { createContext, useContext, useState, useEffect } from "react";
import { useRouter } from "@tanstack/react-router";

const API_URL = "http://localhost:8080/api/v1";

// Matches Go backend User model
export interface BrickUser {
  id: string;
  email: string;
  name: string;
  role: string;
  active: boolean;
  created_at: string;
  updated_at: string;
}

// Matches Go backend IdentityResponse (Fabric ledger)
export interface FabricIdentity {
  userId: string;
  orgId: string;
  role: string;
  status: string;
  identityHash: string;
  mspId: string;
  attributes: Record<string, string>;
  createdAt: string;
  updatedAt: string;
}

export interface AuthSession {
  token: string;
  user: BrickUser;
  identity: FabricIdentity | null;
}

interface AuthContextType {
  session: AuthSession | null;
  isLoading: boolean;
  requestOtp: (email: string, name?: string, orgId?: string) => Promise<void>;
  verifyOtp: (email: string, code: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<AuthSession | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const router = useRouter();

  // Restore session from localStorage on mount
  useEffect(() => {
    const stored = localStorage.getItem("brick_session");
    if (stored) {
      try {
        const parsed: AuthSession = JSON.parse(stored);
        // Check if JWT is not expired
        const payload = JSON.parse(atob(parsed.token.split(".")[1]));
        if (payload.exp * 1000 > Date.now()) {
          setSession(parsed);
        } else {
          localStorage.removeItem("brick_session");
        }
      } catch {
        localStorage.removeItem("brick_session");
      }
    }
    setIsLoading(false);
  }, []);

  const requestOtp = async (email: string, name = "", orgId = "Org1") => {
    setIsLoading(true);
    try {
      const res = await fetch(`${API_URL}/auth/request-otp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, name, orgId }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || "Failed to send OTP");
    } finally {
      setIsLoading(false);
    }
  };

  const verifyOtp = async (email: string, code: string) => {
    setIsLoading(true);
    try {
      const res = await fetch(`${API_URL}/auth/verify-otp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, code }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || "Invalid verification code");

      const newSession: AuthSession = {
        token: data.token,
        user: data.user,
        identity: data.identity ?? null,
      };
      setSession(newSession);
      localStorage.setItem("brick_session", JSON.stringify(newSession));
      router.navigate({ to: "/dashboard" });
    } finally {
      setIsLoading(false);
    }
  };

  const logout = () => {
    setSession(null);
    localStorage.removeItem("brick_session");
    router.navigate({ to: "/" });
  };

  return (
    <AuthContext.Provider value={{ session, isLoading, requestOtp, verifyOtp, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
