import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect } from "react";
import { useBrickAuth, FabricIdentity, OrganizationSwitcher } from "../components/brick-auth";
import {
  LogOut, User, Shield, Key, Network, Activity, FileText, Lock,
  Blocks, Hash, Calendar, CheckCircle2
} from "lucide-react";

export const Route = createFileRoute("/dashboard")({
  component: Dashboard,
});

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-start justify-between gap-3 border-b border-border pb-3 last:border-0 last:pb-0">
      <span className="text-sm text-muted-foreground shrink-0">{label}</span>
      <span className="text-sm font-medium text-right break-all">{value || "—"}</span>
    </div>
  );
}

function FabricCard({ identity }: { identity: FabricIdentity }) {
  return (
    <div className="animate-fade-up rounded-xl border border-border bg-card p-6 shadow-sm md:col-span-2 lg:col-span-1" style={{ animationDelay: "0.3s" }}>
      <div className="flex items-center gap-3 mb-5">
        <div className="rounded-lg bg-amber-500/10 p-2 text-amber-500">
          <Key className="h-5 w-5" />
        </div>
        <h3 className="font-semibold">On-Chain Identity</h3>
        <span className="ml-auto rounded-full bg-green-500/10 px-2 py-0.5 text-xs font-medium text-green-600 dark:text-green-400">
          {identity.status}
        </span>
      </div>

      <div className="space-y-3">
        <InfoRow label="MSP ID" value={identity.mspId} />
        <InfoRow label="Org" value={identity.orgId} />
        <InfoRow label="Role (ACL)" value={identity.role} />
        <InfoRow label="Enrolled" value={new Date(identity.createdAt).toLocaleDateString()} />
      </div>

      <div className="mt-4">
        <div className="flex items-center gap-2 mb-2">
          <Hash className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-medium">Identity Hash</span>
          <Lock className="h-3.5 w-3.5 text-muted-foreground ml-auto" />
        </div>
        <div className="rounded-lg bg-muted p-3">
          <pre className="text-[10px] text-muted-foreground whitespace-pre-wrap break-all leading-relaxed">
            {identity.identityHash}
          </pre>
        </div>
        <p className="mt-2 text-xs text-muted-foreground flex items-start gap-1">
          <FileText className="h-3.5 w-3.5 shrink-0 mt-0.5" />
          Cryptographic hash recorded immutably on the Hyperledger Fabric ledger.
        </p>
      </div>
    </div>
  );
}

function Dashboard() {
  const { session, logout, isLoading } = useBrickAuth();
  const navigate = useNavigate();
  const user = session?.user;
  const identity = session?.identity;

  useEffect(() => {
    if (!isLoading && !session) navigate({ to: "/login" });
  }, [session, isLoading, navigate]);

  if (isLoading || !user) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Top nav */}
      <header className="sticky top-0 z-40 border-b border-border bg-background/95 backdrop-blur">
        <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
          <div className="flex items-center gap-2.5">
            <div className="grid h-8 w-8 place-items-center rounded-lg bg-foreground text-background">
              <Blocks className="h-4 w-4" />
            </div>
            <span className="text-lg font-bold tracking-tight">Brick</span>
          </div>
          <div className="flex items-center gap-4">
            <OrganizationSwitcher className="hidden sm:inline-flex" />
            <span className="hidden sm:block text-sm text-muted-foreground">{user.email}</span>
            <button
              onClick={logout}
              className="flex items-center gap-2 rounded-lg border border-input bg-background px-3 py-1.5 text-sm font-medium transition hover:bg-accent"
            >
              <LogOut className="h-4 w-4" /> Logout
            </button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8 space-y-8">
        {/* Welcome */}
        <div className="animate-fade-up">
          <h1 className="text-3xl font-bold tracking-tight">
            Welcome, {user.name || user.email.split("@")[0]}
          </h1>
          <p className="mt-1 text-muted-foreground">
            Your decentralized identity and session details.
          </p>
        </div>

        {/* Status row */}
        <div className="grid gap-4 sm:grid-cols-3">
          {[
            { icon: CheckCircle2, label: "Account Status", value: user.active ? "Active" : "Inactive", color: "text-green-500" },
            { icon: Shield, label: "Role", value: user.role, color: "text-primary" },
            { icon: Calendar, label: "Member Since", value: new Date(user.created_at).toLocaleDateString(), color: "text-muted-foreground" },
          ].map(({ icon: Icon, label, value, color }) => (
            <div key={label} className="rounded-xl border border-border bg-card p-5 flex items-center gap-4">
              <div className={`rounded-lg bg-muted p-2 ${color}`}>
                <Icon className="h-5 w-5" />
              </div>
              <div>
                <p className="text-xs text-muted-foreground">{label}</p>
                <p className="text-sm font-semibold capitalize">{value}</p>
              </div>
            </div>
          ))}
        </div>

        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
          {/* User Identity Card */}
          <div className="animate-fade-up rounded-xl border border-border bg-card p-6 shadow-sm" style={{ animationDelay: "0.1s" }}>
            <div className="flex items-center gap-3 mb-5">
              <div className="rounded-lg bg-primary/10 p-2 text-primary">
                <User className="h-5 w-5" />
              </div>
              <h3 className="font-semibold">Account Details</h3>
            </div>
            <div className="space-y-3">
              <InfoRow label="User ID" value={user.id} />
              <InfoRow label="Email" value={user.email} />
              <InfoRow label="Name" value={user.name} />
              <InfoRow label="Role" value={user.role} />
            </div>
          </div>

          {/* Network Details */}
          <div className="animate-fade-up rounded-xl border border-border bg-card p-6 shadow-sm" style={{ animationDelay: "0.2s" }}>
            <div className="flex items-center gap-3 mb-5">
              <div className="rounded-lg bg-blue-500/10 p-2 text-blue-500">
                <Network className="h-5 w-5" />
              </div>
              <h3 className="font-semibold">Fabric Network</h3>
            </div>
            <div className="space-y-3">
              <InfoRow label="Mode" value="cloud" />
              <InfoRow
                label="Connection"
                value="Connected"
              />
              <InfoRow label="Chaincode" value="brick-identity" />
              <InfoRow label="Channel" value={identity?.orgId ? `${identity.orgId}-channel` : "defaultchannel"} />
            </div>
            <div className="mt-3 flex items-center gap-1.5 text-xs text-green-500 font-medium">
              <Activity className="h-3.5 w-3.5" /> Ledger healthy
            </div>
          </div>

          {/* Fabric identity or placeholder */}
          {identity ? (
            <FabricCard identity={identity} />
          ) : (
            <div className="animate-fade-up rounded-xl border border-dashed border-border bg-card/50 p-6 flex flex-col items-center justify-center text-center gap-3" style={{ animationDelay: "0.3s" }}>
              <Blocks className="h-8 w-8 text-muted-foreground/50" />
              <p className="text-sm text-muted-foreground">
                Fabric identity not yet linked.<br />Your account is authenticated via OTP.
              </p>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
