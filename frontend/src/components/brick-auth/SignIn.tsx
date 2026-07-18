import { useState } from "react";
import { useBrickAuth } from "./BrickAuthProvider";
import { Mail, Blocks, Loader2, KeyRound, RefreshCw, Wallet } from "lucide-react";

/* ─── Props ─── */
interface SignInProps {
  onSuccess?: () => void;
  onSwitchToSignUp?: () => void;
}

type Step = "email" | "otp";

/* ─── SignIn Component ─── */
export function SignIn({ onSuccess, onSwitchToSignUp }: SignInProps) {
  const { requestOtp, verifyOtp, isLoading } = useBrickAuth();
  const [step, setStep] = useState<Step>("email");
  const [email, setEmail] = useState("");
  const [otp, setOtp] = useState(["", "", "", "", "", ""]);
  const [error, setError] = useState("");
  const [successMsg, setSuccessMsg] = useState("");

  /* ── Handlers ── */
  const handleRequestOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    try {
      await requestOtp(email);
      setSuccessMsg(`Code sent to ${email}`);
      setStep("otp");
    } catch (err: any) {
      setError(err.message ?? "Failed to send verification code");
    }
  };

  const handleVerifyOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    const code = otp.join("");
    if (code.length !== 6) {
      setError("Please enter all 6 digits");
      return;
    }
    try {
      await verifyOtp(email, code);
      onSuccess?.();
    } catch (err: any) {
      setError(err.message ?? "Invalid or expired code");
    }
  };

  const handleOtpChange = (index: number, value: string) => {
    if (!/^\d?$/.test(value)) return;
    const updated = [...otp];
    updated[index] = value;
    setOtp(updated);
    if (value && index < 5)
      document.getElementById(`signin-otp-${index + 1}`)?.focus();
  };

  const handleOtpKeyDown = (index: number, e: React.KeyboardEvent) => {
    if (e.key === "Backspace" && !otp[index] && index > 0)
      document.getElementById(`signin-otp-${index - 1}`)?.focus();
  };

  const handleResend = async () => {
    setError("");
    setSuccessMsg("");
    setOtp(["", "", "", "", "", ""]);
    try {
      await requestOtp(email);
      setSuccessMsg("New code sent!");
    } catch (err: any) {
      setError(err.message);
    }
  };

  return (
    <div className="w-full max-w-md mx-auto">
      <div className="rounded-2xl border border-border bg-card p-8 shadow-sm animate-fade-up">

        {/* ── Logo ── */}
        <div className="flex flex-col items-center gap-3 text-center mb-8">
          <div className="flex items-center gap-2">
            <div className="grid h-9 w-9 place-items-center rounded-lg bg-foreground text-background">
              <Blocks className="h-5 w-5" strokeWidth={2.5} />
            </div>
            <span className="text-xl font-bold tracking-tight">brick</span>
          </div>

          {step === "email" ? (
            <>
              <h1 className="text-2xl font-semibold tracking-tight text-foreground">
                Welcome back
              </h1>
              <p className="text-sm text-muted-foreground">
                Sign in to your blockchain identity
              </p>
            </>
          ) : (
            <>
              <div className="mt-2 flex h-12 w-12 items-center justify-center rounded-full bg-primary/10">
                <KeyRound className="h-6 w-6 text-primary" />
              </div>
              <h1 className="text-2xl font-semibold tracking-tight text-foreground">
                Check your email
              </h1>
              <p className="text-sm text-muted-foreground">
                Enter the 6-digit code sent to{" "}
                <span className="font-medium text-foreground">{email}</span>
              </p>
            </>
          )}
        </div>

        {/* ── Alerts ── */}
        {error && (
          <div className="mb-5 rounded-lg bg-destructive/10 px-4 py-3 text-sm text-destructive border border-destructive/20">
            {error}
          </div>
        )}
        {successMsg && (
          <div className="mb-5 rounded-lg bg-green-500/10 px-4 py-3 text-sm text-green-700 dark:text-green-400 border border-green-500/20">
            {successMsg}
          </div>
        )}

        {/* ── Email Step ── */}
        {step === "email" && (
          <div className="space-y-5">
            <form onSubmit={handleRequestOtp} className="space-y-4">
              <div className="space-y-2">
                <label className="text-sm font-medium text-foreground">
                  Email address
                </label>
                <div className="relative">
                  <Mail className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
                  <input
                    id="brick-signin-email"
                    type="email"
                    required
                    autoFocus
                    className="w-full rounded-lg border border-input bg-background py-2 pl-10 pr-3 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20 transition"
                    placeholder="you@company.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                  />
                </div>
              </div>

              <button
                type="submit"
                id="brick-signin-submit"
                disabled={isLoading || !email}
                className="mt-1 flex w-full items-center justify-center gap-2 rounded-lg bg-foreground px-4 py-2.5 text-sm font-medium text-background transition hover:bg-foreground/90 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isLoading ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  "Continue with Email →"
                )}
              </button>
            </form>

            {/* ── Web3 placeholder ── */}
            <div className="relative flex items-center gap-3">
              <div className="flex-1 border-t border-border" />
              <span className="text-xs text-muted-foreground">or</span>
              <div className="flex-1 border-t border-border" />
            </div>

            <button
              type="button"
              disabled
              title="Web3 wallet sign-in coming soon"
              className="flex w-full items-center justify-center gap-2 rounded-lg border border-border bg-background px-4 py-2.5 text-sm font-medium text-muted-foreground cursor-not-allowed opacity-50 transition"
            >
              <Wallet className="h-4 w-4" />
              Connect Wallet
              <span className="ml-auto rounded-full bg-muted px-2 py-0.5 text-[10px] font-medium text-muted-foreground">
                Soon
              </span>
            </button>
          </div>
        )}

        {/* ── OTP Step ── */}
        {step === "otp" && (
          <form onSubmit={handleVerifyOtp} className="space-y-6">
            <div className="flex justify-center gap-2">
              {otp.map((digit, i) => (
                <input
                  key={i}
                  id={`signin-otp-${i}`}
                  type="text"
                  inputMode="numeric"
                  maxLength={1}
                  value={digit}
                  autoFocus={i === 0}
                  onChange={(e) => handleOtpChange(i, e.target.value)}
                  onKeyDown={(e) => handleOtpKeyDown(i, e)}
                  className="h-12 w-10 rounded-lg border border-input bg-background text-center text-lg font-semibold text-foreground focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20 transition"
                />
              ))}
            </div>

            <button
              type="submit"
              id="brick-signin-verify"
              disabled={isLoading || otp.join("").length < 6}
              className="flex w-full items-center justify-center gap-2 rounded-lg bg-foreground px-4 py-2.5 text-sm font-medium text-background transition hover:bg-foreground/90 disabled:opacity-50"
            >
              {isLoading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <>
                  <Blocks className="h-4 w-4" /> Sign In
                </>
              )}
            </button>

            <div className="flex items-center justify-between text-sm">
              <button
                type="button"
                onClick={() => {
                  setStep("email");
                  setError("");
                  setSuccessMsg("");
                }}
                className="text-muted-foreground hover:text-foreground transition"
              >
                ← Change email
              </button>
              <button
                type="button"
                onClick={handleResend}
                disabled={isLoading}
                className="flex items-center gap-1 text-primary hover:underline disabled:opacity-50"
              >
                <RefreshCw className="h-3.5 w-3.5" /> Resend code
              </button>
            </div>
          </form>
        )}

        {/* ── Switch to SignUp ── */}
        {onSwitchToSignUp && (
          <div className="mt-6 text-center text-sm">
            <span className="text-muted-foreground">Don't have an account? </span>
            <button
              id="brick-switch-signup"
              onClick={onSwitchToSignUp}
              className="font-medium text-primary hover:underline"
            >
              Create one
            </button>
          </div>
        )}
      </div>

      <p className="mt-4 text-center text-xs text-muted-foreground">
        🔐 Identity secured on Hyperledger Fabric
      </p>
    </div>
  );
}
