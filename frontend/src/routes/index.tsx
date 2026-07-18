import { createFileRoute, Link } from "@tanstack/react-router";
import {
  ArrowRight,
  ChevronDown,
  Shield,
  KeyRound,
  Users,
  Wallet,
  Fingerprint,
  Blocks,
  Check,
  Github,
  Twitter,
  Play,
  Mail,
  Smartphone,
  Link2,
  Bot,
  Lock,
  Key,
  Server,
  Building2,
  UserPlus,
  CreditCard,
  Zap,
  Puzzle,
} from "lucide-react";

export const Route = createFileRoute("/")({
  component: Landing,
});

/* ------------------------------------------------------------------ */
/* Logo                                                                */
/* ------------------------------------------------------------------ */
function BrickMark({ light = false }: { light?: boolean }) {
  return (
    <div className="flex items-center gap-2">
      <div
        className={`grid h-6 w-6 place-items-center rounded-md ${
          light ? "bg-background text-foreground" : "bg-brick text-primary-foreground"
        }`}
      >
        <Blocks className="h-3.5 w-3.5" strokeWidth={2.5} />
      </div>
      <span className={`text-[17px] font-bold tracking-tight ${light ? "text-background" : ""}`}>
        brick
      </span>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Announcement + Nav                                                  */
/* ------------------------------------------------------------------ */
function TopBar() {
  return (
    <>
      <div className="bg-foreground text-background">
        <div className="mx-auto flex max-w-7xl items-center justify-center gap-3 px-4 py-2.5 text-[13px]">
          <span className="opacity-80">Brick raises $50M Series C</span>
          <a href="#" className="inline-flex items-center gap-1 font-medium hover:opacity-80">
            Learn more <ArrowRight className="h-3 w-3" />
          </a>
        </div>
      </div>
      <header className="sticky top-4 z-40 px-4 animate-fade-soft">
        <div className="mx-auto flex max-w-6xl items-center justify-between rounded-full border border-border bg-background/85 px-5 py-2.5 shadow-[0_2px_20px_-8px_rgba(0,0,0,0.08)] backdrop-blur">
          <div className="flex items-center gap-8">
            <BrickMark />
            <nav className="hidden items-center gap-1 md:flex">
              {["Products", "Docs", "Changelog", "Company"].map((n) => (
                <button
                  key={n}
                  className="inline-flex items-center gap-1 rounded-full px-3 py-1.5 text-sm text-foreground/80 hover:bg-muted"
                >
                  {n} <ChevronDown className="h-3 w-3 opacity-60" />
                </button>
              ))}
              <a href="#pricing" className="rounded-full px-3 py-1.5 text-sm text-foreground/80 hover:bg-muted">
                Pricing
              </a>
            </nav>
          </div>
          <div className="flex items-center gap-3">
            <Link to="/login" className="hidden text-sm font-medium hover:opacity-80 sm:inline">
              Sign in
            </Link>
            <Link
              to="/signup"
              className="inline-flex items-center gap-1.5 rounded-full bg-foreground px-4 py-1.5 text-sm font-medium text-background hover:opacity-90"
            >
              Start building <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          </div>
        </div>
      </header>
    </>
  );
}

/* ------------------------------------------------------------------ */
/* Hero                                                                */
/* ------------------------------------------------------------------ */
function Hero() {
  return (
    <section className="relative overflow-hidden">
      <div
        aria-hidden
        className="absolute inset-0 opacity-[0.45]"
        style={{
          backgroundImage:
            "linear-gradient(to right, oklch(0.85 0.02 60 / 0.5) 1px, transparent 1px), linear-gradient(to bottom, oklch(0.85 0.02 60 / 0.5) 1px, transparent 1px)",
          backgroundSize: "56px 56px",
          maskImage:
            "radial-gradient(ellipse at 50% 35%, black 30%, transparent 75%)",
        }}
      />
      <div
        aria-hidden
        className="pointer-events-none absolute left-1/2 top-32 h-[540px] w-[900px] -translate-x-1/2 rounded-full blur-3xl"
        style={{
          background:
            "radial-gradient(closest-side, oklch(0.72 0.16 45 / 0.22), transparent)",
        }}
      />
      <div className="relative mx-auto max-w-6xl px-4 pt-24 pb-28 text-center sm:pt-32">
        <h1 className="mx-auto max-w-5xl text-5xl font-black tracking-[-0.03em] sm:text-6xl md:text-7xl animate-fade-up">
          More than authentication,
          <br />
          Complete User Management
        </h1>
        <p
          className="mx-auto mt-7 max-w-2xl text-lg text-muted-foreground animate-fade-up"
          style={{ animationDelay: "80ms" }}
        >
          Need more than sign-in? Brick gives you full-stack auth and user management on the
          blockchain — so you can launch faster, scale easier, and stay focused on building your
          business.
        </p>
        <div
          className="mt-10 flex flex-wrap items-center justify-center gap-3 animate-fade-up"
          style={{ animationDelay: "160ms" }}
        >
          <a
            href="#"
            className="inline-flex items-center gap-1.5 rounded-full bg-brick px-5 py-3 text-sm font-semibold text-primary-foreground shadow-sm transition hover:brightness-95"
          >
            Start building for free
          </a>
          <a
            href="#"
            className="inline-flex items-center gap-1.5 rounded-full border border-border bg-background px-5 py-3 text-sm font-semibold hover:bg-muted"
          >
            Build with agents <ChevronDown className="h-4 w-4" />
          </a>
        </div>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ */
/* Trust logos                                                         */
/* ------------------------------------------------------------------ */
function TrustLogos() {
  const logos = ["Browserbase", "braintrust", "Higgsfield", "Consensus"];
  return (
    <section className="border-y border-border bg-background">
      <div className="mx-auto grid max-w-6xl grid-cols-2 items-center gap-8 px-4 py-10 md:grid-cols-5">
        <p className="text-sm text-muted-foreground md:col-span-1">
          Trusted by fast-growing
          <br />
          companies around the world.
        </p>
        {logos.map((n) => (
          <div
            key={n}
            className="text-center text-xl font-semibold tracking-tight text-foreground/80"
          >
            {n}
          </div>
        ))}
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ */
/* Components section (light)                                          */
/* ------------------------------------------------------------------ */
function ComponentsSection() {
  return (
    <section className="mx-auto max-w-6xl px-4 py-24">
      <div className="grid items-center gap-14 md:grid-cols-2">
        <div>
          <p className="text-sm font-semibold text-brick">Brick Components</p>
          <h2 className="mt-3 text-4xl font-bold tracking-tight sm:text-5xl">
            Pixel-perfect UIs,
            <br /> embedded in minutes
          </h2>
          <p className="mt-5 max-w-md text-muted-foreground">
            Drop-in UI components for authentication, profile management, organization management,
            and billing. Match to your brand with any CSS library, then deploy to your own domain.
          </p>
          <a href="#" className="mt-6 inline-flex items-center gap-1 text-sm font-semibold hover:opacity-80">
            Explore all components <ArrowRight className="h-3.5 w-3.5" />
          </a>

          <div className="mt-10 divide-y divide-border rounded-xl border border-border bg-card">
            {[
              { label: "USER AUTHENTICATION", open: true },
              { label: "B2B AUTHENTICATION" },
              { label: "BILLING" },
            ].map((row) => (
              <div key={row.label} className="px-4 py-3">
                <button className="flex w-full items-center justify-between text-left">
                  <span className="flex items-center gap-3 text-xs font-semibold tracking-widest">
                    <span
                      className={`h-2 w-2 rounded-full ${
                        row.open ? "bg-brick" : "border border-muted-foreground/40"
                      }`}
                    />
                    {row.label}
                  </span>
                  <ChevronDown className="h-4 w-4 opacity-60" />
                </button>
                {row.open && (
                  <div className="mt-3 pl-5">
                    <p className="text-sm text-muted-foreground">
                      Add user <code className="text-brick">&lt;SignUp /&gt;</code> and{" "}
                      <code className="text-brick">&lt;SignIn /&gt;</code>, provide account access
                      through a dropdown menu, and manage profile and security settings.
                    </p>
                    <ul className="mt-3 space-y-1 font-mono text-sm">
                      <li className="text-brick">&lt;SignUp /&gt;</li>
                      <li>&lt;SignIn /&gt;</li>
                      <li>&lt;UserButton /&gt;</li>
                      <li>&lt;UserProfile /&gt;</li>
                      <li>&lt;Waitlist /&gt;</li>
                    </ul>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Sign-up card preview */}
        <div className="relative">
          <div className="absolute -inset-8 rounded-3xl bg-gradient-to-tr from-brick/10 via-transparent to-brick/5 blur-2xl" />
          <div className="relative rounded-2xl border border-border bg-card p-8 shadow-[0_20px_60px_-20px_rgba(0,0,0,0.15)]">
            <div className="mb-5 flex items-center justify-between text-xs text-muted-foreground">
              <span>Secured by</span>
              <BrickMark />
            </div>
            <div className="mx-auto grid h-11 w-11 place-items-center rounded-xl bg-foreground text-background">
              <Blocks className="h-5 w-5" />
            </div>
            <h3 className="mt-4 text-center text-xl font-bold">Create your account</h3>
            <p className="mt-1 text-center text-sm text-muted-foreground">
              Welcome! Please fill in the details to get started.
            </p>
            <div className="mt-5 space-y-2">
              <div className="relative">
                <button className="flex w-full items-center justify-center gap-2 rounded-lg border border-border bg-background py-2.5 text-sm font-medium hover:bg-muted">
                  <span className="grid h-4 w-4 place-items-center rounded-sm bg-foreground text-[9px] font-bold text-background">
                    G
                  </span>
                  Continue with Google
                </button>
                <span className="absolute -top-2 right-2 rounded-md bg-brick-tint px-1.5 py-0.5 text-[10px] font-semibold text-brick">
                  Last used
                </span>
              </div>
              <button className="flex w-full items-center justify-center gap-2 rounded-lg border border-border bg-background py-2.5 text-sm font-medium hover:bg-muted">
                <Github className="h-4 w-4" /> Continue with GitHub
              </button>
            </div>
            <div className="my-4 flex items-center gap-3 text-xs text-muted-foreground">
              <div className="h-px flex-1 bg-border" /> or <div className="h-px flex-1 bg-border" />
            </div>
            <label className="text-xs font-medium">Email address</label>
            <input
              type="email"
              defaultValue="cameron.w"
              className="mt-1 w-full rounded-lg border border-border bg-background px-3 py-2.5 text-sm outline-none focus:ring-2 focus:ring-brick/30"
            />
            <label className="mt-3 block text-xs font-medium">Password</label>
            <input
              type="password"
              placeholder="Enter your password"
              className="mt-1 w-full rounded-lg border border-border bg-background px-3 py-2.5 text-sm outline-none focus:ring-2 focus:ring-brick/30"
            />
            <button className="mt-4 flex w-full items-center justify-center gap-1.5 rounded-lg bg-foreground py-2.5 text-sm font-semibold text-background hover:opacity-90">
              Continue <Play className="h-3 w-3 fill-current" />
            </button>
            <p className="mt-4 text-center text-xs text-muted-foreground">
              Already have an account? <a className="font-semibold text-foreground hover:underline">Sign in</a>
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ */
/* Dark auth features bento                                            */
/* ------------------------------------------------------------------ */
function DarkFeatureCard({
  title,
  desc,
  children,
  className = "",
}: {
  title: string;
  desc: string;
  children?: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={`relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.03] p-6 ${className}`}
    >
      <div className="flex h-40 items-center justify-center">{children}</div>
      <h3 className="mt-4 text-base font-semibold text-background">{title}</h3>
      <p className="mt-1.5 text-sm text-background/60">{desc}</p>
    </div>
  );
}

function AuthDarkSection() {
  return (
    <section
      className="relative overflow-hidden bg-foreground text-background"
      style={{
        clipPath:
          "polygon(0 40px, 50% 0, 100% 40px, 100% calc(100% - 40px), 50% 100%, 0 calc(100% - 40px))",
      }}
    >
      <div
        aria-hidden
        className="absolute inset-0 opacity-[0.15]"
        style={{
          backgroundImage:
            "linear-gradient(to right, oklch(1 0 0 / 0.35) 1px, transparent 1px), linear-gradient(to bottom, oklch(1 0 0 / 0.35) 1px, transparent 1px)",
          backgroundSize: "56px 56px",
          maskImage: "radial-gradient(ellipse at 50% 30%, black 30%, transparent 75%)",
        }}
      />
      <div className="relative mx-auto max-w-6xl px-4 py-32">
        <div className="text-center">
          <p className="text-sm font-semibold text-brick-soft">User authentication</p>
          <h2 className="mt-3 text-4xl font-bold tracking-tight sm:text-5xl">
            Everything you need for authentication
          </h2>
          <p className="mx-auto mt-4 max-w-xl text-background/70">
            Ever feel like authentication requirements change with the season? Brick keeps up with
            the latest trends and security best practices.
          </p>
          <a
            href="#"
            className="mt-6 inline-flex items-center gap-1.5 rounded-full bg-background px-4 py-2 text-sm font-semibold text-foreground hover:opacity-90"
          >
            Explore user authentication <ArrowRight className="h-3.5 w-3.5" />
          </a>
        </div>

        <div className="mt-14 grid gap-4 md:grid-cols-3">
          <DarkFeatureCard
            title="Multifactor Authentication"
            desc="Each user's self-serve multifactor settings are enforced automatically during sign-in."
          >
            <div className="flex gap-1.5">
              {Array.from({ length: 6 }).map((_, i) => (
                <div key={i} className="h-8 w-6 rounded-md bg-white/10" />
              ))}
            </div>
          </DarkFeatureCard>

          <DarkFeatureCard
            title="Session Management"
            desc="Brick manages the full session lifecycle, including critical security functionality like active device monitoring and session revocation."
          >
            <div className="grid h-24 w-24 place-items-center rounded-xl border border-white/10 bg-white/[0.03]">
              <Smartphone className="h-8 w-8 text-background/70" />
            </div>
          </DarkFeatureCard>

          <DarkFeatureCard
            title="Email and SMS one-time passcodes"
            desc="Fast and reliable one-time passcode delivery with built-in brute force prevention."
          >
            <div className="flex gap-2">
              {[Smartphone, Mail, Blocks, Server].map((I, i) => (
                <div
                  key={i}
                  className="grid h-14 w-14 place-items-center rounded-xl border border-white/10 bg-white/[0.03]"
                >
                  <I className="h-5 w-5 text-background/70" />
                </div>
              ))}
            </div>
          </DarkFeatureCard>

          <DarkFeatureCard
            title="Fraud and Abuse Prevention"
            desc="Reduce fraudulent sign-ups and free trial abuse by blocking high-risk disposable email domains."
          >
            <div className="w-full rounded-lg border border-white/10 bg-background/[0.03] p-3 text-xs">
              <div className="flex items-center gap-2">
                <Shield className="h-4 w-4 text-brick-soft" />
                <span className="text-background/80">Fraudulent sign-ups detected</span>
                <span className="ml-auto text-background/50">14:09</span>
              </div>
            </div>
          </DarkFeatureCard>

          <DarkFeatureCard
            title="Social Sign-On"
            desc="Add high-conversion Social Sign-on (SSO) to your application in minutes. 20+ options and growing."
          >
            <div className="relative h-24 w-24">
              <div className="absolute inset-0 grid place-items-center rounded-xl bg-white/[0.06]">
                <Link2 className="h-6 w-6" />
              </div>
              {[Github, Blocks, Wallet, Key].map((I, i) => (
                <div
                  key={i}
                  className="absolute grid h-8 w-8 place-items-center rounded-lg border border-white/10 bg-foreground"
                  style={{
                    top: `${[-8, -8, 80, 80][i]}%`,
                    left: `${[-8, 80, -8, 80][i]}%`,
                  }}
                >
                  <I className="h-4 w-4" />
                </div>
              ))}
            </div>
          </DarkFeatureCard>

          <DarkFeatureCard
            title="Magic Links"
            desc="Improve sign-up conversion rates and filter out spam/fraud with Magic Links."
          >
            <div className="font-mono text-[10px] leading-tight text-background/50">
              {"Yb9WznC5nFrvvz\nkE4AUdaxKhqT9v\nAlKzZoDbYbnSpg\nrLHDMzMcVFbeAbe"}
            </div>
          </DarkFeatureCard>

          <DarkFeatureCard
            title="Advanced security"
            desc="Brick is SOC 2 type 2 compliant and CCPA compliant. We conduct regular third-party audits and penetration tests."
          >
            <Fingerprint className="h-14 w-14 text-brick-soft" />
          </DarkFeatureCard>

          <DarkFeatureCard
            title="Bot Detection"
            desc="Dramatically reduce fraudulent sign-ups with built-in, continually updated machine learning."
          >
            <div className="relative h-24 w-24">
              <div className="absolute inset-0 rounded-full border border-white/10" />
              <div className="absolute inset-4 rounded-full border border-white/10" />
              <Bot className="absolute left-1/2 top-1/2 h-6 w-6 -translate-x-1/2 -translate-y-1/2 text-brick-soft" />
            </div>
          </DarkFeatureCard>

          <DarkFeatureCard
            title="Passwords"
            desc="Simple and secure password authentication, complete with breach detection and recovery options."
          >
            <div className="grid h-24 w-24 place-items-center rounded-xl border border-white/10 bg-white/[0.03]">
              <Lock className="h-8 w-8 text-background/70" />
            </div>
          </DarkFeatureCard>
        </div>

        <div className="mt-4 grid gap-4 md:grid-cols-2">
          <DarkFeatureCard
            title="API Keys"
            desc="Give every user secure, production-ready API keys without building any of the underlying boilerplate code or UI."
          >
            <div className="flex items-center gap-2 rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-xs">
              <div className="h-2 w-2 animate-pulse rounded-full bg-brick-soft" />
              Authenticating…
            </div>
          </DarkFeatureCard>
          <DarkFeatureCard
            title="MCP Server"
            desc="Add secure, consent-driven access to your app with Brick's MCP Server, all backed by Brick's authentication and authorization."
          >
            <div className="flex items-center gap-6">
              <div className="grid h-12 w-12 place-items-center rounded-full border border-white/10 bg-white/[0.03]">
                <Server className="h-5 w-5" />
              </div>
              <div className="h-px w-16 bg-white/20" />
              <div className="grid h-12 w-12 place-items-center rounded-full bg-brick text-primary-foreground">
                <Blocks className="h-5 w-5" />
              </div>
            </div>
          </DarkFeatureCard>
        </div>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ */
/* B2B section                                                         */
/* ------------------------------------------------------------------ */
function B2BSection() {
  return (
    <section className="mx-auto max-w-6xl px-4 py-24">
      <p className="text-sm font-semibold text-brick">B2B Authentication</p>
      <h2 className="mt-3 max-w-2xl text-4xl font-bold tracking-tight sm:text-5xl">
        The easy solution to multi-tenancy
      </h2>
      <p className="mt-4 max-w-xl text-muted-foreground">
        Brick has all the features you need to onboard and manage the users and organizations of
        your multi-tenant SaaS application.
      </p>
      <a href="#" className="mt-5 inline-flex items-center gap-1.5 text-sm font-semibold hover:opacity-80">
        Explore B2B features <ArrowRight className="h-3.5 w-3.5" />
      </a>

      <div className="mt-12 grid gap-5 md:grid-cols-3">
        <div className="rounded-2xl border border-border bg-card p-6">
          <h3 className="text-base font-semibold">Custom roles and permissions</h3>
          <p className="mt-1.5 text-sm text-muted-foreground">
            Powerful primitives to fully customize your app's authorization story.
          </p>
          <div className="mt-6 grid grid-cols-3 gap-2">
            {[0, 1, 2, 3, 4, 5, 6, 7, 8].map((i) => (
              <div
                key={i}
                className={`aspect-square rounded-lg ${
                  [1, 3, 5, 7].includes(i)
                    ? "bg-gradient-to-br from-brick-tint to-brick/30"
                    : "bg-muted"
                }`}
              />
            ))}
          </div>
          <div className="mt-4 flex flex-wrap items-center gap-2 text-xs">
            {["Product Member", "Administrator", "Editor", "QA Tester"].map((r, i) => (
              <span
                key={r}
                className={`rounded-full border px-2.5 py-1 ${
                  i === 1 ? "border-foreground bg-foreground text-background" : "border-border"
                }`}
              >
                {r}
              </span>
            ))}
          </div>
        </div>

        <div className="rounded-2xl border border-border bg-card p-6">
          <div className="grid h-40 place-items-center">
            <div className="relative">
              <div className="flex -space-x-3">
                {[0, 1, 2].map((i) => (
                  <div
                    key={i}
                    className="h-10 w-10 rounded-full border-2 border-card bg-gradient-to-br from-brick-tint to-brick/40"
                  />
                ))}
              </div>
              <div className="mt-4 inline-flex items-center gap-2 rounded-full border border-border bg-background px-3 py-1.5 text-xs">
                <UserPlus className="h-3.5 w-3.5" /> Auto-join
              </div>
            </div>
          </div>
          <h3 className="mt-2 text-base font-semibold">Auto-join</h3>
          <p className="mt-1.5 text-sm text-muted-foreground">
            Let your users discover and join organizations based on their email domain.
          </p>
        </div>

        <div className="rounded-2xl border border-border bg-card p-6">
          <h3 className="text-base font-semibold">Organization UI Components</h3>
          <p className="mt-1.5 text-sm text-muted-foreground">
            Brick's UI components add turn-key simplicity to complex Organization management tasks.
          </p>
          <div className="mt-5 flex items-center gap-2 rounded-lg border border-border bg-background px-3 py-2 text-sm">
            <Building2 className="h-4 w-4" /> Brick
            <ChevronDown className="ml-auto h-4 w-4 opacity-60" />
          </div>
          <div className="mt-2 space-y-1.5">
            {["General", "Members", "Billing", "Settings"].map((n, i) => (
              <div
                key={n}
                className={`rounded-md px-3 py-1.5 text-sm ${
                  i === 0 ? "bg-muted font-medium" : "text-muted-foreground"
                }`}
              >
                {n}
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ */
/* Billing section                                                     */
/* ------------------------------------------------------------------ */
function BillingSection() {
  return (
    <section id="pricing" className="mx-auto max-w-6xl px-4 py-24">
      <div className="grid items-start gap-14 md:grid-cols-2">
        <div>
          <p className="text-sm font-semibold text-brick">Billing</p>
          <h2 className="mt-3 text-4xl font-bold tracking-tight sm:text-5xl">
            Subscription billing,
            <br /> without the headache
          </h2>
          <p className="mt-5 max-w-md text-muted-foreground">
            Add subscriptions to your B2C or B2B application without having to write payment code,
            custom UI, or wrangle webhooks. Just drop in React components and start earning
            recurring revenue.
          </p>
          <p className="mt-6 text-sm font-medium">Here's what you can do out of the box:</p>
          <ul className="mt-3 space-y-2 text-sm">
            {["Define and manage plans", "Unify user and subscription data", "Gate access to content"].map(
              (i) => (
                <li key={i} className="flex items-center gap-2">
                  <span className="grid h-4 w-4 place-items-center rounded-full border border-brick/40">
                    <Check className="h-2.5 w-2.5 text-brick" />
                  </span>
                  {i}
                </li>
              ),
            )}
          </ul>
          <a
            href="#"
            className="mt-7 inline-flex items-center gap-1.5 text-sm font-semibold hover:opacity-80"
          >
            Explore Billing features <ArrowRight className="h-3.5 w-3.5" />
          </a>
        </div>

        <div className="rounded-2xl border border-border bg-gradient-to-b from-brick-tint/60 to-card p-8">
          <h3 className="text-center text-lg font-semibold">Tailor made pricing from Acme, Inc.</h3>
          <p className="text-center text-xs text-muted-foreground">
            Free 365-day trial, no credit-card required.
          </p>
          <div className="mt-6 grid gap-3 sm:grid-cols-2">
            {[
              {
                name: "Starter Acme Plan",
                price: "$9",
                features: [
                  "Custom branding",
                  "Mobile app integration",
                  "Daily backups",
                  "Collaboration tools",
                  "Basic design file inspection",
                ],
              },
              {
                name: "Pro Acme Plan",
                price: "$19",
                features: [
                  "Everything included in Starter",
                  "Unlimited projects",
                  "24/7 priority support",
                  "Advanced analytics",
                  "Centralized admin tools",
                ],
              },
            ].map((p) => (
              <div key={p.name} className="rounded-xl border border-border bg-card p-4">
                <p className="text-xs font-semibold">{p.name}</p>
                <div className="mt-1 flex items-baseline gap-1">
                  <span className="text-3xl font-bold">{p.price}</span>
                  <span className="text-xs text-muted-foreground">/ month</span>
                </div>
                <p className="mt-1 text-[11px] text-muted-foreground">Billed annually</p>
                <button className="mt-4 w-full rounded-lg bg-foreground py-2 text-xs font-semibold text-background">
                  Get started
                </button>
                <ul className="mt-4 space-y-1.5 text-[12px]">
                  {p.features.map((f) => (
                    <li key={f} className="flex items-start gap-1.5">
                      <Check className="mt-0.5 h-3 w-3 text-brick" /> {f}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ */
/* SDKs + Integrations (dark)                                          */
/* ------------------------------------------------------------------ */
function DevSection() {
  return (
    <section
      className="relative overflow-hidden bg-foreground text-background"
      style={{
        clipPath:
          "polygon(0 40px, 50% 0, 100% 40px, 100% calc(100% - 40px), 50% 100%, 0 calc(100% - 40px))",
      }}
    >
      <div className="relative mx-auto grid max-w-6xl gap-16 px-4 py-32 md:grid-cols-2">
        <div className="text-center">
          <p className="text-sm font-semibold text-brick-soft">Frameworks</p>
          <h2 className="mt-3 text-3xl font-bold tracking-tight sm:text-4xl">
            Build with SDKs for
            <br /> modern frameworks
          </h2>
          <p className="mx-auto mt-4 max-w-md text-background/70">
            Brick keeps developer experience front-and-center by providing helpful SDKs for most
            modern frameworks on web and mobile.
          </p>
          <a href="#" className="mt-5 inline-flex items-center gap-1.5 text-sm font-semibold text-background hover:opacity-80">
            All frameworks <ArrowRight className="h-3.5 w-3.5" />
          </a>
          <div className="mt-8 grid grid-cols-3 overflow-hidden rounded-xl border border-white/10">
            {[Zap, Blocks, Server, Puzzle, Github, Wallet].map((I, i) => (
              <div
                key={i}
                className="grid aspect-square place-items-center border-white/10 [&:not(:nth-child(3n))]:border-r [&:not(:nth-last-child(-n+3))]:border-b"
              >
                <I className="h-6 w-6 text-background/70" />
              </div>
            ))}
          </div>
        </div>

        <div className="text-center">
          <p className="text-sm font-semibold text-brick-soft">Integrations</p>
          <h2 className="mt-3 text-3xl font-bold tracking-tight sm:text-4xl">
            Integrate with
            <br /> the tools you love
          </h2>
          <p className="mx-auto mt-4 max-w-md text-background/70">
            Leverage Brick as the source of truth for your user data and integrate with the tools
            that you already depend on.
          </p>
          <a href="#" className="mt-5 inline-flex items-center gap-1.5 text-sm font-semibold text-background hover:opacity-80">
            All integrations <ArrowRight className="h-3.5 w-3.5" />
          </a>
          <div className="mt-8 grid grid-cols-3 overflow-hidden rounded-xl border border-white/10">
            {[CreditCard, Mail, KeyRound, Users, Shield, Bot].map((I, i) => (
              <div
                key={i}
                className="grid aspect-square place-items-center border-white/10 [&:not(:nth-child(3n))]:border-r [&:not(:nth-last-child(-n+3))]:border-b"
              >
                <I className="h-6 w-6 text-background/70" />
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ */
/* Testimonials                                                        */
/* ------------------------------------------------------------------ */
function Testimonials() {
  const items = [
    {
      quote:
        "I rolled my own auth and this is the amount of code I deleted after switching to Brick. Wallet sign-in in under an hour.",
      name: "Cameron W.",
      role: "Founder, Ledgerly",
    },
    {
      quote:
        "I implemented authentication in my starter app using Brick's custom flow setup, and it's been great having on-chain identity out of the box.",
      name: "Nadia K.",
      role: "Engineer, Ethervault",
    },
    {
      quote:
        "The organization UI components saved us weeks. Roles, invites, audit logs — all pixel-perfect from day one.",
      name: "Jonas P.",
      role: "CTO, Consensus",
    },
  ];
  return (
    <section className="mx-auto max-w-6xl px-4 py-24">
      <p className="text-sm font-semibold text-brick">Loved by developers</p>
      <h2 className="mt-3 max-w-2xl text-4xl font-bold tracking-tight sm:text-5xl">
        Ship faster with a stack devs actually enjoy
      </h2>
      <div className="mt-12 grid gap-5 md:grid-cols-3">
        {items.map((t) => (
          <figure
            key={t.name}
            className="flex flex-col rounded-2xl border border-border bg-card p-6"
          >
            <blockquote className="text-sm leading-relaxed text-foreground">
              "{t.quote}"
            </blockquote>
            <figcaption className="mt-6 flex items-center gap-3">
              <div className="h-9 w-9 rounded-full bg-gradient-to-br from-brick-tint to-brick/40" />
              <div className="text-sm">
                <div className="font-semibold">{t.name}</div>
                <div className="text-muted-foreground">{t.role}</div>
              </div>
            </figcaption>
          </figure>
        ))}
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ */
/* CTA + Footer                                                        */
/* ------------------------------------------------------------------ */
function CTA() {
  return (
    <section className="mx-auto max-w-6xl px-4 pb-24">
      <div className="relative overflow-hidden rounded-3xl border border-border bg-foreground p-12 text-background">
        <div
          aria-hidden
          className="absolute inset-0 opacity-30"
          style={{
            backgroundImage:
              "linear-gradient(to right, oklch(1 0 0 / 0.15) 1px, transparent 1px), linear-gradient(to bottom, oklch(1 0 0 / 0.15) 1px, transparent 1px)",
            backgroundSize: "40px 40px",
            maskImage: "radial-gradient(ellipse at 30% 50%, black, transparent 70%)",
          }}
        />
        <div className="relative grid gap-8 md:grid-cols-2 md:items-center">
          <h2 className="text-4xl font-bold tracking-tight sm:text-5xl">
            Start building with Brick today.
          </h2>
          <div className="md:justify-self-end">
            <p className="max-w-md text-background/70">
              Free for the first 10,000 monthly active users. No credit card required.
            </p>
            <div className="mt-5 flex flex-wrap gap-3">
              <a
                href="#"
                className="inline-flex items-center gap-1.5 rounded-full bg-brick px-5 py-3 text-sm font-semibold text-primary-foreground hover:brightness-95"
              >
                Start for free <ArrowRight className="h-4 w-4" />
              </a>
              <a
                href="#"
                className="inline-flex items-center gap-1.5 rounded-full border border-background/30 px-5 py-3 text-sm font-semibold hover:bg-background/10"
              >
                Read the docs
              </a>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

function Footer() {
  return (
    <footer className="border-t border-border">
      <div className="mx-auto max-w-6xl px-4 py-14">
        <div className="grid gap-10 md:grid-cols-5">
          <div className="md:col-span-2">
            <BrickMark />
            <p className="mt-3 max-w-xs text-sm text-muted-foreground">
              Blockchain-based user management and authentication for the modern web.
            </p>
            <div className="mt-4 flex gap-3 text-muted-foreground">
              <a href="#" className="hover:text-foreground"><Github className="h-4 w-4" /></a>
              <a href="#" className="hover:text-foreground"><Twitter className="h-4 w-4" /></a>
            </div>
          </div>
          {[
            { title: "Product", items: ["Authentication", "User Management", "Organizations", "Billing", "Pricing"] },
            { title: "Developers", items: ["Docs", "SDKs", "Changelog", "Status", "MCP Server"] },
            { title: "Company", items: ["About", "Customers", "Careers", "Contact"] },
          ].map((col) => (
            <div key={col.title}>
              <h4 className="text-sm font-semibold">{col.title}</h4>
              <ul className="mt-3 space-y-2 text-sm text-muted-foreground">
                {col.items.map((it) => (
                  <li key={it}>
                    <a href="#" className="hover:text-foreground">{it}</a>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
        <div className="mt-10 flex flex-col items-start justify-between gap-3 border-t border-border pt-6 text-xs text-muted-foreground md:flex-row">
          <span>© {new Date().getFullYear()} Brick Labs, Inc. All rights reserved.</span>
          <span>Made for the on-chain internet.</span>
        </div>
      </div>
    </footer>
  );
}

/* ------------------------------------------------------------------ */
/* Page                                                                */
/* ------------------------------------------------------------------ */
function Landing() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <TopBar />
      <Hero />
      <TrustLogos />
      <ComponentsSection />
      <AuthDarkSection />
      <B2BSection />
      <BillingSection />
      <DevSection />
      <Testimonials />
      <CTA />
      <Footer />
    </div>
  );
}
