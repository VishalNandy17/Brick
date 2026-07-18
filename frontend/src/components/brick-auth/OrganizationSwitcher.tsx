import { useEffect, useRef, useState } from "react";
import { useBrickAuth } from "./BrickAuthProvider";
import { Building2, ChevronDown, Check } from "lucide-react";

/* ─── Config ─── */
interface OrgOption {
  value: string;
  label: string;
  description?: string;
}

const ORG_OPTIONS: OrgOption[] = [
  { value: "Org1", label: "Org1", description: "Consumer" },
  { value: "Org2", label: "Org2", description: "Enterprise" },
  { value: "Org3", label: "Org3", description: "Auditor" },
];

/* ─── Props ─── */
interface OrganizationSwitcherProps {
  /** Extra CSS classes on the trigger button */
  className?: string;
}

/* ─── OrganizationSwitcher ─── */
export function OrganizationSwitcher({ className = "" }: OrganizationSwitcherProps) {
  const { activeOrg, switchOrg, user } = useBrickAuth();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  const activeOption =
    ORG_OPTIONS.find((o) => o.value === activeOrg) ?? ORG_OPTIONS[0];

  // Close on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const handleSelect = (orgValue: string) => {
    switchOrg(orgValue);
    setOpen(false);
  };

  if (!user) return null;

  return (
    <div ref={ref} className={`relative inline-block ${className}`}>
      {/* ── Trigger Button ── */}
      <button
        id="brick-org-switcher"
        type="button"
        onClick={() => setOpen((prev) => !prev)}
        className="flex items-center gap-2 rounded-lg border border-border bg-card px-3 py-2 text-sm font-medium text-foreground shadow-sm transition hover:bg-accent hover:text-accent-foreground focus:outline-none focus:ring-2 focus:ring-primary/30"
        aria-haspopup="listbox"
        aria-expanded={open}
      >
        <div className="flex h-5 w-5 items-center justify-center rounded bg-primary/15">
          <Building2 className="h-3 w-3 text-primary" />
        </div>
        <span>{activeOption.label}</span>
        {activeOption.description && (
          <span className="hidden text-xs text-muted-foreground sm:inline">
            — {activeOption.description}
          </span>
        )}
        <ChevronDown
          className={`ml-1 h-3.5 w-3.5 text-muted-foreground transition-transform duration-200 ${
            open ? "rotate-180" : ""
          }`}
        />
      </button>

      {/* ── Dropdown ── */}
      {open && (
        <div
          role="listbox"
          aria-label="Select organization"
          className="absolute left-0 top-full z-50 mt-1.5 w-56 overflow-hidden rounded-xl border border-border bg-card shadow-lg ring-1 ring-black/5 animate-fade-up"
        >
          <div className="p-1.5">
            <p className="px-2 pb-1.5 pt-1 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
              Organizations
            </p>

            {ORG_OPTIONS.map((org) => {
              const isActive = org.value === activeOrg;
              return (
                <button
                  key={org.value}
                  id={`brick-org-${org.value.toLowerCase()}`}
                  role="option"
                  aria-selected={isActive}
                  type="button"
                  onClick={() => handleSelect(org.value)}
                  className={`flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-left text-sm transition ${
                    isActive
                      ? "bg-primary/10 text-primary"
                      : "text-foreground hover:bg-accent"
                  }`}
                >
                  <div
                    className={`flex h-6 w-6 flex-shrink-0 items-center justify-center rounded-md text-[10px] font-bold ${
                      isActive
                        ? "bg-primary text-primary-foreground"
                        : "bg-muted text-muted-foreground"
                    }`}
                  >
                    {org.label.replace("Org", "")}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="font-medium leading-tight">{org.label}</p>
                    {org.description && (
                      <p className="text-[11px] text-muted-foreground leading-tight">
                        {org.description}
                      </p>
                    )}
                  </div>
                  {isActive && (
                    <Check className="h-3.5 w-3.5 flex-shrink-0 text-primary" />
                  )}
                </button>
              );
            })}
          </div>

          {/* ── Footer info ── */}
          <div className="border-t border-border bg-muted/30 px-3 py-2">
            <p className="text-[11px] text-muted-foreground">
              Signed in as{" "}
              <span className="font-medium text-foreground truncate">
                {user.email}
              </span>
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
