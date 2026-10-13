import { Orbit, ScanSearch, ShieldCheck } from "lucide-react";
import { ReactNode } from "react";

import { ThemeSwitch } from "@/components/ThemeSwitch";
import { AuthBrand } from "@/components/auth/oss/auth-brand";

interface AuthLayoutProps {
  title: string;
  footer?: ReactNode;
  children: ReactNode;
}

const PRODUCT_SIGNALS = [
  {
    icon: ScanSearch,
    label: "Continuous posture",
    description: "One view across cloud risk and compliance.",
  },
  {
    icon: Orbit,
    label: "Connected context",
    description: "Move from finding to affected resource without losing focus.",
  },
  {
    icon: ShieldCheck,
    label: "Actionable security",
    description: "Prioritize what matters and keep remediation moving.",
  },
] as const;

export const AuthLayout = ({ title, footer, children }: AuthLayoutProps) => {
  return (
    <main className="cloudsneeker-auth-shell">
      <section className="cloudsneeker-auth-story" aria-label="Product overview">
        <div aria-hidden="true" className="cloudsneeker-auth-orbit" />
        <div className="cloudsneeker-auth-story-content">
          <AuthBrand />
          <div className="cloudsneeker-auth-copy">
            <p className="cloudsneeker-auth-eyebrow">Cloud security, in focus</p>
            <h1>See risk clearly. Act before exposure becomes impact.</h1>
            <p>
              A focused security workspace for teams that need signal,
              context, and action in one place.
            </p>
          </div>
          <ul className="cloudsneeker-auth-signals">
            {PRODUCT_SIGNALS.map(({ icon: Icon, label, description }) => (
              <li key={label}>
                <span className="cloudsneeker-auth-signal-icon">
                  <Icon aria-hidden="true" />
                </span>
                <span>
                  <strong>{label}</strong>
                  <small>{description}</small>
                </span>
              </li>
            ))}
          </ul>
        </div>
      </section>

      <section className="cloudsneeker-auth-form-side">
        <div className="cloudsneeker-auth-mobile-brand">
          <AuthBrand />
        </div>
        <div className="cloudsneeker-auth-card">
          <div className="cloudsneeker-auth-card-heading">
            <div>
              <p className="cloudsneeker-auth-card-kicker">
                Secure workspace
              </p>
              <h2>{title}</h2>
            </div>
            <ThemeSwitch aria-label="Toggle theme" />
          </div>
          <div>{children}</div>
        </div>
        {footer && <div className="cloudsneeker-auth-footer">{footer}</div>}
      </section>
    </main>
  );
};
