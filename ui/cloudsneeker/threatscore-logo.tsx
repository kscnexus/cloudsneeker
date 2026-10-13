import { BRAND } from "./brand";
import { BrandMark } from "./brand-logo";

export const ThreatScoreLogo = () => (
  <div
    className="cloudsneeker-threatscore-logo"
    role="img"
    aria-label={`${BRAND.name} ThreatScore`}
  >
    <BrandMark size={38} />
    <span className="cloudsneeker-threatscore-name">{BRAND.name}</span>
    <span aria-hidden="true" className="cloudsneeker-threatscore-divider" />
    <span>ThreatScore</span>
    <svg
      aria-hidden="true"
      viewBox="0 0 32 20"
      className="cloudsneeker-threatscore-gauge"
    >
      <path d="M3 17a13 13 0 0 1 26 0" />
      <path d="m16 17 7-8" />
      <circle cx="16" cy="17" r="2" />
    </svg>
  </div>
);
