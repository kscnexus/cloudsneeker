// Operator console root document. It reuses the signed-out root layout
// (theme, fonts, brand tokens, toasts) so the console never mounts the tenant
// sidebar, onboarding gate or tenant stores. `operator/layout.tsx` adds the
// operator chrome and the access check.
export { default, metadata, viewport } from "../(auth)/layout";
