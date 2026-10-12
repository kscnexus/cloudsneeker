// Cloudsneeker pages share the signed-in application shell (sidebar, store
// initializer, onboarding gate, toasts). Re-exporting keeps one shell and
// avoids editing the upstream layout.
export { default, metadata, viewport } from "../(prowler)/layout";
