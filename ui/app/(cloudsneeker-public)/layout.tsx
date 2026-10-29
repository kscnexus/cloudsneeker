// Public Cloudsneeker pages (no session, no sidebar). They reuse the signed-out
// root document (theme, fonts, brand tokens) by re-exporting the upstream
// `(auth)` layout, so no upstream layout is edited. `proxy.ts` lists these
// paths as public through a `cloudsneeker-hook`.
export { default, metadata, viewport } from "../(auth)/layout";
