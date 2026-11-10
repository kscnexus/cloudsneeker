"use client";

import type { MouseEvent } from "react";

import { cn } from "@/lib/utils";

/** The page region of the signed-in shell (`components/layout/main-layout`). */
export const MAIN_CONTENT_SELECTOR = "main[data-responsive-container]";

const SKIP_LINK_CLASS =
  "bg-bg-neutral-secondary text-text-neutral-primary border-border-neutral-secondary fixed top-3 left-3 z-[100] -translate-y-24 rounded-lg border px-4 py-2 text-sm font-medium shadow-overlay transition-transform focus-visible:translate-y-0";

const focusMainContent = (event: MouseEvent<HTMLAnchorElement>) => {
  const main = document.querySelector<HTMLElement>(MAIN_CONTENT_SELECTOR);
  if (!main) return;
  event.preventDefault();
  if (!main.hasAttribute("tabindex")) main.setAttribute("tabindex", "-1");
  main.focus();
};

/**
 * First focusable element on every signed-in page: lets keyboard and screen
 * reader users jump past the sidebar to the page content (WCAG 2.4.1).
 * Hidden until it receives keyboard focus.
 */
export const SkipToContent = ({ className }: { className?: string }) => (
  <a
    href="#main-content"
    data-slot="skip-to-content"
    onClick={focusMainContent}
    className={cn(SKIP_LINK_CLASS, className)}
  >
    Skip to content
  </a>
);
