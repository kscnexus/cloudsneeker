import React from "react";

import { cn } from "@/lib/utils";

import { IconSvgProps } from "../types/index";

import { BRAND } from "./brand";

interface BrandWordmarkProps {
  className?: string;
}

const MarkPaths = () => (
  <>
    <rect width="32" height="32" rx="8" fill="#0B1F33" />
    <circle
      cx="14"
      cy="14"
      r="6"
      fill="none"
      stroke="#67E8F9"
      strokeWidth="2"
    />
    <path
      d="M18.8 18.8 L25 25"
      stroke="#67E8F9"
      strokeWidth="2"
      strokeLinecap="round"
    />
  </>
);

export const BrandWordmark = ({ className }: BrandWordmarkProps) => {
  return (
    <span
      role="img"
      aria-label={BRAND.name}
      className={cn(
        "inline-flex items-center gap-2 text-lg font-semibold tracking-tight text-text-neutral-primary",
        className,
      )}
    >
      <svg
        xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 32 32"
        width="28"
        height="28"
        aria-hidden="true"
      >
        <MarkPaths />
      </svg>
      {BRAND.name}
    </span>
  );
};

export const BrandWordmarkSvg: React.FC<IconSvgProps> = ({
  size,
  width = 248,
  height,
  ...props
}) => {
  return (
    <svg
      className="text-black dark:text-white"
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 248 32"
      fill="none"
      height={size || height}
      width={size || width}
      role="img"
      aria-label={BRAND.name}
      {...props}
    >
      <MarkPaths />
      <text x="40" y="23" fontSize="18" fontWeight="700" fill="currentColor">
        {BRAND.name}
      </text>
    </svg>
  );
};

export const BrandMark: React.FC<IconSvgProps> = ({
  size,
  width = 30,
  height,
  ...props
}) => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    viewBox="0 0 32 32"
    fill="none"
    height={size || height}
    width={size || width}
    aria-hidden={props["aria-label"] ? undefined : true}
    {...props}
  >
    <MarkPaths />
  </svg>
);
