import React from "react";

import { cn } from "@/lib/utils";

import { IconSvgProps } from "../types/index";

import { BRAND } from "./brand";

interface BrandWordmarkProps {
  className?: string;
}

export const BrandWordmark = ({ className }: BrandWordmarkProps) => {
  return (
    <span
      role="img"
      aria-label={BRAND.name}
      className={cn(
        "inline-flex items-center text-lg font-semibold tracking-tight text-slate-900 dark:text-white",
        className,
      )}
    >
      {BRAND.name}
    </span>
  );
};

export const BrandWordmarkSvg: React.FC<IconSvgProps> = ({
  size,
  width = 216,
  height,
  ...props
}) => {
  return (
    <svg
      className="text-black dark:text-white"
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 216 40"
      fill="none"
      height={size || height}
      width={size || width}
      role="img"
      aria-label={BRAND.name}
      {...props}
    >
      <text x="0" y="28" fontSize="24" fontWeight="700" fill="currentColor">
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
    className="text-black dark:text-white"
    xmlns="http://www.w3.org/2000/svg"
    viewBox="0 0 32 32"
    fill="none"
    height={size || height}
    width={size || width}
    // Decorative unless the caller names it (e.g. an owner badge).
    aria-hidden={props["aria-label"] ? undefined : true}
    {...props}
  >
    <rect
      x="1"
      y="1"
      width="30"
      height="30"
      rx="8"
      fill="currentColor"
      opacity="0.08"
    />
    <text
      x="16"
      y="23"
      textAnchor="middle"
      fontSize="20"
      fontWeight="700"
      fill="currentColor"
    >
      {BRAND.shortName.charAt(0)}
    </text>
  </svg>
);
