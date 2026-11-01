import React from "react";

import { cn } from "@/lib/utils";

import { IconSvgProps } from "../types/index";

import { BRAND } from "./brand";

interface BrandWordmarkProps {
  className?: string;
}

const MarkPaths = () => (
  <>
    <defs>
      <linearGradient
        id="cloudsneeker-mark"
        x1="10"
        y1="10"
        x2="90"
        y2="90"
        gradientUnits="userSpaceOnUse"
      >
        <stop stopColor="#2DD4BF" />
        <stop offset="0.5" stopColor="#2583FF" />
        <stop offset="1" stopColor="#8B5CF6" />
      </linearGradient>
    </defs>
    <rect width="64" height="64" rx="16" fill="#07111F" />
    <g transform="translate(3 3) scale(.58)">
      <path
        d="M30 72H26C16 72 10 65 10 57C10 49 16 43 24 42C26 30 36 22 48 22C59 22 68 29 71 39C82 39 90 47 90 57C90 66 83 72 74 72H70"
        fill="none"
        stroke="url(#cloudsneeker-mark)"
        strokeWidth="7"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle
        data-brand-symbol="lens"
        cx="48"
        cy="58"
        r="12"
        fill="#0F1D36"
        stroke="#5BA3FF"
        strokeWidth="5.5"
      />
      <path
        d="M42 54a7 7 0 0 1 6-4"
        fill="none"
        stroke="#2DD4BF"
        strokeWidth="3"
        strokeLinecap="round"
      />
      <path
        d="M57 67L67 77"
        stroke="#5BA3FF"
        strokeWidth="8"
        strokeLinecap="round"
      />
    </g>
  </>
);

const WordmarkText = () => (
  <>
    <span>Cloud</span>
    <span className="cloudsneeker-wordmark-accent">sneeker</span>
  </>
);

export const BrandWordmark = ({ className }: BrandWordmarkProps) => (
  <span
    role="img"
    aria-label={BRAND.name}
    className={cn(
      "text-text-neutral-primary inline-flex items-center gap-2 text-lg font-semibold tracking-tight",
      className,
    )}
  >
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 64 64"
      width="32"
      height="32"
      aria-hidden="true"
    >
      <MarkPaths />
    </svg>
    <span aria-hidden="true">
      <WordmarkText />
    </span>
  </span>
);

export const BrandWordmarkSvg: React.FC<IconSvgProps> = ({
  size,
  width = 248,
  height,
  ...props
}) => (
  <svg
    className="text-black dark:text-white"
    xmlns="http://www.w3.org/2000/svg"
    viewBox="0 0 300 64"
    fill="none"
    height={size || height}
    width={size || width}
    role="img"
    aria-label={BRAND.name}
    {...props}
  >
    <MarkPaths />
    <text x="76" y="41" fontSize="27" fontWeight="750" fill="currentColor">
      Cloud
    </text>
    <text x="150" y="41" fontSize="27" fontWeight="750" fill="#2583FF">
      sneeker
    </text>
  </svg>
);

export const BrandMark: React.FC<IconSvgProps> = ({
  size,
  width = 32,
  height,
  ...props
}) => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    viewBox="0 0 64 64"
    fill="none"
    height={size || height}
    width={size || width}
    aria-hidden={props["aria-label"] ? undefined : true}
    {...props}
  >
    <MarkPaths />
  </svg>
);
