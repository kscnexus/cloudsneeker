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
      <linearGradient id="cloudsneeker-cloud" x1="8" y1="18" x2="56" y2="47">
        <stop stopColor="#5BA3FF" />
        <stop offset="0.52" stopColor="#2583FF" />
        <stop offset="1" stopColor="#0D9488" />
      </linearGradient>
      <linearGradient id="cloudsneeker-shield" x1="23" y1="37" x2="43" y2="58">
        <stop stopColor="#2DD4BF" />
        <stop offset="0.5" stopColor="#2583FF" />
        <stop offset="1" stopColor="#1A6AE6" />
      </linearGradient>
    </defs>
    <rect width="64" height="64" rx="16" fill="#07111F" />
    <path
      d="M16 46H14.5C9.3 46 6 42.8 6 38.3c0-4.2 2.8-7.2 7-8.1C14.4 21.9 21.5 16 30.1 16c7.4 0 13.9 4.5 16.4 11.2 6.6.1 11.5 4.4 11.5 10.3C58 42.9 53.7 46 48 46h-2"
      fill="none"
      stroke="url(#cloudsneeker-cloud)"
      strokeWidth="4"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
    <path
      d="M21 43c.7-10.4 4.7-18 11-21.5C38.3 25 42.3 32.6 43 43l-5.8 8H26.8L21 43Z"
      fill="#101D38"
      stroke="#3155C8"
      strokeWidth="1.5"
      strokeLinejoin="round"
    />
    <path
      d="m26.5 37 4 1.2-4.4 1.2M37.5 37l-4 1.2 4.4 1.2"
      fill="none"
      stroke="#7EB8FF"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
    <path
      data-brand-symbol="shield"
      d="m32 34 11 4v8.2c0 6.4-4.5 10.5-11 13.8-6.5-3.3-11-7.4-11-13.8V38l11-4Z"
      fill="url(#cloudsneeker-shield)"
      stroke="#C5DCFF"
      strokeWidth="1.5"
      strokeLinejoin="round"
    />
    <path
      d="M27 47.5h10M29 44.5h6l2 3-2 3h-6l-2-3 2-3Z"
      fill="none"
      stroke="#D9FCFF"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
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
      "inline-flex items-center gap-2 text-lg font-semibold tracking-tight text-text-neutral-primary",
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
