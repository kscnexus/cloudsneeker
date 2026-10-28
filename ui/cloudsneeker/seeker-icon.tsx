import * as React from "react";

import { IconSvgProps } from "@/types";

interface SeekerIconProps extends IconSvgProps {
  animatedAura?: boolean;
}

// Lens mark for Seeker AI. It replaces the inherited assistant glyph.
export const SeekerIcon: React.FC<SeekerIconProps> = ({
  animatedAura = false,
  size = 19,
  width,
  height,
  ...props
}) => {
  const uid = React.useId().replace(/[«»:]/g, "");
  const gradientId = (name: string) => `${name}_${uid}`;

  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={width || size}
      height={height || size}
      viewBox="0 0 32 32"
      fill="none"
      {...props}
    >
      <path
        d="M3 16c3.4-6 8-9 13-9s9.6 3 13 9c-3.4 6-8 9-13 9s-9.6-3-13-9Z"
        stroke={`url(#${gradientId("lens")})`}
        strokeWidth="2.2"
      />
      <path
        d="M16 11.2a4.8 4.8 0 1 1 0 9.6 4.8 4.8 0 0 1 0-9.6Z"
        fill={`url(#${gradientId("iris")})`}
      />
      <path
        d="M16 13.8a2.2 2.2 0 1 1 0 4.4 2.2 2.2 0 0 1 0-4.4Z"
        fill={`url(#${gradientId("pupil")})`}
      />
      {animatedAura ? (
        <path
          d="M3 16c3.4-6 8-9 13-9s9.6 3 13 9c-3.4 6-8 9-13 9s-9.6-3-13-9Z"
          fill={`url(#${gradientId("aura")})`}
          opacity="0.45"
        >
          <animate
            attributeName="opacity"
            values="0.15;0.6;0.15"
            dur="2.4s"
            repeatCount="indefinite"
          />
        </path>
      ) : null}
      <defs>
        <linearGradient
          id={gradientId("lens")}
          x1="3"
          y1="7"
          x2="29"
          y2="25"
          gradientUnits="userSpaceOnUse"
        >
          <stop stopColor="#5BA3FF" />
          <stop offset="0.55" stopColor="#2583FF" />
          <stop offset="1" stopColor="#0D9488" />
        </linearGradient>
        <linearGradient
          id={gradientId("iris")}
          x1="11"
          y1="11"
          x2="21"
          y2="21"
          gradientUnits="userSpaceOnUse"
        >
          <stop stopColor="#2DD4BF" />
          <stop offset="1" stopColor="#2583FF" />
        </linearGradient>
        <linearGradient
          id={gradientId("pupil")}
          x1="14"
          y1="14"
          x2="18"
          y2="18"
          gradientUnits="userSpaceOnUse"
        >
          <stop stopColor="#E8F2FF" />
          <stop offset="1" stopColor="#7EB8FF" />
        </linearGradient>
        {animatedAura ? (
          <radialGradient
            id={gradientId("aura")}
            cx="16"
            cy="16"
            r="13"
            gradientUnits="userSpaceOnUse"
          >
            <stop stopColor="#5BA3FF" />
            <stop offset="1" stopColor="#5BA3FF" stopOpacity="0" />
          </radialGradient>
        ) : null}
      </defs>
    </svg>
  );
};
