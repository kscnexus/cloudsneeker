"use client";

import { LogOut, UserRound } from "lucide-react";
import Link from "next/link";
import { useSession } from "next-auth/react";

import { logOut } from "@/actions/auth";
import {
  Avatar,
  AvatarFallback,
  AvatarImage,
} from "@/components/shadcn/avatar/avatar";
import { Button } from "@/components/shadcn/button/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";

export const UserNav = () => {
  const { data: session } = useSession();

  if (!session?.user) return null;

  const { name } = session.user;

  const initials = name.includes(" ")
    ? name
        .split(" ")
        .map((word) => word.charAt(0))
        .join("")
    : name.charAt(0);

  return (
    <div className="flex items-center gap-2">
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            variant="outline"
            size="icon-sm"
            className="border-border-input-primary-fill rounded-full"
            asChild
          >
            <Link href="/profile" aria-label="Profile">
              <Avatar className="h-8 w-8">
                <AvatarImage src="#" alt="" />
                <AvatarFallback className="bg-transparent text-xs font-bold">
                  {initials}
                </AvatarFallback>
              </Avatar>
            </Link>
          </Button>
        </TooltipTrigger>
        <TooltipContent>Profile</TooltipContent>
      </Tooltip>

      <Tooltip>
        <TooltipTrigger asChild>
          <Button variant="ghost" size="sm" className="gap-1.5 px-2" asChild>
            <Link href="/profile" aria-label="Open profile">
              <UserRound className="size-4" aria-hidden="true" />
              <span className="hidden sm:inline">Profile</span>
            </Link>
          </Button>
        </TooltipTrigger>
        <TooltipContent className="sm:hidden">Profile</TooltipContent>
      </Tooltip>

      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            variant="ghost"
            size="icon-sm"
            className="border-border-input-primary-fill rounded-full"
            onClick={() => logOut()}
            aria-label="Sign out"
          >
            <LogOut />
          </Button>
        </TooltipTrigger>
        <TooltipContent>Sign Out</TooltipContent>
      </Tooltip>
    </div>
  );
};
