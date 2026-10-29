"use client";

import { Printer } from "lucide-react";

import { Button } from "@/components/shadcn";

export const ReportPrintButton = () => (
  <Button
    type="button"
    variant="outline"
    size="sm"
    onClick={() => window.print()}
  >
    <Printer aria-hidden="true" />
    Print
  </Button>
);
