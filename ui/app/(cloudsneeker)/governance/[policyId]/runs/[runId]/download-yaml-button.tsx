"use client";

import { downloadTextFile } from "@/cloudsneeker/lib/custodian-export";
import { Button } from "@/components/shadcn";

interface CustodianDownloadYamlButtonProps {
  filename: string;
  yaml: string;
}

export const CustodianDownloadYamlButton = ({
  filename,
  yaml,
}: CustodianDownloadYamlButtonProps) => (
  <Button
    type="button"
    variant="ghost"
    size="sm"
    onClick={() => downloadTextFile(filename, yaml, "text/yaml")}
  >
    Download policy YAML
  </Button>
);
