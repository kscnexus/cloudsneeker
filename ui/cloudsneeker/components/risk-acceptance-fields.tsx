"use client";

import {
  isoDateAfter,
  RISK_MAX_DAYS,
  RISK_REASON_MAX_LENGTH,
  type RiskAcceptanceInput,
} from "@/cloudsneeker/lib/risk-acceptance";
import { Input, Textarea } from "@/components/shadcn";

interface RiskAcceptanceFieldsProps {
  idPrefix: string;
  value: RiskAcceptanceInput;
  onChange: (value: RiskAcceptanceInput) => void;
  disabled?: boolean;
}

/** Reason and expiry date for accepting a risk (EB-019). */
export const RiskAcceptanceFields = ({
  idPrefix,
  value,
  onChange,
  disabled,
}: RiskAcceptanceFieldsProps) => (
  <div className="flex flex-wrap items-start gap-3">
    <label
      className="flex min-w-60 flex-1 flex-col gap-1 text-xs"
      htmlFor={`${idPrefix}-reason`}
    >
      <span className="text-text-neutral-secondary font-semibold">
        Why is this risk accepted?
      </span>
      <Textarea
        id={`${idPrefix}-reason`}
        value={value.risk_reason}
        maxLength={RISK_REASON_MAX_LENGTH}
        rows={2}
        disabled={disabled}
        placeholder="Compensating control, business reason, ticket"
        onChange={(event) =>
          onChange({ ...value, risk_reason: event.target.value })
        }
      />
    </label>
    <label
      className="flex flex-col gap-1 text-xs"
      htmlFor={`${idPrefix}-expires`}
    >
      <span className="text-text-neutral-secondary font-semibold">
        Accepted until
      </span>
      <Input
        id={`${idPrefix}-expires`}
        type="date"
        className="w-40"
        value={value.risk_expires_on}
        min={isoDateAfter(1)}
        max={isoDateAfter(RISK_MAX_DAYS)}
        disabled={disabled}
        onChange={(event) =>
          onChange({ ...value, risk_expires_on: event.target.value })
        }
      />
      <span className="text-text-neutral-tertiary">
        The finding reopens after this date.
      </span>
    </label>
  </div>
);
