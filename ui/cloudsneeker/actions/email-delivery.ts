"use server";

import { revalidatePath } from "next/cache";

import { apiBaseUrl, getAuthHeaders, parseStringify } from "@/lib";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";

const EMAIL_CONFIG_PATH = "/email-delivery-config";
const EMAIL_REVALIDATE_PATH = "/integrations/email";

export interface EmailDeliveryConfigAttributes {
  enabled: boolean;
  host: string;
  port: number;
  use_tls: boolean;
  use_ssl: boolean;
  username: string;
  from_email: string;
  has_password: boolean;
}

export interface EmailDeliveryConfigResource {
  id: string;
  type: string;
  attributes: EmailDeliveryConfigAttributes;
}

export interface EmailDeliveryConfigInput {
  enabled?: boolean;
  host: string;
  port: number;
  use_tls: boolean;
  use_ssl: boolean;
  username?: string;
  password?: string;
  from_email: string;
}

export const getEmailDeliveryConfig = async (): Promise<
  EmailDeliveryConfigResource | null | { error: string }
> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}${EMAIL_CONFIG_PATH}`);

  try {
    const response = await fetch(url.toString(), { headers });
    if (!response.ok) {
      return handleApiError(await handleApiResponse(response));
    }
    const body = await response.json();
    const data = body?.data;
    if (!data) return null;
    if (Array.isArray(data)) {
      return data.length
        ? (parseStringify(data[0]) as EmailDeliveryConfigResource)
        : null;
    }
    return parseStringify(data) as EmailDeliveryConfigResource;
  } catch (error) {
    return handleApiError(error);
  }
};

export const saveEmailDeliveryConfig = async (
  input: EmailDeliveryConfigInput,
  existingId?: string,
): Promise<EmailDeliveryConfigResource | { error: string }> => {
  const headers = await getAuthHeaders({ contentType: true });
  const isUpdate = Boolean(existingId);
  const url = new URL(
    isUpdate
      ? `${apiBaseUrl}${EMAIL_CONFIG_PATH}/${existingId}`
      : `${apiBaseUrl}${EMAIL_CONFIG_PATH}`,
  );

  const attributes: Record<string, unknown> = {
    enabled: input.enabled ?? true,
    host: input.host,
    port: input.port,
    use_tls: input.use_tls,
    use_ssl: input.use_ssl,
    username: input.username ?? "",
    from_email: input.from_email,
  };
  if (input.password) {
    attributes.password = input.password;
  }

  try {
    const response = await fetch(url.toString(), {
      method: isUpdate ? "PATCH" : "POST",
      headers,
      body: JSON.stringify({
        data: {
          type: "email-delivery-configs",
          ...(existingId ? { id: existingId } : {}),
          attributes,
        },
      }),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      return {
        error:
          errorData.errors?.[0]?.detail ||
          `Unable to save SMTP settings: ${response.statusText}`,
      };
    }

    const body = await response.json();
    revalidatePath(EMAIL_REVALIDATE_PATH);
    revalidatePath("/integrations");
    return parseStringify(body.data) as EmailDeliveryConfigResource;
  } catch (error) {
    return handleApiError(error);
  }
};

export const deleteEmailDeliveryConfig = async (
  id: string,
): Promise<{ success: true } | { error: string }> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}${EMAIL_CONFIG_PATH}/${id}`);

  try {
    const response = await fetch(url.toString(), {
      method: "DELETE",
      headers,
    });
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      return {
        error:
          errorData.errors?.[0]?.detail ||
          `Unable to delete SMTP settings: ${response.statusText}`,
      };
    }
    revalidatePath(EMAIL_REVALIDATE_PATH);
    revalidatePath("/integrations");
    return { success: true };
  } catch (error) {
    return handleApiError(error);
  }
};

export const testEmailDeliveryConfig = async (
  id: string,
): Promise<{ sent_to: string } | { error: string }> => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}${EMAIL_CONFIG_PATH}/${id}/test`);

  try {
    const response = await fetch(url.toString(), { method: "POST", headers });
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      return {
        error:
          errorData.errors?.[0]?.detail ||
          `SMTP test failed: ${response.statusText}`,
      };
    }
    const body = await response.json();
    return { sent_to: body?.data?.attributes?.sent_to ?? "" };
  } catch (error) {
    return handleApiError(error);
  }
};
