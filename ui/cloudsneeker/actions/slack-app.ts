"use server";

import { revalidatePath } from "next/cache";

import { apiBaseUrl, getAuthHeaders, parseStringify } from "@/lib";
import { handleApiError } from "@/lib/server-actions-helper";

const SLACK_APP_CONFIG_PATH = "/slack-app-config";
const SLACK_REVALIDATE_PATH = "/integrations/slack";

export interface SlackAppConfigAttributes {
  enabled: boolean;
  client_id: string;
  has_client_secret: boolean;
}

export interface SlackAppConfigResource {
  id: string;
  type: string;
  attributes: SlackAppConfigAttributes;
}

export interface SlackAppConfigInput {
  enabled?: boolean;
  client_id: string;
  client_secret?: string;
}

export const getSlackAppConfig = async (): Promise<
  SlackAppConfigResource | null | { error: string }
> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}${SLACK_APP_CONFIG_PATH}`);

  try {
    const response = await fetch(url.toString(), { headers });
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      return {
        error:
          errorData.errors?.[0]?.detail ||
          `Unable to load Slack app settings: ${response.statusText}`,
      };
    }
    const body = await response.json();
    const data = body?.data;
    if (!data) return null;
    if (Array.isArray(data)) {
      return data.length
        ? (parseStringify(data[0]) as SlackAppConfigResource)
        : null;
    }
    return parseStringify(data) as SlackAppConfigResource;
  } catch (error) {
    return handleApiError(error);
  }
};

export const saveSlackAppConfig = async (
  input: SlackAppConfigInput,
  existingId?: string,
): Promise<SlackAppConfigResource | { error: string }> => {
  const headers = await getAuthHeaders({ contentType: true });
  const isUpdate = Boolean(existingId);
  const url = new URL(
    isUpdate
      ? `${apiBaseUrl}${SLACK_APP_CONFIG_PATH}/${existingId}`
      : `${apiBaseUrl}${SLACK_APP_CONFIG_PATH}`,
  );

  const attributes: Record<string, unknown> = {
    enabled: input.enabled ?? true,
    client_id: input.client_id,
  };
  if (input.client_secret) {
    attributes.client_secret = input.client_secret;
  }

  try {
    const response = await fetch(url.toString(), {
      method: isUpdate ? "PATCH" : "POST",
      headers,
      body: JSON.stringify({
        data: {
          type: "slack-app-configs",
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
          `Unable to save Slack app settings: ${response.statusText}`,
      };
    }

    const body = await response.json();
    revalidatePath(SLACK_REVALIDATE_PATH);
    revalidatePath("/integrations");
    return parseStringify(body.data) as SlackAppConfigResource;
  } catch (error) {
    return handleApiError(error);
  }
};

export const deleteSlackAppConfig = async (
  id: string,
): Promise<{ success: true } | { error: string }> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}${SLACK_APP_CONFIG_PATH}/${id}`);

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
          `Unable to delete Slack app settings: ${response.statusText}`,
      };
    }
    revalidatePath(SLACK_REVALIDATE_PATH);
    revalidatePath("/integrations");
    return { success: true };
  } catch (error) {
    return handleApiError(error);
  }
};
