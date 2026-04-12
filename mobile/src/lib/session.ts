import { createApiClient } from "@deadp0et/protocol-client";

import { MOBILE_DEFAULTS } from "./config";
import { hydrateMobileDeviceRecord, type HydratedMobileDeviceRecord } from "./crypto";
import { loadLocalDevice, loadSession } from "./secure-storage";

export type StoredSessionEnvelope = {
  apiBase?: string;
  session?: {
    accessToken: string;
    deviceId: string;
    expiresAt: string;
  };
};

export type StoredLocalDeviceRecord = {
  username?: string;
  accountId?: string;
  passwordVerifier?: string;
  deviceId?: string;
  publicBundle?: {
    deviceId?: string;
  };
  privateKeys?: Record<string, unknown>;
};

export async function loadStoredAuthState() {
  const rawSession = await loadSession();
  const rawLocalDevice = await loadLocalDevice();

  if (!rawSession) {
    throw new Error("No saved mobile session is stored yet. Sign up or log in first.");
  }
  if (!rawLocalDevice) {
    throw new Error("No saved local device record is stored yet. Sign up or log in first.");
  }

  const parsedSession = JSON.parse(rawSession) as StoredSessionEnvelope | StoredSessionEnvelope["session"] | null;
  const parsedDevice = JSON.parse(rawLocalDevice) as StoredLocalDeviceRecord | null;

  const sessionEnvelope = parsedSession && "session" in parsedSession && parsedSession.session
    ? parsedSession
    : { apiBase: MOBILE_DEFAULTS.apiBase, session: parsedSession as StoredSessionEnvelope["session"] | null };

  if (!sessionEnvelope.session?.accessToken) {
    throw new Error("Saved mobile session is malformed.");
  }
  if (!parsedDevice?.deviceId || !parsedDevice?.username) {
    throw new Error("Saved local device record is malformed.");
  }

  return {
    apiBase: sessionEnvelope.apiBase || MOBILE_DEFAULTS.apiBase,
    session: sessionEnvelope.session,
    localDeviceRecord: parsedDevice,
    hydratedDevice: await hydrateMobileDeviceRecord(parsedDevice) as HydratedMobileDeviceRecord | null
  };
}

export function createMobileApi(apiBase: string = MOBILE_DEFAULTS.apiBase, accessToken: string | null = null) {
  return createApiClient({
    apiBase,
    getAccessToken: () => accessToken
  });
}
