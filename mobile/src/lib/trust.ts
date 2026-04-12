import {
  assessTrustState,
  getContactTrustRecord,
  normalizeUsername,
  trustDeviceFingerprint,
  upsertContactTrustRecord
} from "@deadp0et/protocol-client";

import { loadContactTrust, saveContactTrust } from "./secure-storage";
import { sha256Hex } from "./crypto";

type TrustDevice = {
  deviceId: string;
  identityKey?: JsonWebKey;
  signedPrekey?: JsonWebKey;
  prekeySignature?: string;
};

type TrustRecord = {
  username: string;
  deviceId: string;
  trustedFingerprint?: string;
  trustedSafetyNumber?: string;
  pendingFingerprint?: string;
  pendingSafetyNumber?: string;
  firstSeenAt?: string;
  lastSeenAt?: string;
  trustedAt?: string;
  changedAt?: string;
  status?: string;
};

export type StoredTrustRecord = TrustRecord;

function sortObjectDeep(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortObjectDeep);
  }
  if (!value || typeof value !== "object") {
    return value;
  }

  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(value as Record<string, unknown>).sort()) {
    sorted[key] = sortObjectDeep((value as Record<string, unknown>)[key]);
  }
  return sorted;
}

export async function computeMobileDeviceFingerprint(username: string, device: TrustDevice) {
  const payload = {
    username: normalizeUsername(username),
    deviceId: String(device?.deviceId || "").trim(),
    identityKey: sortObjectDeep(device?.identityKey || {}),
    signedPrekey: sortObjectDeep(device?.signedPrekey || {}),
    prekeySignature: device?.prekeySignature || ""
  };

  const fingerprint = await sha256Hex(JSON.stringify(payload));
  const safetyNumber = (fingerprint.slice(0, 60).match(/.{1,5}/g) || []).join(" ");
  return { fingerprint, safetyNumber };
}

export async function assessMobileDeviceTrust(username: string, device: TrustDevice) {
  const normalizedUsername = normalizeUsername(username);
  const deviceId = String(device.deviceId || "").trim();
  const records = JSON.parse((await loadContactTrust()) || "{}") as Record<string, TrustRecord>;
  const record = getContactTrustRecord(records, normalizedUsername, deviceId);
  const { fingerprint, safetyNumber } = await computeMobileDeviceFingerprint(normalizedUsername, device);
  const now = new Date().toISOString();
  const assessment = assessTrustState(record, {
    username: normalizedUsername,
    deviceId,
    fingerprint,
    safetyNumber,
    now
  });
  const nextRecords = upsertContactTrustRecord(records, normalizedUsername, deviceId, assessment.nextRecord);
  await saveContactTrust(JSON.stringify(nextRecords));
  return assessment.result;
}

export async function trustCurrentMobileDevice(username: string, device: TrustDevice) {
  const normalizedUsername = normalizeUsername(username);
  const deviceId = String(device.deviceId || "").trim();
  const records = JSON.parse((await loadContactTrust()) || "{}") as Record<string, TrustRecord>;
  const previous = getContactTrustRecord(records, normalizedUsername, deviceId);
  const { fingerprint, safetyNumber } = await computeMobileDeviceFingerprint(normalizedUsername, device);
  const now = new Date().toISOString();
  const trustedRecord = trustDeviceFingerprint(previous, {
    username: normalizedUsername,
    deviceId,
    fingerprint,
    safetyNumber,
    now
  });
  const nextRecords = upsertContactTrustRecord(records, normalizedUsername, deviceId, trustedRecord);
  await saveContactTrust(JSON.stringify(nextRecords));
  return {
    record: trustedRecord,
    fingerprint,
    safetyNumber
  };
}

export async function loadMobileTrustRecords() {
  const records = JSON.parse((await loadContactTrust()) || "{}") as Record<string, TrustRecord>;
  return Object.values(records).sort((left, right) => {
    const leftTime = new Date(left.lastSeenAt || left.trustedAt || left.firstSeenAt || 0).getTime();
    const rightTime = new Date(right.lastSeenAt || right.trustedAt || right.firstSeenAt || 0).getTime();
    return rightTime - leftTime;
  });
}

export async function removeMobileTrustRecord(username: string, deviceId: string) {
  const normalizedUsername = normalizeUsername(username);
  const records = JSON.parse((await loadContactTrust()) || "{}") as Record<string, TrustRecord>;
  const nextRecords = { ...records };
  delete nextRecords[`${normalizedUsername}#${String(deviceId || "").trim()}`];
  await saveContactTrust(JSON.stringify(nextRecords));
}
