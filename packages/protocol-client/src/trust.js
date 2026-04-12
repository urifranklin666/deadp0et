const crypto = require("crypto");

function sortObjectDeep(value) {
  if (Array.isArray(value)) {
    return value.map(sortObjectDeep);
  }
  if (!value || typeof value !== "object") {
    return value;
  }

  const sorted = {};
  for (const key of Object.keys(value).sort()) {
    sorted[key] = sortObjectDeep(value[key]);
  }
  return sorted;
}

function computeDeviceFingerprint(username, device) {
  const payload = {
    username: String(username || "").trim().toLowerCase(),
    deviceId: String(device?.deviceId || "").trim(),
    identityKey: sortObjectDeep(device?.identityKey || {}),
    signedPrekey: sortObjectDeep(device?.signedPrekey || {}),
    prekeySignature: device?.prekeySignature || ""
  };

  const fingerprint = crypto.createHash("sha256").update(JSON.stringify(payload)).digest("hex");
  const safetyNumber = (fingerprint.slice(0, 60).match(/.{1,5}/g) || []).join(" ");
  return { fingerprint, safetyNumber };
}

function getContactTrustRecord(records, username, deviceId) {
  const key = `${String(username || "").trim().toLowerCase()}#${String(deviceId || "").trim()}`;
  return (records || {})[key] || null;
}

function upsertContactTrustRecord(records, username, deviceId, record) {
  const key = `${String(username || "").trim().toLowerCase()}#${String(deviceId || "").trim()}`;
  return {
    ...(records || {}),
    [key]: record
  };
}

function assessTrustState(existingRecord, { username, deviceId, fingerprint, safetyNumber, now }) {
  if (!existingRecord) {
    return {
      nextRecord: {
        username,
        deviceId,
        trustedFingerprint: fingerprint,
        trustedSafetyNumber: safetyNumber,
        firstSeenAt: now,
        lastSeenAt: now,
        status: "trusted"
      },
      result: {
        status: "trusted-first-seen",
        trusted: true,
        safetyNumber,
        note: "First seen (TOFU).",
        changed: false
      }
    };
  }

  if (existingRecord.trustedFingerprint === fingerprint) {
    return {
      nextRecord: {
        ...existingRecord,
        lastSeenAt: now,
        trustedSafetyNumber: safetyNumber
      },
      result: {
        status: "trusted",
        trusted: true,
        safetyNumber,
        note: "Verified key matches trusted fingerprint.",
        changed: false
      }
    };
  }

  return {
    nextRecord: {
      ...existingRecord,
      status: "changed",
      lastSeenAt: now,
      pendingFingerprint: fingerprint,
      pendingSafetyNumber: safetyNumber,
      changedAt: now
    },
    result: {
      status: "changed",
      trusted: false,
      safetyNumber,
      note: "Key changed since last trusted fingerprint.",
      changed: true
    }
  };
}

function trustDeviceFingerprint(existingRecord, { username, deviceId, fingerprint, safetyNumber, now }) {
  return {
    username,
    deviceId,
    trustedFingerprint: fingerprint,
    trustedSafetyNumber: safetyNumber,
    firstSeenAt: existingRecord?.firstSeenAt || now,
    lastSeenAt: now,
    trustedAt: now,
    status: "trusted"
  };
}

module.exports = {
  assessTrustState,
  computeDeviceFingerprint,
  getContactTrustRecord,
  sortObjectDeep
  ,
  trustDeviceFingerprint,
  upsertContactTrustRecord
};
