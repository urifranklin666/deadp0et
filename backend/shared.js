const crypto = require("crypto");

function createSharedContext(config, repository) {
  function nowIso() {
    return new Date().toISOString();
  }

  function normalizeUsername(value) {
    return typeof value === "string" ? value.trim().toLowerCase() : "";
  }

  function randomId() {
    return crypto.randomUUID();
  }

  function randomToken() {
    return crypto.randomBytes(32).toString("hex");
  }

  function findAccountByUsername(username) {
    const normalized = normalizeUsername(username);
    return repository.accounts.find((account) => account.username === normalized);
  }

  function findAccountById(accountId) {
    return repository.accounts.find((account) => account.accountId === accountId);
  }

  function getAvailableOneTimePrekeysCount(device) {
    return Array.isArray(device.oneTimePrekeys) ? device.oneTimePrekeys.length : 0;
  }

  function getOneTimePrekeyWarning(device) {
    const availableOneTimePrekeys = getAvailableOneTimePrekeysCount(device);
    if (device.revokedAt) {
      return null;
    }
    if (availableOneTimePrekeys >= config.LOW_ONE_TIME_PREKEY_THRESHOLD) {
      return null;
    }
    return `Low one-time prekeys for device ${device.deviceId}: ${availableOneTimePrekeys} remaining (threshold ${config.LOW_ONE_TIME_PREKEY_THRESHOLD}).`;
  }

  function getPublicDeviceBundle(device) {
    const availableOneTimePrekeys = getAvailableOneTimePrekeysCount(device);
    const prekeyWarning = getOneTimePrekeyWarning(device);
    return {
      deviceId: device.deviceId,
      identityKey: device.identityKey,
      signedPrekey: device.signedPrekey,
      prekeySignature: device.prekeySignature,
      oneTimePrekeys: Array.isArray(device.oneTimePrekeys) ? device.oneTimePrekeys : [],
      availableOneTimePrekeys,
      lowOneTimePrekeys: Boolean(prekeyWarning),
      prekeyWarning,
      registeredAt: device.registeredAt,
      revokedAt: device.revokedAt || null
    };
  }

  function getActiveDevices(account) {
    return account.devices.filter((device) => !device.revokedAt);
  }

  function buildPrekeyWarnings(devices) {
    return devices
      .map((device) => ({
        deviceId: device.deviceId,
        warning: getOneTimePrekeyWarning(device)
      }))
      .filter((entry) => Boolean(entry.warning));
  }

  function validateJwkLike(value, fieldName) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      return `${fieldName} must be a JSON object.`;
    }
    if (typeof value.kty !== "string" || !value.kty.trim()) {
      return `${fieldName}.kty is required.`;
    }
    return null;
  }

  function validateDevicePayload(device) {
    if (!device || typeof device !== "object" || Array.isArray(device)) {
      return "device must be an object.";
    }

    const requiredStringFields = ["deviceId", "prekeySignature"];
    for (const field of requiredStringFields) {
      if (typeof device[field] !== "string" || !device[field].trim()) {
        return `device.${field} is required.`;
      }
    }

    const identityError = validateJwkLike(device.identityKey, "device.identityKey");
    if (identityError) {
      return identityError;
    }

    const prekeyError = validateJwkLike(device.signedPrekey, "device.signedPrekey");
    if (prekeyError) {
      return prekeyError;
    }

    if (device.oneTimePrekeys !== undefined && !Array.isArray(device.oneTimePrekeys)) {
      return "device.oneTimePrekeys must be an array when provided.";
    }

    return null;
  }

  return {
    buildPrekeyWarnings,
    config,
    findAccountById,
    findAccountByUsername,
    getActiveDevices,
    getAvailableOneTimePrekeysCount,
    getOneTimePrekeyWarning,
    getPublicDeviceBundle,
    normalizeUsername,
    nowIso,
    randomId,
    randomToken,
    repository,
    validateDevicePayload,
    validateJwkLike
  };
}

module.exports = {
  createSharedContext
};
