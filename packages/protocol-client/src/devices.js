function normalizeUsername(value) {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

function makeDeviceStorageKey(username, deviceId) {
  return `${normalizeUsername(username)}#${String(deviceId || "").trim()}`;
}

function makeContactTrustKey(username, deviceId) {
  return `${normalizeUsername(username)}#${String(deviceId || "").trim()}`;
}

function makeLocalDeviceRecord({ username, deviceId, identityKey, signedPrekey, prekeySignature, storedAt, privateKeys = null }) {
  return {
    username: normalizeUsername(username),
    deviceId: String(deviceId || "").trim(),
    identityKey: identityKey || null,
    signedPrekey: signedPrekey || null,
    prekeySignature: prekeySignature || "",
    privateKeys,
    storedAt: storedAt || new Date().toISOString()
  };
}

function listLocalDevicesForUsername(deviceRecords, username) {
  const normalized = normalizeUsername(username);
  return Object.values(deviceRecords || {})
    .filter((record) => record && normalizeUsername(record.username) === normalized)
    .sort((left, right) => new Date(left.storedAt || 0).getTime() - new Date(right.storedAt || 0).getTime());
}

function getLocalDeviceRecord(deviceRecords, username, deviceId = "") {
  const records = deviceRecords || {};
  const normalized = normalizeUsername(username);

  if (deviceId) {
    return records[makeDeviceStorageKey(normalized, deviceId)] || null;
  }

  return records[normalized] || listLocalDevicesForUsername(records, normalized)[0] || null;
}

function upsertLocalDeviceRecord(deviceRecords, record) {
  const nextRecords = { ...(deviceRecords || {}) };
  nextRecords[makeDeviceStorageKey(record.username, record.deviceId)] = record;
  return nextRecords;
}

async function serializeLocalDeviceRecord({ username, passwordVerifier, accountId, deviceBundle, exportPrivateKey }) {
  const oneTimePrekeyPrivateKeys = {};
  for (const [keyId, privateKey] of Object.entries(deviceBundle.privateKeys.oneTimePrekeyPrivateKeys || {})) {
    oneTimePrekeyPrivateKeys[keyId] = await exportPrivateKey(privateKey);
  }

  return {
    username,
    accountId,
    passwordVerifier,
    deviceId: deviceBundle.publicBundle.deviceId,
    publicBundle: deviceBundle.publicBundle,
    privateKeys: {
      identityPrivateKey: await exportPrivateKey(deviceBundle.privateKeys.identityPrivateKey),
      signedPrekeyPrivateKey: await exportPrivateKey(deviceBundle.privateKeys.signedPrekeyPrivateKey),
      oneTimePrekeyPrivateKeys
    },
    storedAt: new Date().toISOString()
  };
}

async function hydrateLocalDeviceRecord(record, importPrivateKey) {
  if (!record) {
    return null;
  }

  const oneTimePrekeyPrivateKeys = {};
  const serializedOneTimePrekeys = record.privateKeys?.oneTimePrekeyPrivateKeys || {};
  for (const [keyId, jwk] of Object.entries(serializedOneTimePrekeys)) {
    oneTimePrekeyPrivateKeys[keyId] = await importPrivateKey(jwk);
  }

  return {
    username: record.username,
    accountId: record.accountId,
    passwordVerifier: record.passwordVerifier,
    publicBundle: record.publicBundle,
    privateKeys: {
      identityPrivateKey: await importPrivateKey(record.privateKeys.identityPrivateKey),
      signedPrekeyPrivateKey: await importPrivateKey(record.privateKeys.signedPrekeyPrivateKey),
      oneTimePrekeyPrivateKeys
    }
  };
}

function consumeLocalOneTimePrekeyRecord(record, keyId) {
  if (!record?.privateKeys?.oneTimePrekeyPrivateKeys?.[keyId]) {
    return null;
  }

  const nextRecord = {
    ...record,
    privateKeys: {
      ...record.privateKeys,
      oneTimePrekeyPrivateKeys: {
        ...record.privateKeys.oneTimePrekeyPrivateKeys
      }
    }
  };
  delete nextRecord.privateKeys.oneTimePrekeyPrivateKeys[keyId];
  return nextRecord;
}

async function appendLocalOneTimePrekeysRecord(record, privateOneTimePrekeyKeys, publicOneTimePrekeys = [], exportPrivateKey) {
  if (!record) {
    return null;
  }

  const nextOneTimePrivateKeys = {
    ...(record.privateKeys?.oneTimePrekeyPrivateKeys || {})
  };
  for (const [keyId, privateKey] of Object.entries(privateOneTimePrekeyKeys || {})) {
    nextOneTimePrivateKeys[keyId] = await exportPrivateKey(privateKey);
  }

  const existingPublicPrekeys = Array.isArray(record.publicBundle?.oneTimePrekeys) ? record.publicBundle.oneTimePrekeys : [];

  return {
    ...record,
    privateKeys: {
      ...(record.privateKeys || {}),
      oneTimePrekeyPrivateKeys: nextOneTimePrivateKeys
    },
    publicBundle: {
      ...(record.publicBundle || {}),
      oneTimePrekeys: [...existingPublicPrekeys, ...publicOneTimePrekeys]
    },
    storedAt: new Date().toISOString()
  };
}

module.exports = {
  appendLocalOneTimePrekeysRecord,
  consumeLocalOneTimePrekeyRecord,
  getLocalDeviceRecord,
  hydrateLocalDeviceRecord,
  listLocalDevicesForUsername,
  makeContactTrustKey,
  makeDeviceStorageKey,
  makeLocalDeviceRecord,
  normalizeUsername
  ,
  serializeLocalDeviceRecord,
  upsertLocalDeviceRecord
};
