const { createApiClient, normalizeApiBase, requestJson } = require("./api");
const {
  appendLocalOneTimePrekeysRecord,
  consumeLocalOneTimePrekeyRecord,
  getLocalDeviceRecord,
  hydrateLocalDeviceRecord,
  listLocalDevicesForUsername,
  makeContactTrustKey,
  makeDeviceStorageKey,
  makeLocalDeviceRecord,
  normalizeUsername,
  serializeLocalDeviceRecord,
  upsertLocalDeviceRecord
} = require("./devices");
const { STORAGE_KEYS } = require("./storage-schema");
const {
  assessTrustState,
  computeDeviceFingerprint,
  getContactTrustRecord,
  sortObjectDeep,
  trustDeviceFingerprint,
  upsertContactTrustRecord
} = require("./trust");

module.exports = {
  STORAGE_KEYS,
  appendLocalOneTimePrekeysRecord,
  assessTrustState,
  computeDeviceFingerprint,
  consumeLocalOneTimePrekeyRecord,
  createApiClient,
  getContactTrustRecord,
  getLocalDeviceRecord,
  hydrateLocalDeviceRecord,
  listLocalDevicesForUsername,
  makeContactTrustKey,
  makeDeviceStorageKey,
  makeLocalDeviceRecord,
  normalizeApiBase,
  normalizeUsername,
  requestJson,
  serializeLocalDeviceRecord,
  sortObjectDeep,
  trustDeviceFingerprint,
  upsertContactTrustRecord,
  upsertLocalDeviceRecord
};
