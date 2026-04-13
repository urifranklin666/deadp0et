(function initDeadp0etProtocolClient(globalScope) {
  const STORAGE_KEYS = {
    apiBase: "deadp0et.apiBase",
    contactTrust: "deadp0et.contactTrust",
    localDevices: "deadp0et.localDevices",
    mobileInboxCache: "deadp0et.mobileInboxCache",
    mobileSession: "deadp0et.mobileSession"
  };

  function normalizeUsername(value) {
    return typeof value === "string" ? value.trim().toLowerCase() : "";
  }

  function normalizeApiBase(apiBase) {
    return String(apiBase || "").trim().replace(/\/+$/, "");
  }

  function makeContactTrustKey(username, deviceId) {
    return `${normalizeUsername(username)}#${String(deviceId || "").trim()}`;
  }

  function makeDeviceStorageKey(username, deviceId) {
    return `${normalizeUsername(username)}#${String(deviceId || "").trim()}`;
  }

  function makeLocalDeviceRecord(record) {
    return {
      username: normalizeUsername(record?.username),
      deviceId: String(record?.deviceId || "").trim(),
      identityKey: record?.identityKey || null,
      signedPrekey: record?.signedPrekey || null,
      prekeySignature: record?.prekeySignature || "",
      privateKeys: record?.privateKeys || null,
      storedAt: record?.storedAt || new Date().toISOString()
    };
  }

  function listLocalDevicesForUsername(deviceRecords, username) {
    const normalized = normalizeUsername(username);
    return Object.values(deviceRecords || {})
      .filter((record) => record && normalizeUsername(record.username) === normalized)
      .sort((left, right) => new Date(left.storedAt || 0).getTime() - new Date(right.storedAt || 0).getTime());
  }

  function getLocalDeviceRecord(deviceRecords, username, deviceId) {
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

  async function serializeLocalDeviceRecord(details) {
    const oneTimePrekeyPrivateKeys = {};
    for (const [keyId, privateKey] of Object.entries(details.deviceBundle.privateKeys.oneTimePrekeyPrivateKeys || {})) {
      oneTimePrekeyPrivateKeys[keyId] = await details.exportPrivateKey(privateKey);
    }

    return {
      username: details.username,
      accountId: details.accountId,
      passwordVerifier: details.passwordVerifier,
      deviceId: details.deviceBundle.publicBundle.deviceId,
      publicBundle: details.deviceBundle.publicBundle,
      privateKeys: {
        identityPrivateKey: await details.exportPrivateKey(details.deviceBundle.privateKeys.identityPrivateKey),
        signedPrekeyPrivateKey: await details.exportPrivateKey(details.deviceBundle.privateKeys.signedPrekeyPrivateKey),
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

  async function appendLocalOneTimePrekeysRecord(record, privateOneTimePrekeyKeys, publicOneTimePrekeys, exportPrivateKey) {
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
        oneTimePrekeys: [...existingPublicPrekeys, ...(publicOneTimePrekeys || [])]
      },
      storedAt: new Date().toISOString()
    };
  }

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

  async function sha256Hex(text) {
    const bytes = new TextEncoder().encode(text);
    const digest = await globalScope.crypto.subtle.digest("SHA-256", bytes);
    return Array.from(new Uint8Array(digest))
      .map((value) => value.toString(16).padStart(2, "0"))
      .join("");
  }

  async function computeDeviceFingerprint(username, device) {
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

  function getContactTrustRecord(records, username, deviceId) {
    return (records || {})[makeContactTrustKey(username, deviceId)] || null;
  }

  function upsertContactTrustRecord(records, username, deviceId, record) {
    return {
      ...(records || {}),
      [makeContactTrustKey(username, deviceId)]: record
    };
  }

  function assessTrustState(existingRecord, details) {
    const { username, deviceId, fingerprint, safetyNumber, now } = details;

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

  function trustDeviceFingerprint(existingRecord, details) {
    const { username, deviceId, fingerprint, safetyNumber, now } = details;
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

  async function requestJson(apiBase, pathname, options) {
    const nextOptions = options || {};
    const headers = new Headers(nextOptions.headers || {});

    if (!headers.has("Content-Type") && nextOptions.body !== undefined) {
      headers.set("Content-Type", "application/json");
    }

    const response = await globalScope.fetch(`${normalizeApiBase(apiBase)}${pathname}`, {
      ...nextOptions,
      headers
    });

    const text = await response.text();
    const payload = text ? JSON.parse(text) : null;

    if (!response.ok) {
      const error = new Error(payload?.error?.message || `Request failed with ${response.status}.`);
      error.status = response.status;
      error.body = payload;
      throw error;
    }

    return payload;
  }

  function createApiClient(options) {
    const nextOptions = options || {};

    function resolveApiBase() {
      const base = typeof nextOptions.getApiBase === "function" ? nextOptions.getApiBase() : nextOptions.apiBase;
      return normalizeApiBase(base);
    }

    function buildAuthHeaders(headers) {
      const nextHeaders = headers || {};
      const accessToken = typeof nextOptions.getAccessToken === "function" ? nextOptions.getAccessToken() : null;
      if (!accessToken) {
        return nextHeaders;
      }
      return {
        ...nextHeaders,
        Authorization: `Bearer ${accessToken}`
      };
    }

    function request(pathname, requestOptions) {
      return requestJson(resolveApiBase(), pathname, requestOptions || {});
    }

    function buildQuery(params) {
      const search = new URLSearchParams();
      Object.entries(params || {}).forEach(([key, value]) => {
        if (value === undefined || value === null || value === "") {
          return;
        }
        search.set(key, String(value));
      });
      const query = search.toString();
      return query ? `?${query}` : "";
    }

    return {
      request,
      getHealth() {
        return request("/health");
      },
      createAccount(payload) {
        return request("/v1/accounts", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });
      },
      createSession(payload) {
        return request("/v1/sessions", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });
      },
      listSessions() {
        return request("/v1/sessions", {
          method: "GET",
          headers: buildAuthHeaders()
        });
      },
      revokeCurrentSession() {
        return request("/v1/sessions/current", {
          method: "DELETE",
          headers: buildAuthHeaders()
        });
      },
      revokeSession(sessionId) {
        return request(`/v1/sessions/${encodeURIComponent(sessionId)}`, {
          method: "DELETE",
          headers: buildAuthHeaders()
        });
      },
      getBundles(username) {
        return request(`/v1/users/${encodeURIComponent(username)}/bundles`);
      },
      issuePrekeyBundle(username, payload) {
        return request(`/v1/users/${encodeURIComponent(username)}/prekey-bundle`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload || {})
        });
      },
      getInbox() {
        return request("/v1/messages/inbox", {
          method: "GET",
          headers: buildAuthHeaders()
        });
      },
      getInboxPage(params) {
        return request(`/v1/messages/inbox${buildQuery(params || {})}`, {
          method: "GET",
          headers: buildAuthHeaders()
        });
      },
      getHistory(params) {
        return request(`/v1/messages/history${buildQuery(params || {})}`, {
          method: "GET",
          headers: buildAuthHeaders()
        });
      },
      listConversations(params) {
        return request(`/v1/messages/conversations${buildQuery(params || {})}`, {
          method: "GET",
          headers: buildAuthHeaders()
        });
      },
      acknowledgeInbox(payload) {
        return request("/v1/messages/inbox/ack", {
          method: "POST",
          headers: buildAuthHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify(payload)
        });
      },
      storeMessage(payload) {
        return request("/v1/messages", {
          method: "POST",
          headers: buildAuthHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify(payload)
        });
      },
      listDevices() {
        return request("/v1/devices", {
          headers: buildAuthHeaders()
        });
      },
      registerDevice(payload) {
        return request("/v1/devices", {
          method: "POST",
          headers: buildAuthHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify(payload)
        });
      },
      revokeDevice(deviceId) {
        return request(`/v1/devices/${encodeURIComponent(deviceId)}`, {
          method: "DELETE",
          headers: buildAuthHeaders()
        });
      },
      rotatePrekeys(payload) {
        return request("/v1/prekeys/rotate", {
          method: "POST",
          headers: buildAuthHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify(payload)
        });
      },
      listPushRegistrations() {
        return request("/v1/push/registrations", {
          method: "GET",
          headers: buildAuthHeaders()
        });
      },
      registerPushToken(payload) {
        return request("/v1/push/register", {
          method: "POST",
          headers: buildAuthHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify(payload)
        });
      },
      revokePushToken(token) {
        return request(`/v1/push/register/${encodeURIComponent(token)}`, {
          method: "DELETE",
          headers: buildAuthHeaders()
        });
      }
    };
  }

  globalScope.deadp0etProtocolClient = {
    appendLocalOneTimePrekeysRecord,
    assessTrustState,
    STORAGE_KEYS,
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
})(window);
