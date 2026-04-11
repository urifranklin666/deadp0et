const STORAGE_KEYS = {
  apiBase: "deadp0et.apiBase",
  localDevices: "deadp0et.localDevices"
};
const ONE_TIME_PREKEY_BATCH_SIZE = 8;

const state = {
  currentUser: null,
  currentUsername: "",
  lastEnvelope: "",
  inbox: [],
  lookupCache: null,
  devices: []
};

const signupUsername = document.querySelector("#signup-username");
const signupPassword = document.querySelector("#signup-password");
const sessionOutput = document.querySelector("#session-output");
const directoryOutput = document.querySelector("#directory-output");
const recipientUsername = document.querySelector("#recipient-username");
const messageSubject = document.querySelector("#message-subject");
const messageBody = document.querySelector("#message-body");
const envelopeOutput = document.querySelector("#envelope-output");
const inboxOutput = document.querySelector("#inbox-output");
const plaintextOutput = document.querySelector("#plaintext-output");
const signupButton = document.querySelector("#signup-button");
const loginButton = document.querySelector("#login-button");
const bootstrapButton = document.querySelector("#bootstrap-button");
const sendButton = document.querySelector("#send-button");
const copyEnvelopeButton = document.querySelector("#copy-envelope-button");
const refreshInboxButton = document.querySelector("#refresh-inbox-button");
const decryptSelectedButton = document.querySelector("#decrypt-selected-button");
const statusNode = document.querySelector("#status");
const apiBaseInput = document.querySelector("#api-base");
const saveApiButton = document.querySelector("#save-api-button");
const healthButton = document.querySelector("#health-button");
const healthOutput = document.querySelector("#health-output");
const healthSummary = document.querySelector("#health-summary");
const lookupUsername = document.querySelector("#lookup-username");
const lookupButton = document.querySelector("#lookup-button");
const sessionSummary = document.querySelector("#session-summary");
const bundleSummary = document.querySelector("#bundle-summary");
const envelopeSummary = document.querySelector("#envelope-summary");
const inboxSummary = document.querySelector("#inbox-summary");
const plaintextSummary = document.querySelector("#plaintext-summary");
const refreshDevicesButton = document.querySelector("#refresh-devices-button");
const addDeviceButton = document.querySelector("#add-device-button");
const applyDeviceActionButton = document.querySelector("#apply-device-action-button");
const deviceActionId = document.querySelector("#device-action-id");
const deviceActionMode = document.querySelector("#device-action-mode");
const devicesOutput = document.querySelector("#devices-output");
const devicesSummary = document.querySelector("#devices-summary");
const devicePortabilitySummary = document.querySelector("#device-portability-summary");
const devicePortabilityOutput = document.querySelector("#device-portability-output");
const localDeviceSelect = document.querySelector("#local-device-select");
const exportDeviceButton = document.querySelector("#export-device-button");
const importDeviceButton = document.querySelector("#import-device-button");

function setStatus(message, type = "info") {
  statusNode.textContent = message;
  statusNode.style.color = type === "error" ? "var(--danger)" : "var(--success)";
}

function bytesToBase64(bytes) {
  let binary = "";
  bytes.forEach((value) => {
    binary += String.fromCharCode(value);
  });
  return btoa(binary);
}

function base64ToBytes(base64) {
  const binary = atob(base64);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function normalizeUsername(username) {
  return username.trim().toLowerCase();
}

function getDefaultApiBase() {
  return window.location.origin;
}

function getApiBase() {
  const value = apiBaseInput.value.trim();
  return value || getDefaultApiBase();
}

function saveApiBase() {
  const apiBase = getApiBase();
  localStorage.setItem(STORAGE_KEYS.apiBase, apiBase);
  apiBaseInput.value = apiBase;
  setStatus(`Backend endpoint saved: ${apiBase}`);
}

function loadLocalDevices() {
  try {
    const raw = localStorage.getItem(STORAGE_KEYS.localDevices);
    const parsed = raw ? JSON.parse(raw) : {};
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch (error) {
    return {};
  }
}

function saveLocalDevices(devices) {
  localStorage.setItem(STORAGE_KEYS.localDevices, JSON.stringify(devices));
}

function makeDeviceStorageKey(username, deviceId) {
  return `${normalizeUsername(username)}#${deviceId}`;
}

function getLocalDevicesForUsername(username) {
  const normalized = normalizeUsername(username);
  return Object.values(loadLocalDevices())
    .filter((record) => record && normalizeUsername(record.username) === normalized)
    .sort((left, right) => new Date(left.storedAt || 0).getTime() - new Date(right.storedAt || 0).getTime());
}

function getLocalDevice(username, deviceId = "") {
  const devices = loadLocalDevices();
  const normalized = normalizeUsername(username);

  if (deviceId) {
    return devices[makeDeviceStorageKey(normalized, deviceId)] || null;
  }

  return devices[normalized] || getLocalDevicesForUsername(normalized)[0] || null;
}

function storeLocalDevice(record) {
  const devices = loadLocalDevices();
  devices[makeDeviceStorageKey(record.username, record.deviceId)] = record;
  saveLocalDevices(devices);
}

function renderLocalDeviceOptions(username = signupUsername.value) {
  const normalized = normalizeUsername(username);
  const records = normalized ? getLocalDevicesForUsername(normalized) : [];
  const selectedValue = localDeviceSelect.value;

  localDeviceSelect.innerHTML = "";
  const defaultOption = document.createElement("option");
  defaultOption.value = "";
  defaultOption.textContent = records.length
    ? "Use the first local device for this account"
    : "No local devices stored for this account";
  localDeviceSelect.appendChild(defaultOption);

  for (const record of records) {
    const option = document.createElement("option");
    option.value = record.deviceId;
    option.textContent = `${record.deviceId} (${new Date(record.storedAt).toLocaleString()})`;
    localDeviceSelect.appendChild(option);
  }

  localDeviceSelect.value = records.some((record) => record.deviceId === selectedValue) ? selectedValue : "";
}

function setSummary(node, html, empty = false) {
  node.innerHTML = html;
  node.classList.toggle("empty", empty);
}

async function sha256(text) {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return bytesToBase64(new Uint8Array(digest));
}

async function deriveAesKey(sharedSecret) {
  const secretParts = Array.isArray(sharedSecret) ? sharedSecret : [sharedSecret];
  const decodedParts = secretParts.map((secret) => base64ToBytes(secret));
  const totalLength = decodedParts.reduce((sum, bytes) => sum + bytes.length, 0);
  const joined = new Uint8Array(totalLength);
  let offset = 0;
  for (const bytes of decodedParts) {
    joined.set(bytes, offset);
    offset += bytes.length;
  }
  const digest = await crypto.subtle.digest("SHA-256", joined);
  return crypto.subtle.importKey(
    "raw",
    digest,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function exportKeyPair(privateKey) {
  return crypto.subtle.exportKey("jwk", privateKey);
}

async function importPrivateKey(jwk) {
  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
}

async function generateOneTimePrekeySet(count = ONE_TIME_PREKEY_BATCH_SIZE) {
  const publicOneTimePrekeys = [];
  const privateOneTimePrekeyKeys = {};

  for (let index = 0; index < count; index += 1) {
    const oneTimePrekeyPair = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"]
    );
    const keyId = crypto.randomUUID();
    publicOneTimePrekeys.push({
      keyId,
      key: await crypto.subtle.exportKey("jwk", oneTimePrekeyPair.publicKey)
    });
    privateOneTimePrekeyKeys[keyId] = oneTimePrekeyPair.privateKey;
  }

  return {
    publicOneTimePrekeys,
    privateOneTimePrekeyKeys
  };
}

async function generateDeviceBundle() {
  const identity = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
  const signedPrekey = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
  const identityPublic = await crypto.subtle.exportKey("jwk", identity.publicKey);
  const prekeyPublic = await crypto.subtle.exportKey("jwk", signedPrekey.publicKey);
  const oneTimePrekeySet = await generateOneTimePrekeySet();
  const prekeySignature = await sha256(JSON.stringify(identityPublic) + JSON.stringify(prekeyPublic));

  return {
    privateKeys: {
      identityPrivateKey: identity.privateKey,
      signedPrekeyPrivateKey: signedPrekey.privateKey,
      oneTimePrekeyPrivateKeys: oneTimePrekeySet.privateOneTimePrekeyKeys
    },
    publicBundle: {
      identityKey: identityPublic,
      signedPrekey: prekeyPublic,
      prekeySignature,
      oneTimePrekeys: oneTimePrekeySet.publicOneTimePrekeys,
      deviceId: crypto.randomUUID()
    }
  };
}

async function serializeLocalDeviceRecord(username, passwordVerifier, accountId, deviceBundle) {
  const oneTimePrekeyPrivateKeys = {};
  for (const [keyId, privateKey] of Object.entries(deviceBundle.privateKeys.oneTimePrekeyPrivateKeys || {})) {
    oneTimePrekeyPrivateKeys[keyId] = await exportKeyPair(privateKey);
  }

  return {
    username,
    accountId,
    passwordVerifier,
    deviceId: deviceBundle.publicBundle.deviceId,
    publicBundle: deviceBundle.publicBundle,
    privateKeys: {
      identityPrivateKey: await exportKeyPair(deviceBundle.privateKeys.identityPrivateKey),
      signedPrekeyPrivateKey: await exportKeyPair(deviceBundle.privateKeys.signedPrekeyPrivateKey),
      oneTimePrekeyPrivateKeys
    },
    storedAt: new Date().toISOString()
  };
}

async function hydrateLocalDevice(record) {
  if (!record) {
    return null;
  }

  const oneTimePrekeyPrivateKeys = {};
  const serializedOneTimePrekeys = record.privateKeys.oneTimePrekeyPrivateKeys || {};
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

function consumeLocalOneTimePrekey(username, deviceId, keyId) {
  const record = getLocalDevice(username, deviceId);
  if (!record?.privateKeys?.oneTimePrekeyPrivateKeys?.[keyId]) {
    return false;
  }

  delete record.privateKeys.oneTimePrekeyPrivateKeys[keyId];
  storeLocalDevice(record);
  return true;
}

async function appendLocalOneTimePrekeys(username, deviceId, privateOneTimePrekeyKeys, publicOneTimePrekeys = []) {
  const record = getLocalDevice(username, deviceId);
  if (!record) {
    return false;
  }

  record.privateKeys = record.privateKeys || {};
  record.privateKeys.oneTimePrekeyPrivateKeys = record.privateKeys.oneTimePrekeyPrivateKeys || {};
  for (const [keyId, privateKey] of Object.entries(privateOneTimePrekeyKeys || {})) {
    record.privateKeys.oneTimePrekeyPrivateKeys[keyId] = await exportKeyPair(privateKey);
  }

  record.publicBundle = record.publicBundle || {};
  const existingPublicPrekeys = Array.isArray(record.publicBundle.oneTimePrekeys) ? record.publicBundle.oneTimePrekeys : [];
  record.publicBundle.oneTimePrekeys = [...existingPublicPrekeys, ...publicOneTimePrekeys];
  record.storedAt = new Date().toISOString();
  storeLocalDevice(record);
  return true;
}

async function deriveSharedSecret(privateKey, remotePublicJwk) {
  const remotePublicKey = await crypto.subtle.importKey(
    "jwk",
    remotePublicJwk,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: remotePublicKey },
    privateKey,
    256
  );
  return bytesToBase64(new Uint8Array(bits));
}

async function apiRequest(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (!headers.has("Content-Type") && options.body !== undefined) {
    headers.set("Content-Type", "application/json");
  }

  if (state.currentUser?.session?.accessToken && !headers.has("Authorization")) {
    headers.set("Authorization", `Bearer ${state.currentUser.session.accessToken}`);
  }

  const response = await fetch(`${getApiBase()}${path}`, {
    ...options,
    headers
  });

  const text = await response.text();
  const payload = text ? JSON.parse(text) : null;

  if (!response.ok) {
    const message = payload?.error?.message || `Request failed with ${response.status}.`;
    throw new Error(message);
  }

  return payload;
}

function renderLookupResult(payload = null) {
  state.lookupCache = payload;
  directoryOutput.value = payload
    ? JSON.stringify(payload, null, 2)
    : "Use bundle lookup to fetch a recipient's active public keys.";

  if (!payload) {
    setSummary(bundleSummary, "No recipient bundle loaded.", true);
    return;
  }

  const devices = payload.devices || [];
  const deviceSummary = devices.length
    ? devices.map((device) => `<strong>${device.deviceId}</strong>`).join(", ")
    : "none";

  setSummary(
    bundleSummary,
    `<strong>${payload.username}</strong><br>${devices.length} active device bundle(s)<br>${deviceSummary}`
  );
}

function renderDevices(payload = null) {
  if (!payload) {
    state.devices = [];
    devicesOutput.value = "Sign in to inspect account devices.";
    setSummary(devicesSummary, "No device data loaded.", true);
    setSummary(devicePortabilitySummary, "No local device note yet.", true);
    devicePortabilityOutput.value = "Device portability notes will appear here.";
    return;
  }

  state.devices = payload.devices || [];
  devicesOutput.value = JSON.stringify(payload, null, 2);

  const activeDevices = state.devices.filter((device) => !device.revokedAt);
  const revokedDevices = state.devices.filter((device) => device.revokedAt);
  const lowPrekeyDevices = activeDevices.filter((device) => device.lowOneTimePrekeys);
  const lowThreshold = Number(payload.lowOneTimePrekeyThreshold || 0);
  const lowPrekeySummary = lowPrekeyDevices.length
    ? lowPrekeyDevices
        .map((device) => `${device.deviceId} (${device.availableOneTimePrekeys})`)
        .join(", ")
    : "none";
  const localDeviceId = state.currentUser?.publicBundle?.deviceId;
  const localLowPrekeyDevice = lowPrekeyDevices.find((device) => device.deviceId === localDeviceId) || null;

  setSummary(
    devicesSummary,
    `<strong>${activeDevices.length}</strong> active device(s)<br>` +
      `<strong>${revokedDevices.length}</strong> revoked device(s)<br>` +
      `<strong>${lowPrekeyDevices.length}</strong> low-prekey device(s)${lowThreshold ? ` (threshold ${lowThreshold})` : ""}<br>` +
      `${lowPrekeySummary}` +
      (localLowPrekeyDevice
        ? `<br><button type="button" id="replenish-local-prekeys-inline">Replenish Local Prekeys</button>`
        : "")
  );

  const localDevicePresent = Boolean(localDeviceId && activeDevices.some((device) => device.deviceId === localDeviceId));
  setSummary(
    devicePortabilitySummary,
    localDevicePresent
      ? `<strong>Local device ready</strong><br>This browser holds the private keys for <strong>${localDeviceId}</strong>.`
      : "This browser may not hold the private keys for every active device on the account.",
    !localDevicePresent
  );

  devicePortabilityOutput.value = localDevicePresent
    ? `This browser can decrypt envelopes addressed to ${localDeviceId}. Additional devices must generate or import their own private keys locally.`
    : "Authentication alone is not enough for decryption. A browser can only decrypt messages for devices whose private keys are stored locally.";
}

async function replenishLocalPrekeys(deviceId) {
  if (!state.currentUser) {
    setStatus("Sign in before replenishing one-time prekeys.", "error");
    return;
  }

  const localDeviceId = state.currentUser.publicBundle?.deviceId;
  if (!localDeviceId || deviceId !== localDeviceId) {
    setStatus("One-click replenish is only available for the local device in this browser.", "error");
    return;
  }

  const targetDevice = state.devices.find((device) => device.deviceId === deviceId && !device.revokedAt);
  if (!targetDevice) {
    setStatus("Target device is not active on this account.", "error");
    return;
  }

  setStatus(`Replenishing one-time prekeys for local device ${deviceId}...`);
  const oneTimePrekeySet = await generateOneTimePrekeySet();
  const existingOneTimePrekeys = Array.isArray(targetDevice.oneTimePrekeys) ? targetDevice.oneTimePrekeys : [];

  await apiRequest("/v1/prekeys/rotate", {
    method: "POST",
    body: JSON.stringify({
      deviceId,
      signedPrekey: targetDevice.signedPrekey,
      prekeySignature: targetDevice.prekeySignature,
      oneTimePrekeys: [...existingOneTimePrekeys, ...oneTimePrekeySet.publicOneTimePrekeys]
    })
  });

  state.currentUser.privateKeys.oneTimePrekeyPrivateKeys = {
    ...(state.currentUser.privateKeys.oneTimePrekeyPrivateKeys || {}),
    ...oneTimePrekeySet.privateOneTimePrekeyKeys
  };
  await appendLocalOneTimePrekeys(state.currentUser.username, deviceId, oneTimePrekeySet.privateOneTimePrekeyKeys, oneTimePrekeySet.publicOneTimePrekeys);
  await fetchDevices();
  setStatus(`Replenished local one-time prekeys for ${deviceId}.`);
}

function renderSession() {
  if (!state.currentUser) {
    sessionOutput.value = "No active session.";
    setSummary(sessionSummary, "No active account session.", true);
    return;
  }

  sessionOutput.value = JSON.stringify({
    apiBase: getApiBase(),
    accountId: state.currentUser.accountId,
    username: state.currentUser.username,
    session: {
      accessTokenPreview: `${state.currentUser.session.accessToken.slice(0, 16)}...`,
      deviceId: state.currentUser.session.deviceId
    },
    localDevice: {
      deviceId: state.currentUser.publicBundle.deviceId,
      hasPrivateKeys: Boolean(state.currentUser.privateKeys?.signedPrekeyPrivateKey)
    },
    protocol: {
      identityCurve: "P-256 ECDH",
      contentCipher: "AES-GCM-256",
      serverVisibility: "account metadata + ciphertext envelope only"
    }
  }, null, 2);

  setSummary(
    sessionSummary,
    `<strong>${state.currentUser.username}</strong><br>Device ${state.currentUser.session.deviceId}<br>Session expires ${new Date(state.currentUser.session.expiresAt).toLocaleString()}`
  );
}

function renderInbox(messages = null) {
  if (!state.currentUser) {
    state.inbox = [];
    inboxOutput.value = "Sign in to fetch encrypted messages.";
    setSummary(inboxSummary, "No inbox data loaded.", true);
    return [];
  }

  if (Array.isArray(messages)) {
    state.inbox = messages;
  }

  inboxOutput.value = state.inbox.length
    ? JSON.stringify(state.inbox, null, 2)
    : "No encrypted envelopes for this device yet.";

  if (!state.inbox.length) {
    setSummary(inboxSummary, `No encrypted envelopes for <strong>${state.currentUser.session.deviceId}</strong>.`, true);
  } else {
    const latest = state.inbox[state.inbox.length - 1];
    setSummary(
      inboxSummary,
      `<strong>${state.inbox.length}</strong> message(s) for device <strong>${state.currentUser.session.deviceId}</strong><br>Latest from <strong>${latest.from}</strong>`
    );
  }

  return state.inbox;
}

async function fetchHealth() {
  healthButton.disabled = true;
  setStatus("Checking backend health...");

  try {
    const payload = await fetch(`${getApiBase()}/health`).then(async (response) => {
      const text = await response.text();
      return text ? JSON.parse(text) : {};
    });
    healthOutput.value = JSON.stringify(payload, null, 2);
    setSummary(
      healthSummary,
      `<strong>${payload.status}</strong><br>${payload.accounts} account(s), ${payload.sessions} active session(s), ${payload.messages} message(s)`
    );
    setStatus(`Backend reachable at ${getApiBase()}.`);
    return payload;
  } catch (error) {
    healthOutput.value = "";
    setSummary(healthSummary, "Backend health check failed.", true);
    setStatus(`Unable to reach backend at ${getApiBase()}.`, "error");
    throw error;
  } finally {
    healthButton.disabled = false;
  }
}

async function fetchBundles(username = lookupUsername.value) {
  const normalized = normalizeUsername(username);
  if (!normalized) {
    setStatus("Enter a recipient username to fetch bundles.", "error");
    return null;
  }

  lookupButton.disabled = true;
  setStatus(`Fetching public bundles for ${normalized}...`);

  try {
    const payload = await apiRequest(`/v1/users/${encodeURIComponent(normalized)}/bundles`, {
      method: "GET",
      headers: {}
    });
    renderLookupResult(payload);
    setStatus(`Fetched ${payload.devices.length} active bundle(s) for ${payload.username}.`);
    return payload;
  } catch (error) {
    renderLookupResult(null);
    setStatus(error.message, "error");
    throw error;
  } finally {
    lookupButton.disabled = false;
  }
}

async function fetchPrekeyBundle(username, deviceId = "") {
  const normalized = normalizeUsername(username);
  if (!normalized) {
    throw new Error("Recipient username is required.");
  }

  const body = deviceId ? { deviceId } : {};
  const payload = await apiRequest(`/v1/users/${encodeURIComponent(normalized)}/prekey-bundle`, {
    method: "POST",
    body: JSON.stringify(body)
  });

  renderLookupResult({
    username: payload.username,
    devices: [{
      ...payload.device,
      oneTimePrekeys: payload.oneTimePrekey ? [payload.oneTimePrekey] : []
    }]
  });
  return payload;
}

async function fetchInbox() {
  if (!state.currentUser) {
    setStatus("Sign in before fetching an inbox.", "error");
    return [];
  }

  refreshInboxButton.disabled = true;
  setStatus(`Fetching ciphertext inbox for ${state.currentUser.username}...`);

  try {
    const payload = await apiRequest("/v1/messages/inbox", {
      method: "GET",
      headers: {}
    });
    renderInbox(payload.messages || []);
    setStatus(`Fetched ${payload.messages.length} encrypted message(s) for ${payload.deviceId}.`);
    return payload.messages || [];
  } catch (error) {
    renderInbox([]);
    setStatus(error.message, "error");
    throw error;
  } finally {
    refreshInboxButton.disabled = false;
  }
}

async function fetchDevices() {
  if (!state.currentUser) {
    setStatus("Sign in before loading account devices.", "error");
    return [];
  }

  refreshDevicesButton.disabled = true;
  setStatus(`Fetching devices for ${state.currentUser.username}...`);

  try {
    const payload = await apiRequest("/v1/devices", {
      method: "GET",
      headers: {}
    });
    renderDevices(payload);
    setStatus(`Fetched ${payload.devices.length} device record(s) for ${payload.username}.`);
    return payload.devices || [];
  } catch (error) {
    renderDevices(null);
    setStatus(error.message, "error");
    throw error;
  } finally {
    refreshDevicesButton.disabled = false;
  }
}

async function createAccount() {
  const username = normalizeUsername(signupUsername.value);
  const password = signupPassword.value;

  if (!username || !password) {
    setStatus("Enter a username and password to create an account.", "error");
    return;
  }

  signupButton.disabled = true;
  setStatus("Generating local device keys and registering the account...");

  try {
    const deviceBundle = await generateDeviceBundle();
    const passwordVerifier = await sha256(password);
    const payload = await apiRequest("/v1/accounts", {
      method: "POST",
      body: JSON.stringify({
        username,
        passwordVerifier,
        device: deviceBundle.publicBundle
      })
    });

    const localRecord = await serializeLocalDeviceRecord(username, passwordVerifier, payload.accountId, deviceBundle);
    storeLocalDevice(localRecord);
    renderLocalDeviceOptions(username);
    const hydrated = await hydrateLocalDevice(localRecord);

    state.currentUser = {
      accountId: payload.accountId,
      username: payload.username,
      session: payload.session,
      passwordVerifier,
      publicBundle: hydrated.publicBundle,
      privateKeys: hydrated.privateKeys
    };
    state.currentUsername = payload.username;

    renderSession();
    renderInbox([]);
    renderDevices({
      username: payload.username,
      devices: [{
        ...hydrated.publicBundle,
        oneTimePrekeys: hydrated.publicBundle.oneTimePrekeys || [],
        registeredAt: new Date().toISOString(),
        revokedAt: null
      }]
    });
    plaintextOutput.value = "";
    setStatus(`Account ${payload.username} created and this browser registered as device ${payload.session.deviceId}.`);
    return payload;
  } catch (error) {
    setStatus(error.message, "error");
    throw error;
  } finally {
    signupButton.disabled = false;
  }
}

async function signIn() {
  const username = normalizeUsername(signupUsername.value);
  const password = signupPassword.value;

  if (!username || !password) {
    setStatus("Enter a username and password to sign in.", "error");
    return;
  }

  loginButton.disabled = true;
  setStatus(`Authenticating ${username} against the backend...`);

  try {
    const passwordVerifier = await sha256(password);
    const localRecord = getLocalDevice(username, localDeviceSelect.value);

    if (!localRecord) {
      throw new Error("No local device keys are stored for this account in this browser. Create the account here or import a device before signing in.");
    }

    if (localRecord.passwordVerifier !== passwordVerifier) {
      throw new Error("Password does not match the verifier stored for this local device.");
    }

    const payload = await apiRequest("/v1/sessions", {
      method: "POST",
      body: JSON.stringify({
        username,
        passwordVerifier,
        deviceId: localRecord.deviceId
      })
    });

    const hydrated = await hydrateLocalDevice(localRecord);
    state.currentUser = {
      accountId: payload.accountId,
      username: payload.username,
      session: payload.session,
      passwordVerifier,
      publicBundle: hydrated.publicBundle,
      privateKeys: hydrated.privateKeys
    };
    state.currentUsername = payload.username;

    renderSession();
    plaintextOutput.value = "";
    await fetchDevices();
    await fetchInbox();
    setStatus(`Signed in as ${payload.username} on local device ${payload.session.deviceId}.`);
    return payload;
  } catch (error) {
    setStatus(error.message, "error");
    throw error;
  } finally {
    loginButton.disabled = false;
  }
}

async function encryptForRecipient(sender, recipientBundle, subject, body) {
  const recipientDevice = recipientBundle.device;
  const ephemeral = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
  const ephemeralPublic = await crypto.subtle.exportKey("jwk", ephemeral.publicKey);
  const sharedSecrets = [await deriveSharedSecret(ephemeral.privateKey, recipientDevice.signedPrekey)];
  let oneTimePrekeyId = null;
  if (recipientBundle.oneTimePrekey && recipientBundle.oneTimePrekey.key) {
    sharedSecrets.push(await deriveSharedSecret(ephemeral.privateKey, recipientBundle.oneTimePrekey.key));
    oneTimePrekeyId = recipientBundle.oneTimePrekey.keyId || null;
  }

  const aesKey = await deriveAesKey(sharedSecrets);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const payload = {
    subject,
    body,
    sentAt: new Date().toISOString(),
    senderDeviceId: sender.publicBundle.deviceId
  };
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, plaintext);

  return {
    protocol: "deadp0et-envelope-v1",
    from: sender.username,
    to: recipientDevice.username,
    envelopeId: crypto.randomUUID(),
    recipientDeviceId: recipientDevice.deviceId,
    oneTimePrekeyId,
    prekeyReservationToken: recipientBundle.prekeyReservationToken,
    ephemeralKey: ephemeralPublic,
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext))
  };
}

async function sendMessage() {
  if (!state.currentUser) {
    setStatus("Create or sign in to an account before sending messages.", "error");
    return;
  }

  const to = normalizeUsername(recipientUsername.value);
  const subject = messageSubject.value.trim();
  const body = messageBody.value.trim();

  if (!to || !subject || !body) {
    setStatus("Recipient, subject, and message body are all required.", "error");
    return;
  }

  if (to === state.currentUser.username) {
    setStatus("Send to a different account so the device bundle lookup path is exercised.", "error");
    return;
  }

  sendButton.disabled = true;
  setStatus(`Reserving recipient prekey bundle for ${to} and encrypting locally...`);

  try {
    const prekeyBundle = await fetchPrekeyBundle(to);
    if (!prekeyBundle || !prekeyBundle.device) {
      throw new Error("Recipient has no active prekey bundle.");
    }

    const envelope = await encryptForRecipient(state.currentUser, prekeyBundle, subject, body);

    const stored = await apiRequest("/v1/messages", {
      method: "POST",
      body: JSON.stringify({
        to: prekeyBundle.username,
        recipientDeviceId: prekeyBundle.device.deviceId,
        envelope: {
          protocol: envelope.protocol,
          ephemeralKey: envelope.ephemeralKey,
          iv: envelope.iv,
          ciphertext: envelope.ciphertext,
          oneTimePrekeyId: envelope.oneTimePrekeyId,
          prekeyReservationToken: envelope.prekeyReservationToken
        }
      })
    });

    state.lastEnvelope = JSON.stringify({
      ...envelope,
      storedAt: stored.storedAt,
      messageId: stored.messageId
    }, null, 2);
    envelopeOutput.value = state.lastEnvelope;
    setSummary(
      envelopeSummary,
      `<strong>${stored.messageId}</strong><br>Stored for <strong>${prekeyBundle.username}</strong> on device <strong>${prekeyBundle.device.deviceId}</strong>`
    );
    copyEnvelopeButton.disabled = false;
    setStatus(
      envelope.oneTimePrekeyId
        ? `Encrypted envelope stored for ${prekeyBundle.username} on device ${prekeyBundle.device.deviceId} using one-time prekey ${envelope.oneTimePrekeyId}.`
        : `Encrypted envelope stored for ${prekeyBundle.username} on device ${prekeyBundle.device.deviceId}.`
    );
    return stored;
  } catch (error) {
    setStatus(error.message, "error");
    throw error;
  } finally {
    sendButton.disabled = false;
  }
}

async function decryptLatest() {
  if (!state.currentUser) {
    setStatus("Sign in before trying to decrypt inbox messages.", "error");
    return;
  }

  const latest = state.inbox[state.inbox.length - 1];
  if (!latest) {
    setStatus("No messages are waiting for this device.", "error");
    return;
  }

  try {
    const sharedSecrets = [await deriveSharedSecret(
      state.currentUser.privateKeys.signedPrekeyPrivateKey,
      latest.envelope.ephemeralKey
    )];
    const oneTimePrekeyId = typeof latest.envelope.oneTimePrekeyId === "string" ? latest.envelope.oneTimePrekeyId.trim() : "";
    if (oneTimePrekeyId) {
      const oneTimePrekeyPrivateKey = state.currentUser.privateKeys.oneTimePrekeyPrivateKeys?.[oneTimePrekeyId];
      if (!oneTimePrekeyPrivateKey) {
        throw new Error("Missing local one-time prekey private key required for this envelope.");
      }
      sharedSecrets.push(await deriveSharedSecret(oneTimePrekeyPrivateKey, latest.envelope.ephemeralKey));
    }

    const aesKey = await deriveAesKey(sharedSecrets);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64ToBytes(latest.envelope.iv) },
      aesKey,
      base64ToBytes(latest.envelope.ciphertext)
    );
    const decoded = JSON.parse(new TextDecoder().decode(plaintext));
    const ackPayload = {
      messageIds: [latest.messageId]
    };
    if (oneTimePrekeyId) {
      ackPayload.oneTimePrekeyProofs = [{
        messageId: latest.messageId,
        oneTimePrekeyId
      }];
    }
    await apiRequest("/v1/messages/inbox/ack", {
      method: "POST",
      body: JSON.stringify(ackPayload)
    });

    if (oneTimePrekeyId) {
      delete state.currentUser.privateKeys.oneTimePrekeyPrivateKeys[oneTimePrekeyId];
      consumeLocalOneTimePrekey(state.currentUser.username, state.currentUser.publicBundle.deviceId, oneTimePrekeyId);
    }
    plaintextOutput.value = JSON.stringify(decoded, null, 2);
    setSummary(
      plaintextSummary,
      `<strong>${decoded.subject}</strong><br>From device <strong>${decoded.senderDeviceId}</strong><br>${decoded.body}`
    );
    setStatus(
      oneTimePrekeyId
        ? `Latest message from ${latest.from} decrypted locally on device ${state.currentUser.session.deviceId} using one-time prekey ${oneTimePrekeyId}.`
        : `Latest message from ${latest.from} decrypted locally on device ${state.currentUser.session.deviceId}.`
    );
  } catch (error) {
    plaintextOutput.value = "";
    setSummary(plaintextSummary, "Unable to decrypt the latest message with the current local device key.", true);
    setStatus("Unable to decrypt the latest envelope with the locally stored device key.", "error");
    throw error;
  }
}

async function copyLastEnvelope() {
  if (!state.lastEnvelope) {
    return;
  }

  try {
    await navigator.clipboard.writeText(state.lastEnvelope);
    setStatus("Last encrypted envelope copied to the clipboard.");
  } catch (error) {
    setStatus("Clipboard access was blocked. Copy the envelope manually.", "error");
  }
}

async function registerAdditionalDevice() {
  if (!state.currentUser) {
    setStatus("Sign in before registering an additional device.", "error");
    return;
  }

  addDeviceButton.disabled = true;
  setStatus("Generating another device bundle in this browser...");

  try {
    const deviceBundle = await generateDeviceBundle();
    await apiRequest("/v1/devices", {
      method: "POST",
      body: JSON.stringify({
        device: deviceBundle.publicBundle
      })
    });

    const localRecord = await serializeLocalDeviceRecord(
      state.currentUser.username,
      state.currentUser.passwordVerifier || "",
      state.currentUser.accountId,
      deviceBundle
    );
    storeLocalDevice(localRecord);
    renderLocalDeviceOptions(state.currentUser.username);
    deviceActionId.value = deviceBundle.publicBundle.deviceId;
    localDeviceSelect.value = deviceBundle.publicBundle.deviceId;
    await fetchDevices();
    setStatus(`Registered additional device ${deviceBundle.publicBundle.deviceId}. Its private keys remain only in this browser unless exported separately.`);
  } catch (error) {
    setStatus(error.message, "error");
    throw error;
  } finally {
    addDeviceButton.disabled = false;
  }
}

async function applyDeviceAction() {
  if (!state.currentUser) {
    setStatus("Sign in before managing devices.", "error");
    return;
  }

  const targetDeviceId = deviceActionId.value.trim();
  const mode = deviceActionMode.value;

  if (!targetDeviceId) {
    setStatus("Enter a device ID before applying a device action.", "error");
    return;
  }

  applyDeviceActionButton.disabled = true;
  setStatus(`${mode === "rotate" ? "Rotating prekeys for" : "Revoking"} ${targetDeviceId}...`);

  try {
    if (mode === "rotate") {
      const deviceBundle = await generateDeviceBundle();
      await apiRequest("/v1/prekeys/rotate", {
        method: "POST",
        body: JSON.stringify({
          deviceId: targetDeviceId,
          signedPrekey: deviceBundle.publicBundle.signedPrekey,
          prekeySignature: deviceBundle.publicBundle.prekeySignature,
          oneTimePrekeys: deviceBundle.publicBundle.oneTimePrekeys || []
        })
      });
      setStatus(`Rotated prekeys for device ${targetDeviceId}.`);
    } else {
      await apiRequest(`/v1/devices/${encodeURIComponent(targetDeviceId)}`, {
        method: "DELETE",
        headers: {}
      });
      setStatus(`Revoked device ${targetDeviceId}.`);
    }

    await fetchDevices();
  } catch (error) {
    setStatus(error.message, "error");
    throw error;
  } finally {
    applyDeviceActionButton.disabled = false;
  }
}

async function exportSelectedDevice() {
  const username = normalizeUsername(signupUsername.value || state.currentUser?.username || "");
  const record = getLocalDevice(username, localDeviceSelect.value);

  if (!record) {
    setStatus("No local device is selected for export.", "error");
    return;
  }

  const payload = JSON.stringify(record, null, 2);
  devicePortabilityOutput.value = payload;
  setSummary(
    devicePortabilitySummary,
    `<strong>Ready to export</strong><br>Local device <strong>${record.deviceId}</strong> for <strong>${record.username}</strong>`
  );

  try {
    await navigator.clipboard.writeText(payload);
    setStatus(`Exported local device ${record.deviceId} to the portability panel and clipboard.`);
  } catch (error) {
    setStatus(`Exported local device ${record.deviceId} to the portability panel.`);
  }
}

function validateImportedRecord(record) {
  if (!record || typeof record !== "object") {
    throw new Error("Imported device payload must be a JSON object.");
  }
  if (!record.username || !record.deviceId || !record.accountId) {
    throw new Error("Imported device payload is missing username, accountId, or deviceId.");
  }
  if (!record.publicBundle || !record.privateKeys) {
    throw new Error("Imported device payload is missing publicBundle or privateKeys.");
  }
  if (!record.privateKeys.identityPrivateKey || !record.privateKeys.signedPrekeyPrivateKey) {
    throw new Error("Imported device payload is missing private key material.");
  }
}

async function importDevicePayload() {
  const raw = devicePortabilityOutput.value.trim();
  if (!raw) {
    setStatus("Paste an exported device payload before importing.", "error");
    return;
  }

  let record;
  try {
    record = JSON.parse(raw);
    validateImportedRecord(record);
  } catch (error) {
    setStatus(error.message || "Imported device payload is not valid JSON.", "error");
    throw error;
  }

  storeLocalDevice(record);
  signupUsername.value = record.username;
  renderLocalDeviceOptions(record.username);
  localDeviceSelect.value = record.deviceId;
  setSummary(
    devicePortabilitySummary,
    `<strong>Imported local device</strong><br><strong>${record.deviceId}</strong> for <strong>${record.username}</strong>`
  );
  setStatus(`Imported local device ${record.deviceId} for ${record.username}. Enter the account password to sign in with it.`);
}

async function bootstrapDemoUsers() {
  bootstrapButton.disabled = true;
  setStatus("Creating demo users iris and noor through the live API...");

  try {
    apiBaseInput.value = getApiBase();

    signupUsername.value = "iris";
    signupPassword.value = "lantern";
    await createAccount();

    signupUsername.value = "noor";
    signupPassword.value = "lantern";
    await createAccount();

    signupUsername.value = "iris";
    signupPassword.value = "lantern";
    await signIn();

    recipientUsername.value = "noor";
    lookupUsername.value = "noor";
    messageSubject.value = "First secure hello";
    messageBody.value = "The backend receives only the envelope. This browser retains the private device key.";
    await fetchBundles("noor");
    await fetchDevices();
    setStatus("Demo users created through the backend. Signed in as iris and ready to send to noor.");
  } catch (error) {
    setStatus(error.message, "error");
    throw error;
  } finally {
    bootstrapButton.disabled = false;
  }
}

saveApiButton.addEventListener("click", () => {
  saveApiBase();
});

healthButton.addEventListener("click", () => {
  fetchHealth().catch((error) => setStatus(error.message, "error"));
});

signupButton.addEventListener("click", () => {
  createAccount().catch((error) => setStatus(error.message, "error"));
});

loginButton.addEventListener("click", () => {
  signIn().catch((error) => setStatus(error.message, "error"));
});

bootstrapButton.addEventListener("click", () => {
  bootstrapDemoUsers().catch((error) => setStatus(error.message, "error"));
});

lookupButton.addEventListener("click", () => {
  fetchBundles().catch((error) => setStatus(error.message, "error"));
});

refreshDevicesButton.addEventListener("click", () => {
  fetchDevices().catch((error) => setStatus(error.message, "error"));
});

addDeviceButton.addEventListener("click", () => {
  registerAdditionalDevice().catch((error) => setStatus(error.message, "error"));
});

applyDeviceActionButton.addEventListener("click", () => {
  applyDeviceAction().catch((error) => setStatus(error.message, "error"));
});

devicesSummary.addEventListener("click", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) {
    return;
  }
  if (target.id !== "replenish-local-prekeys-inline") {
    return;
  }

  const localDeviceId = state.currentUser?.publicBundle?.deviceId;
  if (!localDeviceId) {
    setStatus("Local device is not available.", "error");
    return;
  }
  replenishLocalPrekeys(localDeviceId).catch((error) => setStatus(error.message, "error"));
});

exportDeviceButton.addEventListener("click", () => {
  exportSelectedDevice().catch((error) => setStatus(error.message, "error"));
});

importDeviceButton.addEventListener("click", () => {
  importDevicePayload().catch((error) => setStatus(error.message, "error"));
});

sendButton.addEventListener("click", () => {
  sendMessage().catch((error) => setStatus(error.message, "error"));
});

copyEnvelopeButton.addEventListener("click", () => {
  copyLastEnvelope().catch((error) => setStatus(error.message, "error"));
});

refreshInboxButton.addEventListener("click", () => {
  fetchInbox().catch((error) => setStatus(error.message, "error"));
});

decryptSelectedButton.addEventListener("click", () => {
  decryptLatest().catch((error) => setStatus(error.message, "error"));
});

signupUsername.addEventListener("input", () => {
  renderLocalDeviceOptions(signupUsername.value);
});

apiBaseInput.value = localStorage.getItem(STORAGE_KEYS.apiBase) || getDefaultApiBase();
renderLocalDeviceOptions("");
renderLookupResult(null);
renderSession();
renderInbox([]);
renderDevices(null);
setSummary(healthSummary, "No health check has been run yet.", true);
setSummary(envelopeSummary, "No envelope has been sent yet.", true);
setSummary(plaintextSummary, "No message decrypted yet.", true);
healthOutput.value = "Use Check health to verify the backend endpoint.";
