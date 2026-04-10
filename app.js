const STORAGE_KEYS = {
  apiBase: "deadp0et.apiBase",
  localDevices: "deadp0et.localDevices"
};

const state = {
  currentUser: null,
  currentUsername: "",
  lastEnvelope: "",
  inbox: [],
  lookupCache: null
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
const lookupUsername = document.querySelector("#lookup-username");
const lookupButton = document.querySelector("#lookup-button");

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

function getLocalDevice(username) {
  return loadLocalDevices()[normalizeUsername(username)] || null;
}

function storeLocalDevice(username, record) {
  const devices = loadLocalDevices();
  devices[normalizeUsername(username)] = record;
  saveLocalDevices(devices);
}

async function sha256(text) {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return bytesToBase64(new Uint8Array(digest));
}

async function deriveAesKey(sharedSecret) {
  const secretBytes = base64ToBytes(sharedSecret);
  const digest = await crypto.subtle.digest("SHA-256", secretBytes);
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
  const prekeySignature = await sha256(JSON.stringify(identityPublic) + JSON.stringify(prekeyPublic));

  return {
    privateKeys: {
      identityPrivateKey: identity.privateKey,
      signedPrekeyPrivateKey: signedPrekey.privateKey
    },
    publicBundle: {
      identityKey: identityPublic,
      signedPrekey: prekeyPublic,
      prekeySignature,
      deviceId: crypto.randomUUID()
    }
  };
}

async function serializeLocalDeviceRecord(username, passwordVerifier, accountId, deviceBundle) {
  return {
    username,
    accountId,
    passwordVerifier,
    deviceId: deviceBundle.publicBundle.deviceId,
    publicBundle: deviceBundle.publicBundle,
    privateKeys: {
      identityPrivateKey: await exportKeyPair(deviceBundle.privateKeys.identityPrivateKey),
      signedPrekeyPrivateKey: await exportKeyPair(deviceBundle.privateKeys.signedPrekeyPrivateKey)
    },
    storedAt: new Date().toISOString()
  };
}

async function hydrateLocalDevice(record) {
  if (!record) {
    return null;
  }

  return {
    username: record.username,
    accountId: record.accountId,
    passwordVerifier: record.passwordVerifier,
    publicBundle: record.publicBundle,
    privateKeys: {
      identityPrivateKey: await importPrivateKey(record.privateKeys.identityPrivateKey),
      signedPrekeyPrivateKey: await importPrivateKey(record.privateKeys.signedPrekeyPrivateKey)
    }
  };
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
}

function renderSession() {
  if (!state.currentUser) {
    sessionOutput.value = "No active session.";
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
}

function renderInbox(messages = null) {
  if (!state.currentUser) {
    state.inbox = [];
    inboxOutput.value = "Sign in to fetch encrypted messages.";
    return [];
  }

  if (Array.isArray(messages)) {
    state.inbox = messages;
  }

  inboxOutput.value = state.inbox.length
    ? JSON.stringify(state.inbox, null, 2)
    : "No encrypted envelopes for this device yet.";

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
    setStatus(`Backend reachable at ${getApiBase()}.`);
    return payload;
  } catch (error) {
    healthOutput.value = "";
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
    storeLocalDevice(username, localRecord);
    const hydrated = await hydrateLocalDevice(localRecord);

    state.currentUser = {
      accountId: payload.accountId,
      username: payload.username,
      session: payload.session,
      publicBundle: hydrated.publicBundle,
      privateKeys: hydrated.privateKeys
    };
    state.currentUsername = payload.username;

    renderSession();
    renderInbox([]);
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
    const localRecord = getLocalDevice(username);

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
      publicBundle: hydrated.publicBundle,
      privateKeys: hydrated.privateKeys
    };
    state.currentUsername = payload.username;

    renderSession();
    plaintextOutput.value = "";
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

async function encryptForRecipient(sender, recipientDevice, subject, body) {
  const ephemeral = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
  const ephemeralPublic = await crypto.subtle.exportKey("jwk", ephemeral.publicKey);
  const sharedSecret = await deriveSharedSecret(ephemeral.privateKey, recipientDevice.signedPrekey);
  const aesKey = await deriveAesKey(sharedSecret);
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
  setStatus(`Resolving recipient bundle for ${to} and encrypting locally...`);

  try {
    const bundleResponse = await fetchBundles(to);
    if (!bundleResponse || !bundleResponse.devices.length) {
      throw new Error("Recipient has no active device bundles.");
    }

    const recipientDevice = {
      username: bundleResponse.username,
      ...bundleResponse.devices[0]
    };
    const envelope = await encryptForRecipient(state.currentUser, recipientDevice, subject, body);

    const stored = await apiRequest("/v1/messages", {
      method: "POST",
      body: JSON.stringify({
        to: bundleResponse.username,
        recipientDeviceId: recipientDevice.deviceId,
        envelope: {
          protocol: envelope.protocol,
          ephemeralKey: envelope.ephemeralKey,
          iv: envelope.iv,
          ciphertext: envelope.ciphertext
        }
      })
    });

    state.lastEnvelope = JSON.stringify({
      ...envelope,
      storedAt: stored.storedAt,
      messageId: stored.messageId
    }, null, 2);
    envelopeOutput.value = state.lastEnvelope;
    copyEnvelopeButton.disabled = false;
    setStatus(`Encrypted envelope stored for ${bundleResponse.username} on device ${recipientDevice.deviceId}.`);
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
    const sharedSecret = await deriveSharedSecret(
      state.currentUser.privateKeys.signedPrekeyPrivateKey,
      latest.envelope.ephemeralKey
    );
    const aesKey = await deriveAesKey(sharedSecret);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64ToBytes(latest.envelope.iv) },
      aesKey,
      base64ToBytes(latest.envelope.ciphertext)
    );
    const decoded = JSON.parse(new TextDecoder().decode(plaintext));
    plaintextOutput.value = JSON.stringify(decoded, null, 2);
    setStatus(`Latest message from ${latest.from} decrypted locally on device ${state.currentUser.session.deviceId}.`);
  } catch (error) {
    plaintextOutput.value = "";
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

apiBaseInput.value = localStorage.getItem(STORAGE_KEYS.apiBase) || getDefaultApiBase();
renderLookupResult(null);
renderSession();
renderInbox([]);
healthOutput.value = "Use Check health to verify the backend endpoint.";
