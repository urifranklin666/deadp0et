const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const HOST = process.env.HOST || "0.0.0.0";
const PORT = Number(process.env.PORT || 3000);
const SESSION_TTL_MS = Number(process.env.SESSION_TTL_MS || 7 * 24 * 60 * 60 * 1000);
const MAX_ACTIVE_SESSIONS_PER_ACCOUNT = Math.max(1, Number(process.env.MAX_ACTIVE_SESSIONS_PER_ACCOUNT || 12));
const MAX_ACTIVE_SESSIONS_PER_DEVICE = Math.max(1, Number(process.env.MAX_ACTIVE_SESSIONS_PER_DEVICE || 4));
const MAX_PASSWORD_VERIFIER_LENGTH = Number(process.env.MAX_PASSWORD_VERIFIER_LENGTH || 4096);
const AUTH_WINDOW_MS = Math.max(1000, Number(process.env.AUTH_WINDOW_MS || 10 * 60 * 1000));
const AUTH_MAX_ATTEMPTS_PER_KEY = Math.max(1, Number(process.env.AUTH_MAX_ATTEMPTS_PER_KEY || 8));
const AUTH_BLOCK_MS = Math.max(1000, Number(process.env.AUTH_BLOCK_MS || 15 * 60 * 1000));
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const DATA_FILE = path.join(DATA_DIR, "store.json");
const STATIC_FILES = {
  "/": { filePath: path.join(__dirname, "index.html"), contentType: "text/html; charset=utf-8" },
  "/index.html": { filePath: path.join(__dirname, "index.html"), contentType: "text/html; charset=utf-8" },
  "/app.js": { filePath: path.join(__dirname, "app.js"), contentType: "application/javascript; charset=utf-8" },
  "/styles.css": { filePath: path.join(__dirname, "styles.css"), contentType: "text/css; charset=utf-8" }
};

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

function deriveVerifierRecord(passwordVerifier) {
  const salt = crypto.randomBytes(16).toString("hex");
  const digest = crypto.scryptSync(passwordVerifier, salt, 64).toString("hex");
  return {
    salt,
    digest,
    algorithm: "scrypt"
  };
}

function isVerifierLengthValid(passwordVerifier) {
  return typeof passwordVerifier === "string" && passwordVerifier.length > 0 && passwordVerifier.length <= MAX_PASSWORD_VERIFIER_LENGTH;
}

function verifyVerifierRecord(account, passwordVerifier) {
  if (!isVerifierLengthValid(passwordVerifier)) {
    return false;
  }

  if (account.verifier && account.verifier.salt && account.verifier.digest) {
    const candidate = crypto.scryptSync(passwordVerifier, account.verifier.salt, 64).toString("hex");
    const candidateBuffer = Buffer.from(candidate, "hex");
    const digestBuffer = Buffer.from(account.verifier.digest, "hex");
    if (candidateBuffer.length === 0 || digestBuffer.length === 0 || candidateBuffer.length !== digestBuffer.length) {
      return false;
    }
    return crypto.timingSafeEqual(candidateBuffer, digestBuffer);
  }

  if (typeof account.passwordVerifier === "string" && account.passwordVerifier) {
    const accountVerifierBuffer = Buffer.from(account.passwordVerifier, "utf8");
    const candidateBuffer = Buffer.from(passwordVerifier, "utf8");
    if (accountVerifierBuffer.length !== candidateBuffer.length) {
      return false;
    }
    return crypto.timingSafeEqual(accountVerifierBuffer, candidateBuffer);
  }

  return false;
}

function migrateLegacyVerifier(account, passwordVerifier) {
  if (account.verifier || typeof account.passwordVerifier !== "string") {
    return false;
  }

  account.verifier = deriveVerifierRecord(passwordVerifier);
  delete account.passwordVerifier;
  return true;
}

function ensureDirectory(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function defaultStore() {
  return {
    accounts: [],
    sessions: [],
    messages: []
  };
}

function loadStore() {
  try {
    const raw = fs.readFileSync(DATA_FILE, "utf8");
    const parsed = JSON.parse(raw);
    return {
      accounts: Array.isArray(parsed.accounts) ? parsed.accounts : [],
      sessions: Array.isArray(parsed.sessions) ? parsed.sessions : [],
      messages: Array.isArray(parsed.messages) ? parsed.messages : []
    };
  } catch (error) {
    if (error.code === "ENOENT") {
      return defaultStore();
    }
    throw error;
  }
}

function saveStore(store) {
  ensureDirectory(DATA_DIR);
  fs.writeFileSync(DATA_FILE, JSON.stringify(store, null, 2));
}

const store = loadStore();
const authAttemptState = new Map();

function sendJson(response, statusCode, payload) {
  response.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store"
  });
  response.end(JSON.stringify(payload, null, 2));
}

function sendError(response, statusCode, message, details) {
  sendJson(response, statusCode, {
    error: {
      message,
      details: details || null
    }
  });
}

function notFound(response) {
  sendError(response, 404, "Route not found.");
}

function methodNotAllowed(response, method) {
  sendError(response, 405, `Method ${method} is not allowed for this route.`);
}

function readJsonBody(request) {
  return new Promise((resolve, reject) => {
    let body = "";
    request.on("data", (chunk) => {
      body += chunk;
      if (body.length > 1024 * 1024) {
        reject(new Error("Request body exceeds 1 MiB."));
        request.destroy();
      }
    });
    request.on("end", () => {
      if (!body) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(body));
      } catch (error) {
        reject(new Error("Request body must be valid JSON."));
      }
    });
    request.on("error", reject);
  });
}

function getBearerToken(request) {
  const header = request.headers.authorization || "";
  const [scheme, token] = header.split(" ");
  if (scheme !== "Bearer" || !token) {
    return null;
  }
  return token;
}

function findAccountByUsername(username) {
  const normalized = normalizeUsername(username);
  return store.accounts.find((account) => account.username === normalized) || null;
}

function findAccountById(accountId) {
  return store.accounts.find((account) => account.accountId === accountId) || null;
}

function getPublicDeviceBundle(device) {
  return {
    deviceId: device.deviceId,
    identityKey: device.identityKey,
    signedPrekey: device.signedPrekey,
    prekeySignature: device.prekeySignature,
    oneTimePrekeys: Array.isArray(device.oneTimePrekeys) ? device.oneTimePrekeys : [],
    registeredAt: device.registeredAt,
    revokedAt: device.revokedAt || null
  };
}

function getActiveDevices(account) {
  return account.devices.filter((device) => !device.revokedAt);
}

function ensureDevicePrekeyCollections(device) {
  if (!Array.isArray(device.oneTimePrekeys)) {
    device.oneTimePrekeys = [];
  }
  if (!Array.isArray(device.consumedOneTimePrekeys)) {
    device.consumedOneTimePrekeys = [];
  }
}

function reserveOneTimePrekey(device) {
  ensureDevicePrekeyCollections(device);
  const reservedPrekey = device.oneTimePrekeys.shift();
  if (!reservedPrekey) {
    return null;
  }
  const consumedAt = nowIso();
  device.consumedOneTimePrekeys.push({
    consumedAt,
    prekey: reservedPrekey
  });
  return {
    prekey: reservedPrekey,
    consumedAt
  };
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

function requireAuth(request, response) {
  const token = getBearerToken(request);
  if (!token) {
    sendError(response, 401, "Missing bearer token.");
    return null;
  }

  const session = store.sessions.find((entry) => entry.accessToken === token && !entry.revokedAt);
  if (!session) {
    sendError(response, 401, "Session is invalid or expired.");
    return null;
  }

  if (session.expiresAt && Date.parse(session.expiresAt) <= Date.now()) {
    session.revokedAt = nowIso();
    saveStore(store);
    sendError(response, 401, "Session is invalid or expired.");
    return null;
  }

  const account = findAccountById(session.accountId);
  if (!account) {
    sendError(response, 401, "Session account no longer exists.");
    return null;
  }

  const sessionDevice = account.devices.find((device) => device.deviceId === session.deviceId);
  if (!sessionDevice || sessionDevice.revokedAt) {
    session.revokedAt = nowIso();
    saveStore(store);
    sendError(response, 401, "Session device is no longer active.");
    return null;
  }

  return { session, account };
}

function revokeSession(session, revokedAt) {
  if (!session.revokedAt) {
    session.revokedAt = revokedAt;
    return true;
  }
  return false;
}

function pruneSessionsForAccount(accountId) {
  const revokedAt = nowIso();
  let changed = false;
  const activeSessions = [];
  const activeSessionsByDevice = new Map();

  for (const session of store.sessions) {
    if (session.accountId !== accountId) {
      continue;
    }

    const isExpired = session.expiresAt && Date.parse(session.expiresAt) <= Date.now();
    if (isExpired) {
      changed = revokeSession(session, revokedAt) || changed;
      continue;
    }

    if (!session.revokedAt) {
      activeSessions.push(session);
      const bucket = activeSessionsByDevice.get(session.deviceId) || [];
      bucket.push(session);
      activeSessionsByDevice.set(session.deviceId, bucket);
    }
  }

  for (const sessionsForDevice of activeSessionsByDevice.values()) {
    if (sessionsForDevice.length <= MAX_ACTIVE_SESSIONS_PER_DEVICE) {
      continue;
    }
    sessionsForDevice.sort((a, b) => Date.parse(a.createdAt || 0) - Date.parse(b.createdAt || 0));
    const overflow = sessionsForDevice.length - MAX_ACTIVE_SESSIONS_PER_DEVICE;
    for (let index = 0; index < overflow; index += 1) {
      changed = revokeSession(sessionsForDevice[index], revokedAt) || changed;
    }
  }

  const stillActiveSessions = activeSessions.filter((session) => !session.revokedAt);
  if (stillActiveSessions.length > MAX_ACTIVE_SESSIONS_PER_ACCOUNT) {
    stillActiveSessions.sort((a, b) => Date.parse(a.createdAt || 0) - Date.parse(b.createdAt || 0));
    const overflow = stillActiveSessions.length - MAX_ACTIVE_SESSIONS_PER_ACCOUNT;
    for (let index = 0; index < overflow; index += 1) {
      changed = revokeSession(stillActiveSessions[index], revokedAt) || changed;
    }
  }

  return changed;
}

function issueSession(account, deviceId) {
  const activeDeviceId = deviceId || getActiveDevices(account)[0]?.deviceId || null;
  const session = {
    sessionId: randomId(),
    accessToken: randomToken(),
    accountId: account.accountId,
    deviceId: activeDeviceId,
    createdAt: nowIso(),
    expiresAt: new Date(Date.now() + SESSION_TTL_MS).toISOString(),
    revokedAt: null
  };
  store.sessions.push(session);
  pruneSessionsForAccount(account.accountId);
  saveStore(store);
  return session;
}

function parseUrl(request) {
  return new URL(request.url, `http://${request.headers.host || "localhost"}`);
}

function getClientIp(request) {
  const forwardedFor = request.headers["x-forwarded-for"];
  if (typeof forwardedFor === "string" && forwardedFor.trim()) {
    return forwardedFor.split(",")[0].trim().toLowerCase();
  }
  return (request.socket?.remoteAddress || "unknown").toLowerCase();
}

function getAuthThrottleKey(request, username) {
  return `${normalizeUsername(username) || "<unknown>"}|${getClientIp(request)}`;
}

function cleanupAuthAttempts(nowMs) {
  for (const [key, entry] of authAttemptState.entries()) {
    const recentAttempts = entry.attempts.filter((timestampMs) => nowMs - timestampMs <= AUTH_WINDOW_MS);
    const blockStillActive = entry.blockedUntilMs && entry.blockedUntilMs > nowMs;
    if (recentAttempts.length === 0 && !blockStillActive) {
      authAttemptState.delete(key);
      continue;
    }
    entry.attempts = recentAttempts;
  }
}

function getAuthThrottleState(key, nowMs) {
  cleanupAuthAttempts(nowMs);
  const entry = authAttemptState.get(key);
  if (!entry) {
    return { blocked: false, retryAfterMs: 0 };
  }
  if (entry.blockedUntilMs && entry.blockedUntilMs > nowMs) {
    return { blocked: true, retryAfterMs: entry.blockedUntilMs - nowMs };
  }
  return { blocked: false, retryAfterMs: 0 };
}

function registerAuthFailure(key, nowMs) {
  const entry = authAttemptState.get(key) || { attempts: [], blockedUntilMs: 0 };
  entry.attempts = entry.attempts.filter((timestampMs) => nowMs - timestampMs <= AUTH_WINDOW_MS);
  entry.attempts.push(nowMs);
  if (entry.attempts.length >= AUTH_MAX_ATTEMPTS_PER_KEY) {
    entry.blockedUntilMs = nowMs + AUTH_BLOCK_MS;
    entry.attempts = [];
  }
  authAttemptState.set(key, entry);
}

function clearAuthFailures(key) {
  authAttemptState.delete(key);
}

async function handleCreateAccount(request, response) {
  const body = await readJsonBody(request);
  const username = normalizeUsername(body.username);
  const passwordVerifier = typeof body.passwordVerifier === "string" ? body.passwordVerifier.trim() : "";
  const deviceError = validateDevicePayload(body.device);

  if (!username) {
    sendError(response, 400, "username is required.");
    return;
  }

  if (!passwordVerifier) {
    sendError(response, 400, "passwordVerifier is required.");
    return;
  }
  if (!isVerifierLengthValid(passwordVerifier)) {
    sendError(response, 400, `passwordVerifier must be 1-${MAX_PASSWORD_VERIFIER_LENGTH} characters.`);
    return;
  }

  if (deviceError) {
    sendError(response, 400, deviceError);
    return;
  }

  if (findAccountByUsername(username)) {
    sendError(response, 409, "That username already exists.");
    return;
  }

  const account = {
    accountId: randomId(),
    username,
    verifier: deriveVerifierRecord(passwordVerifier),
    createdAt: nowIso(),
    profile: {
      joinedAt: nowIso()
    },
    devices: [
      {
        deviceId: body.device.deviceId,
        identityKey: body.device.identityKey,
        signedPrekey: body.device.signedPrekey,
        prekeySignature: body.device.prekeySignature,
        oneTimePrekeys: Array.isArray(body.device.oneTimePrekeys) ? body.device.oneTimePrekeys : [],
        registeredAt: nowIso(),
        revokedAt: null
      }
    ]
  };

  store.accounts.push(account);
  const session = issueSession(account, body.device.deviceId);

  sendJson(response, 201, {
    accountId: account.accountId,
    username: account.username,
    session: {
      accessToken: session.accessToken,
      deviceId: session.deviceId,
      expiresAt: session.expiresAt
    }
  });
}

async function handleCreateSession(request, response) {
  const body = await readJsonBody(request);
  const username = normalizeUsername(body.username);
  const passwordVerifier = typeof body.passwordVerifier === "string" ? body.passwordVerifier.trim() : "";
  const requestedDeviceId = typeof body.deviceId === "string" ? body.deviceId.trim() : "";
  const throttleKey = getAuthThrottleKey(request, username);
  const nowMs = Date.now();
  const throttleState = getAuthThrottleState(throttleKey, nowMs);

  if (throttleState.blocked) {
    response.setHeader("Retry-After", String(Math.max(1, Math.ceil(throttleState.retryAfterMs / 1000))));
    sendError(response, 429, "Too many login attempts. Try again later.");
    return;
  }

  if (!username || !passwordVerifier) {
    registerAuthFailure(throttleKey, nowMs);
    sendError(response, 400, "username and passwordVerifier are required.");
    return;
  }
  if (!isVerifierLengthValid(passwordVerifier)) {
    registerAuthFailure(throttleKey, nowMs);
    sendError(response, 401, "Invalid credentials.");
    return;
  }

  const account = findAccountByUsername(username);
  if (!account || !verifyVerifierRecord(account, passwordVerifier)) {
    registerAuthFailure(throttleKey, nowMs);
    sendError(response, 401, "Invalid credentials.");
    return;
  }

  const migratedLegacyVerifier = migrateLegacyVerifier(account, passwordVerifier);
  const activeDevices = getActiveDevices(account);
  if (activeDevices.length === 0) {
    sendError(response, 409, "No active devices remain on this account.");
    return;
  }

  if (requestedDeviceId && !activeDevices.some((device) => device.deviceId === requestedDeviceId)) {
    registerAuthFailure(throttleKey, nowMs);
    sendError(response, 404, "Requested device is not active for this account.");
    return;
  }

  const session = issueSession(account, requestedDeviceId || activeDevices[0].deviceId);
  clearAuthFailures(throttleKey);
  if (migratedLegacyVerifier) {
    saveStore(store);
  }

  sendJson(response, 200, {
    accountId: account.accountId,
    username: account.username,
    session: {
      accessToken: session.accessToken,
      deviceId: session.deviceId,
      expiresAt: session.expiresAt
    }
  });
}

function handleGetBundles(response, username) {
  const account = findAccountByUsername(username);
  if (!account) {
    sendError(response, 404, "Recipient account was not found.");
    return;
  }

  sendJson(response, 200, {
    username: account.username,
    devices: getActiveDevices(account).map(getPublicDeviceBundle)
  });
}

async function handleIssuePrekeyBundle(request, response, username) {
  const account = findAccountByUsername(username);
  if (!account) {
    sendError(response, 404, "Recipient account was not found.");
    return;
  }

  const body = await readJsonBody(request);
  const requestedDeviceIdRaw = body.deviceId;
  if (requestedDeviceIdRaw !== undefined && typeof requestedDeviceIdRaw !== "string") {
    sendError(response, 400, "deviceId must be a string when provided.");
    return;
  }
  const requestedDeviceId = typeof requestedDeviceIdRaw === "string" ? requestedDeviceIdRaw.trim() : "";

  const activeDevices = getActiveDevices(account);
  if (activeDevices.length === 0) {
    sendError(response, 404, "Recipient has no active devices.");
    return;
  }

  let selectedDevice = null;
  if (requestedDeviceId) {
    selectedDevice = activeDevices.find((device) => device.deviceId === requestedDeviceId) || null;
    if (!selectedDevice) {
      sendError(response, 404, "Requested device is not active for this recipient.");
      return;
    }
  } else {
    selectedDevice =
      activeDevices.find((device) => Array.isArray(device.oneTimePrekeys) && device.oneTimePrekeys.length > 0) || activeDevices[0];
  }

  const reservedOneTimePrekey = reserveOneTimePrekey(selectedDevice);
  if (reservedOneTimePrekey) {
    saveStore(store);
  }

  sendJson(response, 200, {
    username: account.username,
    issuedAt: nowIso(),
    device: {
      deviceId: selectedDevice.deviceId,
      identityKey: selectedDevice.identityKey,
      signedPrekey: selectedDevice.signedPrekey,
      prekeySignature: selectedDevice.prekeySignature
    },
    oneTimePrekey: reservedOneTimePrekey ? reservedOneTimePrekey.prekey : null,
    oneTimePrekeyConsumedAt: reservedOneTimePrekey ? reservedOneTimePrekey.consumedAt : null
  });
}

async function handleStoreMessage(request, response) {
  const auth = requireAuth(request, response);
  if (!auth) {
    return;
  }

  const body = await readJsonBody(request);
  const recipientUsername = normalizeUsername(body.to);
  const recipientDeviceId = typeof body.recipientDeviceId === "string" ? body.recipientDeviceId.trim() : "";
  const envelope = body.envelope;

  if (!recipientUsername || !recipientDeviceId || !envelope || typeof envelope !== "object") {
    sendError(response, 400, "to, recipientDeviceId, and envelope are required.");
    return;
  }

  const recipient = findAccountByUsername(recipientUsername);
  if (!recipient) {
    sendError(response, 404, "Recipient account was not found.");
    return;
  }

  const targetDevice = recipient.devices.find((device) => device.deviceId === recipientDeviceId && !device.revokedAt);
  if (!targetDevice) {
    sendError(response, 404, "Recipient device was not found or is revoked.");
    return;
  }

  const requiredEnvelopeFields = ["protocol", "iv", "ciphertext"];
  for (const field of requiredEnvelopeFields) {
    if (typeof envelope[field] !== "string" || !envelope[field].trim()) {
      sendError(response, 400, `envelope.${field} is required.`);
      return;
    }
  }

  const ephemeralKeyError = validateJwkLike(envelope.ephemeralKey, "envelope.ephemeralKey");
  if (ephemeralKeyError) {
    sendError(response, 400, ephemeralKeyError);
    return;
  }

  const oneTimePrekeyId = envelope.oneTimePrekeyId;
  if (oneTimePrekeyId !== undefined && (typeof oneTimePrekeyId !== "string" || !oneTimePrekeyId.trim())) {
    sendError(response, 400, "envelope.oneTimePrekeyId must be a non-empty string when provided.");
    return;
  }

  const message = {
    messageId: randomId(),
    to: recipient.username,
    recipientDeviceId,
    from: auth.account.username,
    senderDeviceId: auth.session.deviceId,
    envelope: {
      protocol: envelope.protocol,
      ephemeralKey: envelope.ephemeralKey,
      iv: envelope.iv,
      ciphertext: envelope.ciphertext,
      oneTimePrekeyId: oneTimePrekeyId ? oneTimePrekeyId.trim() : null
    },
    storedAt: nowIso(),
    deliveredAt: null,
    readAt: null,
    deliveryCount: 0
  };

  store.messages.push(message);
  saveStore(store);

  sendJson(response, 201, {
    messageId: message.messageId,
    to: message.to,
    recipientDeviceId: message.recipientDeviceId,
    storedAt: message.storedAt
  });
}

function handleInbox(request, response) {
  const auth = requireAuth(request, response);
  if (!auth) {
    return;
  }

  const url = parseUrl(request);
  const deviceIdFilter = url.searchParams.get("deviceId") || auth.session.deviceId;

  let storeChanged = false;

  const messages = store.messages
    .filter((message) => {
      if (message.to !== auth.account.username) {
        return false;
      }
      if (deviceIdFilter) {
        return message.recipientDeviceId === deviceIdFilter;
      }
      return true;
    })
    .map((message) => {
      if (!message.deliveredAt) {
        message.deliveredAt = nowIso();
      }
      message.deliveryCount = (message.deliveryCount || 0) + 1;
      storeChanged = true;

      return {
        messageId: message.messageId,
        to: message.to,
        recipientDeviceId: message.recipientDeviceId,
        from: message.from,
        senderDeviceId: message.senderDeviceId,
        storedAt: message.storedAt,
        deliveredAt: message.deliveredAt,
        readAt: message.readAt || null,
        deliveryCount: message.deliveryCount,
        envelope: message.envelope
      };
    });

  if (storeChanged) {
    saveStore(store);
  }

  sendJson(response, 200, {
    username: auth.account.username,
    deviceId: deviceIdFilter || null,
    messages
  });
}

async function handleAcknowledgeInbox(request, response) {
  const auth = requireAuth(request, response);
  if (!auth) {
    return;
  }

  const body = await readJsonBody(request);
  if (!Array.isArray(body.messageIds) || body.messageIds.length === 0) {
    sendError(response, 400, "messageIds must be a non-empty array.");
    return;
  }

  const targetMessageIds = new Set(
    body.messageIds.filter((messageId) => typeof messageId === "string" && messageId.trim()).map((messageId) => messageId.trim())
  );

  if (targetMessageIds.size === 0) {
    sendError(response, 400, "messageIds must include at least one valid message id.");
    return;
  }

  let updated = 0;
  const acknowledgedAt = nowIso();

  for (const message of store.messages) {
    if (!targetMessageIds.has(message.messageId)) {
      continue;
    }
    if (message.to !== auth.account.username || message.recipientDeviceId !== auth.session.deviceId) {
      continue;
    }
    if (!message.readAt) {
      message.readAt = acknowledgedAt;
      updated += 1;
    }
  }

  saveStore(store);

  sendJson(response, 200, {
    username: auth.account.username,
    deviceId: auth.session.deviceId,
    acknowledged: updated,
    acknowledgedAt
  });
}

async function handleRegisterDevice(request, response) {
  const auth = requireAuth(request, response);
  if (!auth) {
    return;
  }

  const body = await readJsonBody(request);
  const deviceError = validateDevicePayload(body.device);
  if (deviceError) {
    sendError(response, 400, deviceError);
    return;
  }

  if (auth.account.devices.some((device) => device.deviceId === body.device.deviceId)) {
    sendError(response, 409, "That deviceId is already registered on the account.");
    return;
  }

  const device = {
    deviceId: body.device.deviceId,
    identityKey: body.device.identityKey,
    signedPrekey: body.device.signedPrekey,
    prekeySignature: body.device.prekeySignature,
    oneTimePrekeys: Array.isArray(body.device.oneTimePrekeys) ? body.device.oneTimePrekeys : [],
    registeredAt: nowIso(),
    revokedAt: null
  };

  auth.account.devices.push(device);
  saveStore(store);

  sendJson(response, 201, {
    username: auth.account.username,
    device: getPublicDeviceBundle(device)
  });
}

function handleListDevices(request, response) {
  const auth = requireAuth(request, response);
  if (!auth) {
    return;
  }

  sendJson(response, 200, {
    username: auth.account.username,
    devices: auth.account.devices.map(getPublicDeviceBundle)
  });
}

function handleDeleteDevice(response, auth, deviceId) {
  const device = auth.account.devices.find((entry) => entry.deviceId === deviceId);
  if (!device) {
    sendError(response, 404, "Device was not found.");
    return;
  }

  if (device.revokedAt) {
    sendError(response, 409, "Device is already revoked.");
    return;
  }

  if (getActiveDevices(auth.account).length <= 1) {
    sendError(response, 409, "Cannot revoke the last active device on the account.");
    return;
  }

  device.revokedAt = nowIso();
  store.sessions.forEach((session) => {
    if (session.accountId === auth.account.accountId && session.deviceId === deviceId && !session.revokedAt) {
      session.revokedAt = nowIso();
    }
  });
  saveStore(store);

  sendJson(response, 200, {
    username: auth.account.username,
    deviceId,
    revokedAt: device.revokedAt
  });
}

async function handleRotatePrekeys(request, response) {
  const auth = requireAuth(request, response);
  if (!auth) {
    return;
  }

  const body = await readJsonBody(request);
  const deviceId = typeof body.deviceId === "string" && body.deviceId.trim() ? body.deviceId.trim() : auth.session.deviceId;
  const signedPrekey = body.signedPrekey;
  const prekeySignature = typeof body.prekeySignature === "string" ? body.prekeySignature.trim() : "";
  const oneTimePrekeys = body.oneTimePrekeys;

  const device = auth.account.devices.find((entry) => entry.deviceId === deviceId && !entry.revokedAt);
  if (!device) {
    sendError(response, 404, "Active device was not found.");
    return;
  }

  const prekeyError = validateJwkLike(signedPrekey, "signedPrekey");
  if (prekeyError) {
    sendError(response, 400, prekeyError);
    return;
  }

  if (!prekeySignature) {
    sendError(response, 400, "prekeySignature is required.");
    return;
  }

  if (oneTimePrekeys !== undefined && !Array.isArray(oneTimePrekeys)) {
    sendError(response, 400, "oneTimePrekeys must be an array when provided.");
    return;
  }

  device.signedPrekey = signedPrekey;
  device.prekeySignature = prekeySignature;
  if (Array.isArray(oneTimePrekeys)) {
    device.oneTimePrekeys = oneTimePrekeys;
  }
  device.prekeysRotatedAt = nowIso();
  saveStore(store);

  sendJson(response, 200, {
    username: auth.account.username,
    device: getPublicDeviceBundle(device)
  });
}

function handleHealth(response) {
  sendJson(response, 200, {
    status: "ok",
    accounts: store.accounts.length,
    sessions: store.sessions.filter((session) => !session.revokedAt && (!session.expiresAt || Date.parse(session.expiresAt) > Date.now())).length,
    messages: store.messages.length
  });
}

function handleStatic(response, pathname) {
  const asset = STATIC_FILES[pathname];
  if (!asset) {
    return false;
  }

  try {
    const content = fs.readFileSync(asset.filePath);
    response.writeHead(200, {
      "Content-Type": asset.contentType,
      "Cache-Control": pathname === "/" || pathname === "/index.html" ? "no-store" : "public, max-age=300"
    });
    response.end(content);
    return true;
  } catch (error) {
    sendError(response, 500, "Unable to serve static asset.", error.message);
    return true;
  }
}

const server = http.createServer(async (request, response) => {
  response.setHeader("Access-Control-Allow-Origin", "*");
  response.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  response.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");

  if (request.method === "OPTIONS") {
    response.writeHead(204);
    response.end();
    return;
  }

  try {
    const url = parseUrl(request);
    const pathname = url.pathname;

    if (request.method === "GET" && pathname === "/health") {
      handleHealth(response);
      return;
    }

    if (pathname === "/v1/accounts") {
      if (request.method !== "POST") {
        methodNotAllowed(response, request.method);
        return;
      }
      await handleCreateAccount(request, response);
      return;
    }

    if (pathname === "/v1/sessions") {
      if (request.method !== "POST") {
        methodNotAllowed(response, request.method);
        return;
      }
      await handleCreateSession(request, response);
      return;
    }

    if (request.method === "GET" && pathname.startsWith("/v1/users/") && pathname.endsWith("/bundles")) {
      const username = decodeURIComponent(pathname.slice("/v1/users/".length, -"/bundles".length));
      handleGetBundles(response, username);
      return;
    }

    if (pathname.startsWith("/v1/users/") && pathname.endsWith("/prekey-bundle")) {
      if (request.method !== "POST") {
        methodNotAllowed(response, request.method);
        return;
      }
      const username = decodeURIComponent(pathname.slice("/v1/users/".length, -"/prekey-bundle".length));
      await handleIssuePrekeyBundle(request, response, username);
      return;
    }

    if (pathname === "/v1/messages") {
      if (request.method !== "POST") {
        methodNotAllowed(response, request.method);
        return;
      }
      await handleStoreMessage(request, response);
      return;
    }

    if (pathname === "/v1/messages/inbox") {
      if (request.method === "GET") {
        handleInbox(request, response);
        return;
      }
      if (request.method === "POST") {
        await handleAcknowledgeInbox(request, response);
        return;
      }
      methodNotAllowed(response, request.method);
      return;
    }

    if (pathname === "/v1/messages/inbox/ack") {
      if (request.method !== "POST") {
        methodNotAllowed(response, request.method);
        return;
      }
      await handleAcknowledgeInbox(request, response);
      return;
    }

    if (pathname === "/v1/devices") {
      if (request.method === "GET") {
        handleListDevices(request, response);
        return;
      }
      if (request.method === "POST") {
        await handleRegisterDevice(request, response);
        return;
      }
      methodNotAllowed(response, request.method);
      return;
    }

    if (request.method === "DELETE" && pathname.startsWith("/v1/devices/")) {
      const auth = requireAuth(request, response);
      if (!auth) {
        return;
      }
      const deviceId = decodeURIComponent(pathname.slice("/v1/devices/".length));
      handleDeleteDevice(response, auth, deviceId);
      return;
    }

    if (pathname === "/v1/prekeys/rotate") {
      if (request.method !== "POST") {
        methodNotAllowed(response, request.method);
        return;
      }
      await handleRotatePrekeys(request, response);
      return;
    }

    if (request.method === "GET" && handleStatic(response, pathname)) {
      return;
    }

    notFound(response);
  } catch (error) {
    sendError(response, 500, "Internal server error.", error.message);
  }
});

server.listen(PORT, HOST, () => {
  ensureDirectory(DATA_DIR);
  console.log(`deadp0et backend listening on http://${HOST}:${PORT}`);
});
