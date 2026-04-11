const crypto = require("crypto");

const { readJsonBody, sendError, sendJson } = require("./http");

function createAuthService(ctx) {
  const authAttemptState = new Map();

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
    return (
      typeof passwordVerifier === "string" &&
      passwordVerifier.length > 0 &&
      passwordVerifier.length <= ctx.config.MAX_PASSWORD_VERIFIER_LENGTH
    );
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

  function getBearerToken(request) {
    const header = request.headers.authorization || "";
    const [scheme, token] = header.split(" ");
    if (scheme !== "Bearer" || !token) {
      return null;
    }
    return token;
  }

  function requireAuth(request, response) {
    const token = getBearerToken(request);
    if (!token) {
      sendError(response, 401, "Missing bearer token.");
      return null;
    }

    const session = ctx.repository.sessions.find((entry) => entry.accessToken === token && !entry.revokedAt);
    if (!session) {
      sendError(response, 401, "Session is invalid or expired.");
      return null;
    }

    if (session.expiresAt && Date.parse(session.expiresAt) <= Date.now()) {
      session.revokedAt = ctx.nowIso();
      ctx.repository.saveStore();
      sendError(response, 401, "Session is invalid or expired.");
      return null;
    }

    const account = ctx.findAccountById(session.accountId);
    if (!account) {
      sendError(response, 401, "Session account no longer exists.");
      return null;
    }

    const sessionDevice = account.devices.find((device) => device.deviceId === session.deviceId);
    if (!sessionDevice || sessionDevice.revokedAt) {
      session.revokedAt = ctx.nowIso();
      ctx.repository.saveStore();
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
    const revokedAt = ctx.nowIso();
    let changed = false;
    const activeSessions = [];
    const activeSessionsByDevice = new Map();

    for (const session of ctx.repository.sessions.all()) {
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
      if (sessionsForDevice.length <= ctx.config.MAX_ACTIVE_SESSIONS_PER_DEVICE) {
        continue;
      }
      sessionsForDevice.sort((a, b) => Date.parse(a.createdAt || 0) - Date.parse(b.createdAt || 0));
      const overflow = sessionsForDevice.length - ctx.config.MAX_ACTIVE_SESSIONS_PER_DEVICE;
      for (let index = 0; index < overflow; index += 1) {
        changed = revokeSession(sessionsForDevice[index], revokedAt) || changed;
      }
    }

    const stillActiveSessions = activeSessions.filter((session) => !session.revokedAt);
    if (stillActiveSessions.length > ctx.config.MAX_ACTIVE_SESSIONS_PER_ACCOUNT) {
      stillActiveSessions.sort((a, b) => Date.parse(a.createdAt || 0) - Date.parse(b.createdAt || 0));
      const overflow = stillActiveSessions.length - ctx.config.MAX_ACTIVE_SESSIONS_PER_ACCOUNT;
      for (let index = 0; index < overflow; index += 1) {
        changed = revokeSession(stillActiveSessions[index], revokedAt) || changed;
      }
    }

    return changed;
  }

  function issueSession(account, deviceId) {
    const activeDeviceId = deviceId || ctx.getActiveDevices(account)[0]?.deviceId || null;
    const session = {
      sessionId: ctx.randomId(),
      accessToken: ctx.randomToken(),
      accountId: account.accountId,
      deviceId: activeDeviceId,
      createdAt: ctx.nowIso(),
      expiresAt: new Date(Date.now() + ctx.config.SESSION_TTL_MS).toISOString(),
      revokedAt: null
    };
    ctx.repository.sessions.push(session);
    pruneSessionsForAccount(account.accountId);
    ctx.repository.saveStore();
    return session;
  }

  function getClientIp(request) {
    const forwardedFor = request.headers["x-forwarded-for"];
    if (typeof forwardedFor === "string" && forwardedFor.trim()) {
      return forwardedFor.split(",")[0].trim().toLowerCase();
    }
    return (request.socket?.remoteAddress || "unknown").toLowerCase();
  }

  function getAuthThrottleKey(request, username) {
    return `${ctx.normalizeUsername(username) || "<unknown>"}|${getClientIp(request)}`;
  }

  function cleanupAuthAttempts(nowMs) {
    for (const [key, entry] of authAttemptState.entries()) {
      const recentAttempts = entry.attempts.filter((timestampMs) => nowMs - timestampMs <= ctx.config.AUTH_WINDOW_MS);
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
    entry.attempts = entry.attempts.filter((timestampMs) => nowMs - timestampMs <= ctx.config.AUTH_WINDOW_MS);
    entry.attempts.push(nowMs);
    if (entry.attempts.length >= ctx.config.AUTH_MAX_ATTEMPTS_PER_KEY) {
      entry.blockedUntilMs = nowMs + ctx.config.AUTH_BLOCK_MS;
      entry.attempts = [];
    }
    authAttemptState.set(key, entry);
  }

  function clearAuthFailures(key) {
    authAttemptState.delete(key);
  }

  async function handleCreateAccount(request, response) {
    const body = await readJsonBody(request);
    const username = ctx.normalizeUsername(body.username);
    const passwordVerifier = typeof body.passwordVerifier === "string" ? body.passwordVerifier.trim() : "";
    const deviceError = ctx.validateDevicePayload(body.device);

    if (!username) {
      sendError(response, 400, "username is required.");
      return;
    }

    if (!passwordVerifier) {
      sendError(response, 400, "passwordVerifier is required.");
      return;
    }
    if (!isVerifierLengthValid(passwordVerifier)) {
      sendError(response, 400, `passwordVerifier must be 1-${ctx.config.MAX_PASSWORD_VERIFIER_LENGTH} characters.`);
      return;
    }

    if (deviceError) {
      sendError(response, 400, deviceError);
      return;
    }

    if (ctx.findAccountByUsername(username)) {
      sendError(response, 409, "That username already exists.");
      return;
    }

    const account = {
      accountId: ctx.randomId(),
      username,
      verifier: deriveVerifierRecord(passwordVerifier),
      createdAt: ctx.nowIso(),
      profile: {
        joinedAt: ctx.nowIso()
      },
      devices: [
        {
          deviceId: body.device.deviceId,
          identityKey: body.device.identityKey,
          signedPrekey: body.device.signedPrekey,
          prekeySignature: body.device.prekeySignature,
          oneTimePrekeys: Array.isArray(body.device.oneTimePrekeys) ? body.device.oneTimePrekeys : [],
          registeredAt: ctx.nowIso(),
          revokedAt: null
        }
      ]
    };

    ctx.repository.accounts.push(account);
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
    const username = ctx.normalizeUsername(body.username);
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

    const account = ctx.findAccountByUsername(username);
    if (!account || !verifyVerifierRecord(account, passwordVerifier)) {
      registerAuthFailure(throttleKey, nowMs);
      sendError(response, 401, "Invalid credentials.");
      return;
    }

    const migratedLegacyVerifier = migrateLegacyVerifier(account, passwordVerifier);
    const activeDevices = ctx.getActiveDevices(account);
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
      ctx.repository.saveStore();
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

  return {
    handleCreateAccount,
    handleCreateSession,
    issueSession,
    requireAuth
  };
}

module.exports = {
  createAuthService
};
