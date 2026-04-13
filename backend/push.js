const { readJsonBody, sendError, sendJson } = require("./http");

function createPushService(ctx, auth) {
  function sanitizePlatform(value) {
    return typeof value === "string" ? value.trim().toLowerCase() : "";
  }

  function sanitizeToken(value) {
    return typeof value === "string" ? value.trim() : "";
  }

  function listRegistrationsForAccount(accountId, deviceId = "") {
    return ctx.repository.pushRegistrations
      .filter((entry) => entry.accountId === accountId && (!deviceId || entry.deviceId === deviceId))
      .sort((left, right) => Date.parse(right.updatedAt || 0) - Date.parse(left.updatedAt || 0));
  }

  function serializeRegistration(registration) {
    return {
      registrationId: registration.registrationId,
      deviceId: registration.deviceId,
      token: registration.token,
      platform: registration.platform,
      provider: registration.provider,
      createdAt: registration.createdAt,
      updatedAt: registration.updatedAt
    };
  }

  function queueMessageNotifications(message) {
    const registrations = listRegistrationsForAccount(message.recipientAccountId, message.recipientDeviceId);
    if (!registrations.length) {
      return 0;
    }

    const now = ctx.nowIso();
    for (const registration of registrations) {
      ctx.repository.notificationEvents.push({
        eventId: ctx.randomId(),
        type: "new_message_available",
        accountId: message.recipientAccountId,
        username: message.to,
        deviceId: message.recipientDeviceId,
        token: registration.token,
        platform: registration.platform,
        provider: registration.provider,
        messageId: message.messageId,
        correspondent: message.from,
        createdAt: now
      });
    }

    ctx.repository.stats.increment("queuedNotificationEvents", registrations.length);
    return registrations.length;
  }

  function removeRegistrationsForDevice(accountId, deviceId) {
    return ctx.repository.pushRegistrations.removeWhere((entry) => (
      entry.accountId === accountId && entry.deviceId === deviceId
    ));
  }

  function handleListRegistrations(request, response) {
    const authState = auth.requireAuth(request, response);
    if (!authState) {
      return;
    }

    sendJson(response, 200, {
      username: authState.account.username,
      registrations: listRegistrationsForAccount(authState.account.accountId).map(serializeRegistration)
    });
  }

  async function handleRegisterPushToken(request, response) {
    const authState = auth.requireAuth(request, response);
    if (!authState) {
      return;
    }

    const body = await readJsonBody(request);
    const token = sanitizeToken(body.token);
    const platform = sanitizePlatform(body.platform);
    const provider = sanitizePlatform(body.provider) || "native";
    const deviceId = typeof body.deviceId === "string" && body.deviceId.trim()
      ? body.deviceId.trim()
      : authState.session.deviceId;

    if (!token) {
      sendError(response, 400, "token is required.");
      return;
    }
    if (token.length > 1024) {
      sendError(response, 400, "token must be 1-1024 characters.");
      return;
    }
    if (!platform) {
      sendError(response, 400, "platform is required.");
      return;
    }

    const device = authState.account.devices.find((entry) => entry.deviceId === deviceId && !entry.revokedAt);
    if (!device) {
      sendError(response, 404, "Active device was not found for push registration.");
      return;
    }

    const existing = ctx.repository.pushRegistrations.find((entry) => (
      entry.accountId === authState.account.accountId &&
      entry.deviceId === deviceId &&
      entry.token === token
    ));

    if (existing) {
      existing.platform = platform;
      existing.provider = provider;
      existing.updatedAt = ctx.nowIso();
      ctx.repository.saveStore();
      sendJson(response, 200, {
        username: authState.account.username,
        registration: serializeRegistration(existing)
      });
      return;
    }

    const registration = {
      registrationId: ctx.randomId(),
      accountId: authState.account.accountId,
      username: authState.account.username,
      deviceId,
      token,
      platform,
      provider,
      createdAt: ctx.nowIso(),
      updatedAt: ctx.nowIso()
    };

    ctx.repository.pushRegistrations.push(registration);
    ctx.repository.saveStore();

    sendJson(response, 201, {
      username: authState.account.username,
      registration: serializeRegistration(registration)
    });
  }

  function handleDeletePushToken(response, authState, token) {
    const normalizedToken = sanitizeToken(token);
    if (!normalizedToken) {
      sendError(response, 400, "token is required.");
      return;
    }

    const removed = ctx.repository.pushRegistrations.removeWhere((entry) => (
      entry.accountId === authState.account.accountId && entry.token === normalizedToken
    ));

    if (removed > 0) {
      ctx.repository.saveStore();
    }

    sendJson(response, 200, {
      username: authState.account.username,
      removed,
      token: normalizedToken
    });
  }

  return {
    handleDeletePushToken,
    handleListRegistrations,
    handleRegisterPushToken,
    queueMessageNotifications,
    removeRegistrationsForDevice
  };
}

module.exports = {
  createPushService
};
