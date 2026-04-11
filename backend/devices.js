const { readJsonBody, sendError, sendJson } = require("./http");

function createDeviceService(ctx, auth, prekeys) {
  async function handleRegisterDevice(request, response) {
    const authState = auth.requireAuth(request, response);
    if (!authState) {
      return;
    }

    const body = await readJsonBody(request);
    const deviceError = ctx.validateDevicePayload(body.device);
    if (deviceError) {
      sendError(response, 400, deviceError);
      return;
    }

    if (authState.account.devices.some((device) => device.deviceId === body.device.deviceId)) {
      sendError(response, 409, "That deviceId is already registered on the account.");
      return;
    }

    const device = {
      deviceId: body.device.deviceId,
      identityKey: body.device.identityKey,
      signedPrekey: body.device.signedPrekey,
      prekeySignature: body.device.prekeySignature,
      oneTimePrekeys: Array.isArray(body.device.oneTimePrekeys) ? body.device.oneTimePrekeys : [],
      registeredAt: ctx.nowIso(),
      revokedAt: null
    };

    authState.account.devices.push(device);
    ctx.repository.saveStore();

    sendJson(response, 201, {
      username: authState.account.username,
      device: ctx.getPublicDeviceBundle(device)
    });
  }

  function handleListDevices(request, response) {
    const reconciled = prekeys.reconcilePrekeyReservations();
    if (reconciled) {
      ctx.repository.saveStore();
    }

    const authState = auth.requireAuth(request, response);
    if (!authState) {
      return;
    }

    sendJson(response, 200, {
      username: authState.account.username,
      lowOneTimePrekeyThreshold: ctx.config.LOW_ONE_TIME_PREKEY_THRESHOLD,
      devices: authState.account.devices.map(ctx.getPublicDeviceBundle),
      prekeyWarnings: ctx.buildPrekeyWarnings(ctx.getActiveDevices(authState.account))
    });
  }

  function handleDeleteDevice(response, authState, deviceId) {
    const device = authState.account.devices.find((entry) => entry.deviceId === deviceId);
    if (!device) {
      sendError(response, 404, "Device was not found.");
      return;
    }

    if (device.revokedAt) {
      sendError(response, 409, "Device is already revoked.");
      return;
    }

    if (ctx.getActiveDevices(authState.account).length <= 1) {
      sendError(response, 409, "Cannot revoke the last active device on the account.");
      return;
    }

    device.revokedAt = ctx.nowIso();
    ctx.repository.sessions.forEach((session) => {
      if (session.accountId === authState.account.accountId && session.deviceId === deviceId && !session.revokedAt) {
        session.revokedAt = ctx.nowIso();
      }
    });
    ctx.repository.saveStore();

    sendJson(response, 200, {
      username: authState.account.username,
      deviceId,
      revokedAt: device.revokedAt
    });
  }

  async function handleRotatePrekeys(request, response) {
    const authState = auth.requireAuth(request, response);
    if (!authState) {
      return;
    }

    const body = await readJsonBody(request);
    const deviceId = typeof body.deviceId === "string" && body.deviceId.trim() ? body.deviceId.trim() : authState.session.deviceId;
    const signedPrekey = body.signedPrekey;
    const prekeySignature = typeof body.prekeySignature === "string" ? body.prekeySignature.trim() : "";
    const oneTimePrekeys = body.oneTimePrekeys;

    const device = authState.account.devices.find((entry) => entry.deviceId === deviceId && !entry.revokedAt);
    if (!device) {
      sendError(response, 404, "Active device was not found.");
      return;
    }

    const prekeyError = ctx.validateJwkLike(signedPrekey, "signedPrekey");
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
    device.prekeysRotatedAt = ctx.nowIso();
    ctx.repository.saveStore();

    sendJson(response, 200, {
      username: authState.account.username,
      device: ctx.getPublicDeviceBundle(device)
    });
  }

  function handleHealth(response) {
    const reconciled = prekeys.reconcilePrekeyReservations();
    if (reconciled) {
      ctx.repository.saveStore();
    }

    let reservedOneTimePrekeys = 0;
    let consumedOneTimePrekeys = 0;
    for (const account of ctx.repository.accounts.all()) {
      for (const device of account.devices || []) {
        if (Array.isArray(device.reservedOneTimePrekeys)) {
          reservedOneTimePrekeys += device.reservedOneTimePrekeys.length;
        }
        if (Array.isArray(device.consumedOneTimePrekeys)) {
          consumedOneTimePrekeys += device.consumedOneTimePrekeys.length;
        }
      }
    }

    const activePrekeyReservations = ctx.repository.prekeyReservations.count((entry) => !entry.consumedAt && !entry.releasedAt);
    const deliveredPendingAckReservations = ctx.repository.prekeyReservations.count(
      (entry) => entry.deliveredMessageId && !entry.consumedAt && !entry.releasedAt
    );
    const releasedPrekeyReservations = ctx.repository.prekeyReservations.count((entry) => entry.releasedAt);
    const expiredMessages = ctx.repository.messages.count((message) => message.expiredAt);

    sendJson(response, 200, {
      status: "ok",
      accounts: ctx.repository.accounts.count(),
      sessions: ctx.repository.sessions.count(
        (session) => !session.revokedAt && (!session.expiresAt || Date.parse(session.expiresAt) > Date.now())
      ),
      messages: ctx.repository.messages.count(),
      prekeyReservations: activePrekeyReservations,
      deliveredPendingAckReservations,
      releasedPrekeyReservations,
      reservedOneTimePrekeys,
      consumedOneTimePrekeys,
      expiredMessages
    });
  }

  return {
    handleDeleteDevice,
    handleHealth,
    handleListDevices,
    handleRegisterDevice,
    handleRotatePrekeys
  };
}

module.exports = {
  createDeviceService
};
