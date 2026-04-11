const { readJsonBody, sendError, sendJson } = require("./http");

function createPrekeyService(ctx) {
  function ensureDevicePrekeyCollections(device) {
    if (!Array.isArray(device.oneTimePrekeys)) {
      device.oneTimePrekeys = [];
    }
    if (!Array.isArray(device.reservedOneTimePrekeys)) {
      device.reservedOneTimePrekeys = [];
    }
    if (!Array.isArray(device.consumedOneTimePrekeys)) {
      device.consumedOneTimePrekeys = [];
    }
  }

  function reserveOneTimePrekey(device, reservationToken) {
    ensureDevicePrekeyCollections(device);
    const reservedPrekey = device.oneTimePrekeys.shift();
    if (!reservedPrekey) {
      return null;
    }
    const reservedAt = ctx.nowIso();
    device.reservedOneTimePrekeys.push({
      reservationToken,
      reservedAt,
      prekey: reservedPrekey
    });
    return {
      prekey: reservedPrekey,
      reservedAt
    };
  }

  function releaseReservedOneTimePrekey(device, reservationToken, oneTimePrekeyId) {
    ensureDevicePrekeyCollections(device);
    const reservationIndex = device.reservedOneTimePrekeys.findIndex(
      (entry) => entry.reservationToken === reservationToken && entry.prekey?.keyId === oneTimePrekeyId
    );
    if (reservationIndex === -1) {
      return false;
    }
    const [released] = device.reservedOneTimePrekeys.splice(reservationIndex, 1);
    device.oneTimePrekeys.unshift(released.prekey);
    return true;
  }

  function consumeReservedOneTimePrekey(device, reservationToken, oneTimePrekeyId, consumedAt, consumedByMessageId) {
    ensureDevicePrekeyCollections(device);
    const reservationIndex = device.reservedOneTimePrekeys.findIndex(
      (entry) => entry.reservationToken === reservationToken && entry.prekey?.keyId === oneTimePrekeyId
    );
    if (reservationIndex === -1) {
      return false;
    }
    const [reserved] = device.reservedOneTimePrekeys.splice(reservationIndex, 1);
    device.consumedOneTimePrekeys.push({
      consumedAt,
      consumedByMessageId,
      prekey: reserved.prekey
    });
    return true;
  }

  function reconcilePrekeyReservations() {
    const now = Date.now();
    let changed = false;

    for (const entry of ctx.repository.prekeyReservations.all()) {
      if (entry.consumedAt || entry.releasedAt) {
        continue;
      }

      const expiresAtMs = Date.parse(entry.expiresAt || 0);
      if (Number.isNaN(expiresAtMs)) {
        entry.releasedAt = ctx.nowIso();
        entry.releaseReason = "invalid_expiry";
        changed = true;
        continue;
      }
      if (expiresAtMs > now) {
        continue;
      }

      const account = ctx.findAccountByUsername(entry.username);
      const device = account?.devices?.find((item) => item.deviceId === entry.recipientDeviceId) || null;
      if (device && entry.oneTimePrekeyId) {
        changed = releaseReservedOneTimePrekey(device, entry.reservationToken, entry.oneTimePrekeyId) || changed;
      }

      if (entry.deliveredMessageId) {
        const message = ctx.repository.messages.find((item) => item.messageId === entry.deliveredMessageId);
        if (message && !message.readAt && !message.expiredAt) {
          message.expiredAt = ctx.nowIso();
          changed = true;
        }
      }

      entry.releasedAt = ctx.nowIso();
      entry.releaseReason = "expired";
      changed = true;
    }

    return changed;
  }

  function createPrekeyReservation(account, device, reservedOneTimePrekey) {
    const reservation = {
      reservationId: ctx.randomId(),
      reservationToken: ctx.randomToken(),
      username: account.username,
      recipientDeviceId: device.deviceId,
      oneTimePrekeyId: reservedOneTimePrekey?.prekey?.keyId || null,
      oneTimePrekeyReservedAt: reservedOneTimePrekey?.reservedAt || null,
      createdAt: ctx.nowIso(),
      expiresAt: new Date(Date.now() + ctx.config.PREKEY_RESERVATION_TTL_MS).toISOString(),
      deliveredMessageId: null,
      acknowledgedAt: null,
      consumedAt: null,
      consumedByMessageId: null,
      releasedAt: null,
      releaseReason: null
    };
    ctx.repository.prekeyReservations.push(reservation);
    return reservation;
  }

  function findUsablePrekeyReservation(token, recipientUsername, recipientDeviceId) {
    if (typeof token !== "string" || !token.trim()) {
      return null;
    }

    const reservation = ctx.repository.prekeyReservations.find(
      (entry) =>
        entry.reservationToken === token &&
        entry.username === recipientUsername &&
        entry.recipientDeviceId === recipientDeviceId &&
        !entry.deliveredMessageId &&
        !entry.consumedAt &&
        !entry.releasedAt
    );

    if (!reservation) {
      return null;
    }

    if (Date.parse(reservation.expiresAt || 0) <= Date.now()) {
      return null;
    }

    return reservation;
  }

  function handleGetBundles(response, username) {
    const reconciled = reconcilePrekeyReservations();
    if (reconciled) {
      ctx.repository.saveStore();
    }

    const account = ctx.findAccountByUsername(username);
    if (!account) {
      sendError(response, 404, "Recipient account was not found.");
      return;
    }

    const activeDevices = ctx.getActiveDevices(account);
    sendJson(response, 200, {
      username: account.username,
      lowOneTimePrekeyThreshold: ctx.config.LOW_ONE_TIME_PREKEY_THRESHOLD,
      devices: activeDevices.map(ctx.getPublicDeviceBundle),
      prekeyWarnings: ctx.buildPrekeyWarnings(activeDevices)
    });
  }

  async function handleIssuePrekeyBundle(request, response, username) {
    const reconciled = reconcilePrekeyReservations();
    if (reconciled) {
      ctx.repository.saveStore();
    }

    const account = ctx.findAccountByUsername(username);
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

    const activeDevices = ctx.getActiveDevices(account);
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

    const reservationToken = ctx.randomToken();
    const reservedOneTimePrekey = reserveOneTimePrekey(selectedDevice, reservationToken);
    const reservation = createPrekeyReservation(account, selectedDevice, reservedOneTimePrekey);
    reservation.reservationToken = reservationToken;
    const reservationsPruned = reconcilePrekeyReservations();
    if (reservedOneTimePrekey || reservationsPruned || reservation) {
      ctx.repository.saveStore();
    }

    sendJson(response, 200, {
      username: account.username,
      issuedAt: ctx.nowIso(),
      device: {
        deviceId: selectedDevice.deviceId,
        identityKey: selectedDevice.identityKey,
        signedPrekey: selectedDevice.signedPrekey,
        prekeySignature: selectedDevice.prekeySignature
      },
      oneTimePrekey: reservedOneTimePrekey ? reservedOneTimePrekey.prekey : null,
      oneTimePrekeyReservedAt: reservedOneTimePrekey ? reservedOneTimePrekey.reservedAt : null,
      prekeyReservationToken: reservation.reservationToken,
      prekeyReservationExpiresAt: reservation.expiresAt
    });
  }

  return {
    consumeReservedOneTimePrekey,
    findUsablePrekeyReservation,
    handleGetBundles,
    handleIssuePrekeyBundle,
    reconcilePrekeyReservations
  };
}

module.exports = {
  createPrekeyService
};
