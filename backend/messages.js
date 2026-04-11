const { parseUrl, readJsonBody, sendError, sendJson } = require("./http");

function createMessageService(ctx, auth, prekeys) {
  async function handleStoreMessage(request, response) {
    const authState = auth.requireAuth(request, response);
    if (!authState) {
      return;
    }

    const body = await readJsonBody(request);
    const recipientUsername = ctx.normalizeUsername(body.to);
    const recipientDeviceId = typeof body.recipientDeviceId === "string" ? body.recipientDeviceId.trim() : "";
    const envelope = body.envelope;

    if (!recipientUsername || !recipientDeviceId || !envelope || typeof envelope !== "object") {
      sendError(response, 400, "to, recipientDeviceId, and envelope are required.");
      return;
    }

    const recipient = ctx.findAccountByUsername(recipientUsername);
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

    const ephemeralKeyError = ctx.validateJwkLike(envelope.ephemeralKey, "envelope.ephemeralKey");
    if (ephemeralKeyError) {
      sendError(response, 400, ephemeralKeyError);
      return;
    }

    const oneTimePrekeyId = envelope.oneTimePrekeyId;
    if (oneTimePrekeyId !== undefined && (typeof oneTimePrekeyId !== "string" || !oneTimePrekeyId.trim())) {
      sendError(response, 400, "envelope.oneTimePrekeyId must be a non-empty string when provided.");
      return;
    }
    const prekeyReservationToken = envelope.prekeyReservationToken;
    if (typeof prekeyReservationToken !== "string" || !prekeyReservationToken.trim()) {
      sendError(response, 400, "envelope.prekeyReservationToken is required.");
      return;
    }

    const reservationsPruned = prekeys.reconcilePrekeyReservations();
    const reservation = prekeys.findUsablePrekeyReservation(prekeyReservationToken.trim(), recipient.username, recipientDeviceId);
    if (!reservation) {
      if (reservationsPruned) {
        ctx.repository.saveStore();
      }
      sendError(response, 409, "Prekey reservation is invalid, expired, or already consumed.");
      return;
    }

    const normalizedOneTimePrekeyId = oneTimePrekeyId ? oneTimePrekeyId.trim() : null;
    if (reservation.oneTimePrekeyId && reservation.oneTimePrekeyId !== normalizedOneTimePrekeyId) {
      sendError(response, 409, "Envelope oneTimePrekeyId does not match reserved prekey.");
      return;
    }
    if (!reservation.oneTimePrekeyId && normalizedOneTimePrekeyId) {
      sendError(response, 409, "Envelope includes a oneTimePrekeyId but reservation does not.");
      return;
    }

    const message = {
      messageId: ctx.randomId(),
      to: recipient.username,
      recipientDeviceId,
      from: authState.account.username,
      senderDeviceId: authState.session.deviceId,
      envelope: {
        protocol: envelope.protocol,
        ephemeralKey: envelope.ephemeralKey,
        iv: envelope.iv,
        ciphertext: envelope.ciphertext,
        oneTimePrekeyId: normalizedOneTimePrekeyId,
        prekeyReservationToken: prekeyReservationToken.trim()
      },
      storedAt: ctx.nowIso(),
      deliveredAt: null,
      readAt: null,
      deliveryCount: 0
    };

    ctx.repository.messages.push(message);
    reservation.deliveredMessageId = message.messageId;
    ctx.repository.saveStore();

    sendJson(response, 201, {
      messageId: message.messageId,
      to: message.to,
      recipientDeviceId: message.recipientDeviceId,
      storedAt: message.storedAt
    });
  }

  function handleInbox(request, response) {
    const reconciled = prekeys.reconcilePrekeyReservations();
    if (reconciled) {
      ctx.repository.saveStore();
    }

    const authState = auth.requireAuth(request, response);
    if (!authState) {
      return;
    }

    const url = parseUrl(request);
    const deviceIdFilter = url.searchParams.get("deviceId") || authState.session.deviceId;

    let storeChanged = false;

    const messages = ctx.repository.messages
      .all()
      .filter((message) => {
        if (message.expiredAt) {
          return false;
        }
        if (message.to !== authState.account.username) {
          return false;
        }
        if (deviceIdFilter) {
          return message.recipientDeviceId === deviceIdFilter;
        }
        return true;
      })
      .map((message) => {
        if (!message.deliveredAt) {
          message.deliveredAt = ctx.nowIso();
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
      ctx.repository.saveStore();
    }

    sendJson(response, 200, {
      username: authState.account.username,
      deviceId: deviceIdFilter || null,
      messages
    });
  }

  async function handleAcknowledgeInbox(request, response) {
    const reconciled = prekeys.reconcilePrekeyReservations();
    if (reconciled) {
      ctx.repository.saveStore();
    }

    const authState = auth.requireAuth(request, response);
    if (!authState) {
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

    const oneTimePrekeyProofMap = new Map();
    if (body.oneTimePrekeyProofs !== undefined) {
      if (!Array.isArray(body.oneTimePrekeyProofs)) {
        sendError(response, 400, "oneTimePrekeyProofs must be an array when provided.");
        return;
      }
      for (const proof of body.oneTimePrekeyProofs) {
        if (!proof || typeof proof !== "object" || Array.isArray(proof)) {
          sendError(response, 400, "oneTimePrekeyProofs entries must be objects.");
          return;
        }
        const messageId = typeof proof.messageId === "string" ? proof.messageId.trim() : "";
        const oneTimePrekeyId = typeof proof.oneTimePrekeyId === "string" ? proof.oneTimePrekeyId.trim() : "";
        if (!messageId || !oneTimePrekeyId) {
          sendError(response, 400, "oneTimePrekeyProofs entries require messageId and oneTimePrekeyId.");
          return;
        }
        oneTimePrekeyProofMap.set(messageId, oneTimePrekeyId);
      }
    }

    const messagesToAcknowledge = [];
    for (const message of ctx.repository.messages.all()) {
      if (!targetMessageIds.has(message.messageId)) {
        continue;
      }
      if (message.to !== authState.account.username || message.recipientDeviceId !== authState.session.deviceId) {
        continue;
      }
      if (message.readAt) {
        continue;
      }
      messagesToAcknowledge.push(message);
    }

    for (const message of messagesToAcknowledge) {
      const requiredOneTimePrekeyId = message.envelope?.oneTimePrekeyId || null;
      if (!requiredOneTimePrekeyId) {
        continue;
      }
      const providedOneTimePrekeyId = oneTimePrekeyProofMap.get(message.messageId);
      if (!providedOneTimePrekeyId) {
        sendError(response, 400, `oneTimePrekeyProof is required for message ${message.messageId}.`);
        return;
      }
      if (providedOneTimePrekeyId !== requiredOneTimePrekeyId) {
        sendError(response, 409, `oneTimePrekeyProof does not match envelope for message ${message.messageId}.`);
        return;
      }
    }

    let updated = 0;
    const acknowledgedAt = ctx.nowIso();

    for (const message of messagesToAcknowledge) {
      const requiredOneTimePrekeyId = message.envelope?.oneTimePrekeyId || null;
      if (requiredOneTimePrekeyId) {
        const reservationToken = message.envelope?.prekeyReservationToken || "";
        const reservation = ctx.repository.prekeyReservations.find(
          (entry) =>
            entry.reservationToken === reservationToken &&
            entry.username === authState.account.username &&
            entry.recipientDeviceId === authState.session.deviceId &&
            entry.oneTimePrekeyId === requiredOneTimePrekeyId &&
            entry.deliveredMessageId === message.messageId &&
            !entry.consumedAt &&
            !entry.releasedAt
        );
        if (!reservation) {
          sendError(response, 409, `Reservation state is invalid for message ${message.messageId}.`);
          return;
        }

        const device = authState.account.devices.find((entry) => entry.deviceId === authState.session.deviceId && !entry.revokedAt);
        if (!device) {
          sendError(response, 409, "Active device state is invalid for acknowledgement.");
          return;
        }
        const consumed = prekeys.consumeReservedOneTimePrekey(
          device,
          reservation.reservationToken,
          requiredOneTimePrekeyId,
          acknowledgedAt,
          message.messageId
        );
        if (!consumed) {
          sendError(response, 409, `Reserved one-time prekey is missing for message ${message.messageId}.`);
          return;
        }

        reservation.acknowledgedAt = acknowledgedAt;
        reservation.consumedAt = acknowledgedAt;
        reservation.consumedByMessageId = message.messageId;
      }

      message.readAt = acknowledgedAt;
      updated += 1;
    }

    ctx.repository.saveStore();

    sendJson(response, 200, {
      username: authState.account.username,
      deviceId: authState.session.deviceId,
      acknowledged: updated,
      acknowledgedAt
    });
  }

  return {
    handleAcknowledgeInbox,
    handleInbox,
    handleStoreMessage
  };
}

module.exports = {
  createMessageService
};
