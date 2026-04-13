const { parseUrl, readJsonBody, sendError, sendJson } = require("./http");

function createMessageService(ctx, auth, prekeys, push) {
  const DEFAULT_PAGE_SIZE = 50;
  const MAX_PAGE_SIZE = 100;

  function reconcileAcknowledgedMessageRetention() {
    if (ctx.config.ACKNOWLEDGED_MESSAGE_RETENTION_MS <= 0) {
      return 0;
    }

    const cutoffMs = Date.now() - ctx.config.ACKNOWLEDGED_MESSAGE_RETENTION_MS;
    const purged = ctx.repository.messages.removeWhere((message) => {
      if (!message.readAt) {
        return false;
      }
      const readAtMs = Date.parse(message.readAt);
      if (!Number.isFinite(readAtMs)) {
        return false;
      }
      return readAtMs <= cutoffMs;
    });

    if (purged > 0) {
      ctx.repository.stats.increment("purgedAcknowledgedMessages", purged);
      ctx.repository.saveStore();
    }

    return purged;
  }

  function serializeMessage(message) {
    return {
      messageId: message.messageId,
      to: message.to,
      recipientDeviceId: message.recipientDeviceId,
      from: message.from,
      senderDeviceId: message.senderDeviceId,
      storedAt: message.storedAt,
      deliveredAt: message.deliveredAt || null,
      readAt: message.readAt || null,
      deliveryCount: message.deliveryCount || 0,
      envelope: message.envelope
    };
  }

  function parsePageSize(rawValue) {
    if (rawValue === null) {
      return DEFAULT_PAGE_SIZE;
    }
    const value = Number.parseInt(rawValue, 10);
    if (!Number.isFinite(value) || value <= 0) {
      return null;
    }
    return Math.min(value, MAX_PAGE_SIZE);
  }

  function encodeCursor(message) {
    return Buffer.from(JSON.stringify({
      storedAt: message.storedAt,
      messageId: message.messageId
    })).toString("base64url");
  }

  function decodeCursor(cursor) {
    if (!cursor || typeof cursor !== "string") {
      return null;
    }
    try {
      const parsed = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8"));
      if (!parsed || typeof parsed !== "object") {
        return null;
      }
      if (typeof parsed.storedAt !== "string" || !parsed.storedAt.trim()) {
        return null;
      }
      if (typeof parsed.messageId !== "string" || !parsed.messageId.trim()) {
        return null;
      }
      return parsed;
    } catch (error) {
      return null;
    }
  }

  function compareMessagesAscending(left, right) {
    const leftTime = Date.parse(left.storedAt || 0);
    const rightTime = Date.parse(right.storedAt || 0);
    if (leftTime !== rightTime) {
      return leftTime - rightTime;
    }
    return String(left.messageId || "").localeCompare(String(right.messageId || ""));
  }

  function compareMessagesDescending(left, right) {
    return compareMessagesAscending(right, left);
  }

  function isAfterCursor(message, cursor) {
    if (!cursor) {
      return true;
    }
    const timeComparison = Date.parse(message.storedAt || 0) - Date.parse(cursor.storedAt || 0);
    if (timeComparison !== 0) {
      return timeComparison > 0;
    }
    return String(message.messageId || "") > String(cursor.messageId || "");
  }

  function isBeforeCursor(message, cursor) {
    if (!cursor) {
      return true;
    }
    const timeComparison = Date.parse(message.storedAt || 0) - Date.parse(cursor.storedAt || 0);
    if (timeComparison !== 0) {
      return timeComparison < 0;
    }
    return String(message.messageId || "") < String(cursor.messageId || "");
  }

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
    push.queueMessageNotifications({
      ...message,
      recipientAccountId: recipient.accountId
    });
    ctx.repository.saveStore();

    sendJson(response, 201, {
      messageId: message.messageId,
      to: message.to,
      recipientDeviceId: message.recipientDeviceId,
      storedAt: message.storedAt
    });
  }

  function handleInbox(request, response) {
    reconcileAcknowledgedMessageRetention();
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
    const pageSize = parsePageSize(url.searchParams.get("limit"));
    const cursor = decodeCursor(url.searchParams.get("cursor"));

    if (pageSize === null) {
      sendError(response, 400, `limit must be an integer between 1 and ${MAX_PAGE_SIZE}.`);
      return;
    }
    if (url.searchParams.get("cursor") && !cursor) {
      sendError(response, 400, "cursor is invalid.");
      return;
    }

    let storeChanged = false;

    const matchingMessages = ctx.repository.messages
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
      .sort(compareMessagesAscending);

    const pageMessages = matchingMessages
      .filter((message) => isAfterCursor(message, cursor))
      .slice(0, pageSize);

    const messages = pageMessages
      .map((message) => {
        if (!message.deliveredAt) {
          message.deliveredAt = ctx.nowIso();
        }
        message.deliveryCount = (message.deliveryCount || 0) + 1;
        storeChanged = true;

        return serializeMessage(message);
      });

    if (storeChanged) {
      ctx.repository.saveStore();
    }

    const hasMore = matchingMessages.filter((message) => isAfterCursor(message, cursor)).length > messages.length;
    const nextCursor = messages.length && hasMore ? encodeCursor(messages[messages.length - 1]) : null;

    sendJson(response, 200, {
      username: authState.account.username,
      deviceId: deviceIdFilter || null,
      limit: pageSize,
      nextCursor,
      messages
    });
  }

  function handleHistory(request, response) {
    reconcileAcknowledgedMessageRetention();
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
    const correspondent = ctx.normalizeUsername(url.searchParams.get("correspondent"));
    const pageSize = parsePageSize(url.searchParams.get("limit"));
    const beforeCursor = decodeCursor(url.searchParams.get("before"));

    if (pageSize === null) {
      sendError(response, 400, `limit must be an integer between 1 and ${MAX_PAGE_SIZE}.`);
      return;
    }
    if (url.searchParams.get("before") && !beforeCursor) {
      sendError(response, 400, "before cursor is invalid.");
      return;
    }

    const matchingMessages = ctx.repository.messages
      .all()
      .filter((message) => {
        if (message.expiredAt) {
          return false;
        }

        const isInbound = (
          message.to === authState.account.username &&
          (!deviceIdFilter || message.recipientDeviceId === deviceIdFilter)
        );
        const isOutbound = (
          message.from === authState.account.username &&
          (!deviceIdFilter || message.senderDeviceId === deviceIdFilter)
        );

        if (!isInbound && !isOutbound) {
          return false;
        }

        if (!correspondent) {
          return true;
        }

        const otherParty = isOutbound ? message.to : message.from;
        return otherParty === correspondent;
      })
      .sort(compareMessagesDescending);

    const pageMessages = matchingMessages
      .filter((message) => isBeforeCursor(message, beforeCursor))
      .slice(0, pageSize);

    const hasMore = matchingMessages.filter((message) => isBeforeCursor(message, beforeCursor)).length > pageMessages.length;
    const nextCursor = pageMessages.length && hasMore ? encodeCursor(pageMessages[pageMessages.length - 1]) : null;

    sendJson(response, 200, {
      username: authState.account.username,
      deviceId: deviceIdFilter || null,
      correspondent: correspondent || null,
      limit: pageSize,
      nextCursor,
      messages: pageMessages.map(serializeMessage)
    });
  }

  function handleConversations(request, response) {
    reconcileAcknowledgedMessageRetention();
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
    const pageSize = parsePageSize(url.searchParams.get("limit"));
    const beforeCursor = decodeCursor(url.searchParams.get("before"));

    if (pageSize === null) {
      sendError(response, 400, `limit must be an integer between 1 and ${MAX_PAGE_SIZE}.`);
      return;
    }
    if (url.searchParams.get("before") && !beforeCursor) {
      sendError(response, 400, "before cursor is invalid.");
      return;
    }

    const conversationMap = new Map();

    for (const message of ctx.repository.messages.all()) {
      if (message.expiredAt) {
        continue;
      }

      const isInbound = (
        message.to === authState.account.username &&
        (!deviceIdFilter || message.recipientDeviceId === deviceIdFilter)
      );
      const isOutbound = (
        message.from === authState.account.username &&
        (!deviceIdFilter || message.senderDeviceId === deviceIdFilter)
      );

      if (!isInbound && !isOutbound) {
        continue;
      }

      const correspondent = isOutbound ? message.to : message.from;
      const existing = conversationMap.get(correspondent) || {
        correspondent,
        latestMessage: null,
        unreadCount: 0,
        messageCount: 0
      };

      existing.messageCount += 1;
      if (isInbound && !message.readAt) {
        existing.unreadCount += 1;
      }
      if (!existing.latestMessage || compareMessagesAscending(existing.latestMessage, message) < 0) {
        existing.latestMessage = message;
      }

      conversationMap.set(correspondent, existing);
    }

    const summaries = Array.from(conversationMap.values())
      .sort((left, right) => compareMessagesDescending(left.latestMessage, right.latestMessage));

    const filteredSummaries = summaries.filter((summary) => isBeforeCursor(summary.latestMessage, beforeCursor));
    const pageSummaries = filteredSummaries.slice(0, pageSize);
    const hasMore = filteredSummaries.length > pageSummaries.length;
    const nextCursor = pageSummaries.length && hasMore ? encodeCursor(pageSummaries[pageSummaries.length - 1].latestMessage) : null;

    sendJson(response, 200, {
      username: authState.account.username,
      deviceId: deviceIdFilter || null,
      limit: pageSize,
      nextCursor,
      conversations: pageSummaries.map((summary) => ({
        correspondent: summary.correspondent,
        unreadCount: summary.unreadCount,
        messageCount: summary.messageCount,
        latestMessage: serializeMessage(summary.latestMessage)
      }))
    });
  }

  function handleRetentionRun(request, response) {
    const authState = auth.requireAuth(request, response);
    if (!authState) {
      return;
    }

    const purged = reconcileAcknowledgedMessageRetention();
    sendJson(response, 200, {
      username: authState.account.username,
      retentionMs: ctx.config.ACKNOWLEDGED_MESSAGE_RETENTION_MS,
      purgedAcknowledgedMessages: purged,
      totalPurgedAcknowledgedMessages: Number(ctx.repository.stats.get().purgedAcknowledgedMessages || 0),
      remainingMessages: ctx.repository.messages.count()
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
    handleConversations,
    handleHistory,
    handleInbox,
    handleRetentionRun,
    handleStoreMessage
  };
}

module.exports = {
  createMessageService
};
