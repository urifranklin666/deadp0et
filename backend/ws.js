const jwt  = require("jsonwebtoken");
const push = require("./push");
const { storeMessage, markDelivered, getOrCreateConversation } = require("./messages");

const JWT_SECRET = process.env.JWT_SECRET || "change-me-in-production";

// userId → WebSocket
const online = new Map();

function setupWs(wss) {
  wss.on("connection", (ws, req) => {
    // Authenticate via ?token= query param
    const url    = new URL(req.url, "http://localhost");
    const token  = url.searchParams.get("token");
    let user     = null;

    try {
      const p = jwt.verify(token, JWT_SECRET);
      user     = { id: p.sub, username: p.username };
    } catch {
      ws.close(4001, "Unauthorized");
      return;
    }

    online.set(user.id, ws);
    ws._user = user;

    send(ws, { type: "auth_ok", userId: user.id, username: user.username });

    ws.on("message", async (raw) => {
      let msg;
      try { msg = JSON.parse(raw); } catch { return; }

      switch (msg.type) {
        case "send": {
          const { conversationId, iv, ciphertext, mediaId } = msg;
          if (!conversationId || !iv || !ciphertext) return;

          const stored = storeMessage(conversationId, user.id, iv, ciphertext, mediaId || null);

          // Ack back to sender
          send(ws, { type: "ack", tempId: msg.tempId, messageId: stored.id });

          // Deliver to recipient if online, otherwise push
          const recipientId = recipientIdOf(conversationId, user.id);
          const recipientWs = recipientId ? online.get(recipientId) : null;
          if (recipientWs) {
            send(recipientWs, {
              type:           "message",
              id:             stored.id,
              conversationId: stored.conversation_id,
              sender_id:      stored.sender_id,
              iv:             stored.iv,
              ciphertext:     stored.ciphertext,
              mediaId:        stored.media_id,
              created_at:     stored.created_at,
            });
            markDelivered(stored.id);
          } else if (recipientId) {
            push.sendPush(recipientId, {
              title: "deadp0et",
              body:  "New encrypted message",
            }).catch(() => {});
          }
          break;
        }

        case "typing": {
          const { conversationId } = msg;
          if (!conversationId) return;
          const recipientId = recipientIdOf(conversationId, user.id);
          const recipientWs = recipientId ? online.get(recipientId) : null;
          if (recipientWs) {
            send(recipientWs, { type: "typing", conversationId });
          }
          break;
        }
      }
    });

    ws.on("close", () => {
      if (ws._user) online.delete(ws._user.id);
    });
  });
}

function send(ws, obj) {
  if (ws && ws.readyState === ws.OPEN) ws.send(JSON.stringify(obj));
}

// Return the other participant's userId for a conversation
function recipientIdOf(conversationId, senderId) {
  const { getDb } = require("./db");
  const row = getDb().prepare("SELECT user1_id, user2_id FROM conversations WHERE id = ?").get(conversationId);
  if (!row) return null;
  return row.user1_id === senderId ? row.user2_id : row.user1_id;
}

function isOnline(userId) {
  return online.has(userId);
}

module.exports = { setupWs, isOnline, recipientIdOf };
