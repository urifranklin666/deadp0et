const { getDb } = require("./db");

// Get or create a conversation between two users
function getOrCreateConversation(userAId, userBId) {
  const db  = getDb();
  const lo  = Math.min(userAId, userBId);
  const hi  = Math.max(userAId, userBId);

  let conv = db.prepare(
    "SELECT * FROM conversations WHERE user1_id = ? AND user2_id = ?"
  ).get(lo, hi);

  if (!conv) {
    const row = db.prepare(
      "INSERT INTO conversations (user1_id, user2_id) VALUES (?, ?)"
    ).run(lo, hi);
    conv = db.prepare("SELECT * FROM conversations WHERE id = ?").get(row.lastInsertRowid);
  }
  return conv;
}

// List all conversations for a user, with peer info + last-message time
function listConversations(userId) {
  const db = getDb();
  return db.prepare(`
    SELECT
      c.id,
      c.created_at,
      CASE WHEN c.user1_id = ? THEN c.user2_id ELSE c.user1_id END AS peer_id,
      u.username  AS peer_username,
      (SELECT created_at FROM messages WHERE conversation_id = c.id ORDER BY created_at DESC LIMIT 1) AS last_at,
      (SELECT sender_id  FROM messages WHERE conversation_id = c.id ORDER BY created_at DESC LIMIT 1) AS last_sender_id,
      (SELECT COUNT(*) FROM messages
        WHERE conversation_id = c.id AND sender_id != ? AND delivered_at IS NULL) AS unread
    FROM conversations c
    JOIN users u ON u.id = CASE WHEN c.user1_id = ? THEN c.user2_id ELSE c.user1_id END
    WHERE c.user1_id = ? OR c.user2_id = ?
    ORDER BY COALESCE(last_at, c.created_at) DESC
  `).all(userId, userId, userId, userId, userId);
}

// Paginated message fetch — newest first
function getMessages(conversationId, userId, before = null, limit = 50) {
  const db  = getDb();
  const sql = before
    ? `SELECT id, sender_id, iv, ciphertext, media_id, created_at
       FROM messages WHERE conversation_id = ? AND created_at < ?
       ORDER BY created_at DESC LIMIT ?`
    : `SELECT id, sender_id, iv, ciphertext, media_id, created_at
       FROM messages WHERE conversation_id = ?
       ORDER BY created_at DESC LIMIT ?`;

  const rows = before
    ? db.prepare(sql).all(conversationId, before, limit)
    : db.prepare(sql).all(conversationId, limit);

  // Mark unread messages as delivered
  db.prepare(`
    UPDATE messages SET delivered_at = unixepoch()
    WHERE conversation_id = ? AND sender_id != ? AND delivered_at IS NULL
  `).run(conversationId, userId);

  return rows.reverse(); // return chronological order
}

function storeMessage(conversationId, senderId, iv, ciphertext, mediaId = null) {
  const db  = getDb();
  const row = db.prepare(`
    INSERT INTO messages (conversation_id, sender_id, iv, ciphertext, media_id)
    VALUES (?, ?, ?, ?, ?)
  `).run(conversationId, senderId, iv, ciphertext, mediaId);

  return db.prepare("SELECT * FROM messages WHERE id = ?").get(row.lastInsertRowid);
}

function markDelivered(messageId) {
  getDb().prepare(
    "UPDATE messages SET delivered_at = unixepoch() WHERE id = ? AND delivered_at IS NULL"
  ).run(messageId);
}

module.exports = { getOrCreateConversation, listConversations, getMessages, storeMessage, markDelivered };
