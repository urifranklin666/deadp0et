const fs   = require("fs");
const path = require("path");
const { getDb, MEDIA_DIR } = require("./db");

const MAX_SIZE = 25 * 1024 * 1024; // 25 MB

function mediaPath(id) {
  return path.join(MEDIA_DIR, String(id));
}

// Stream request body into a Buffer
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data",  c => chunks.push(c));
    req.on("end",   () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

async function uploadMedia(req, uploaderId, conversationId) {
  if (!conversationId) {
    return { status: 400, body: { error: "conversationId required." } };
  }

  const data = await readBody(req);
  if (data.length === 0) {
    return { status: 400, body: { error: "Empty upload." } };
  }
  if (data.length > MAX_SIZE) {
    return { status: 413, body: { error: "File too large (max 25 MB)." } };
  }

  const db  = getDb();
  const row = db.prepare(
    "INSERT INTO media (uploader_id, conversation_id, size) VALUES (?, ?, ?)"
  ).run(uploaderId, conversationId, data.length);

  const id = row.lastInsertRowid;
  fs.writeFileSync(mediaPath(id), data);

  return { status: 201, body: { mediaId: id, size: data.length } };
}

function downloadMedia(mediaId, requesterId) {
  const db   = getDb();
  const meta = db.prepare("SELECT * FROM media WHERE id = ?").get(mediaId);
  if (!meta) return { status: 404, body: null };

  // Verify requester is in this conversation
  const inConv = db.prepare(`
    SELECT 1 FROM conversations
    WHERE id = ? AND (user1_id = ? OR user2_id = ?)
  `).get(meta.conversation_id, requesterId, requesterId);

  if (!inConv) return { status: 403, body: null };

  const filePath = mediaPath(mediaId);
  if (!fs.existsSync(filePath)) return { status: 404, body: null };

  return { status: 200, filePath, size: meta.size };
}

module.exports = { uploadMedia, downloadMedia, readBody };
