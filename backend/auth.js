const bcrypt = require("bcryptjs");
const jwt    = require("jsonwebtoken");
const { getDb } = require("./db");

const JWT_SECRET    = process.env.JWT_SECRET || "change-me-in-production";
const JWT_EXPIRES   = "30d";
const BCRYPT_ROUNDS = 12;

function signToken(userId, username) {
  return jwt.sign({ sub: userId, username }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
}

async function register(body) {
  const { username, password, publicKey, encPrivateKey } = body;

  if (!username || !password || !publicKey || !encPrivateKey) {
    return { status: 400, body: { error: "Missing required fields." } };
  }
  if (!/^[a-zA-Z0-9_-]{3,32}$/.test(username)) {
    return { status: 400, body: { error: "Username: 3–32 chars, letters/numbers/_ only." } };
  }
  if (password.length < 8) {
    return { status: 400, body: { error: "Password must be at least 8 characters." } };
  }

  const db   = getDb();
  const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);

  try {
    const row = db.prepare(`
      INSERT INTO users (username, password_hash, public_key, enc_private_key)
      VALUES (?, ?, ?, ?)
    `).run(username, hash, JSON.stringify(publicKey), JSON.stringify(encPrivateKey));

    const token = signToken(row.lastInsertRowid, username);
    return { status: 201, body: { token, userId: row.lastInsertRowid, username } };
  } catch (e) {
    if (e.message.includes("UNIQUE")) {
      return { status: 409, body: { error: "Username already taken." } };
    }
    throw e;
  }
}

async function login(body) {
  const { username, password } = body;
  if (!username || !password) {
    return { status: 400, body: { error: "Missing credentials." } };
  }

  const db   = getDb();
  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  if (!user) {
    return { status: 401, body: { error: "Invalid username or password." } };
  }

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) {
    return { status: 401, body: { error: "Invalid username or password." } };
  }

  const token = signToken(user.id, user.username);
  return {
    status: 200,
    body: {
      token,
      userId:        user.id,
      username:      user.username,
      encPrivateKey: JSON.parse(user.enc_private_key),
    },
  };
}

function requireAuth(req) {
  const header = req.headers["authorization"] || "";
  const raw    = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!raw) return null;
  try {
    const p = jwt.verify(raw, JWT_SECRET);
    return { id: p.sub, username: p.username };
  } catch {
    return null;
  }
}

function searchUsers(query, requesterId) {
  if (!query || query.length < 2) return [];
  const db = getDb();
  return db.prepare(
    "SELECT id, username FROM users WHERE username LIKE ? AND id != ? LIMIT 10"
  ).all(`${query}%`, requesterId);
}

function getPublicKey(userId) {
  const db  = getDb();
  const row = db.prepare("SELECT public_key FROM users WHERE id = ?").get(userId);
  return row ? JSON.parse(row.public_key) : null;
}

module.exports = { register, login, requireAuth, searchUsers, getPublicKey };
