const Database = require("better-sqlite3");
const path     = require("path");
const fs       = require("fs");

const DATA_DIR  = path.join(__dirname, "../data");
const MEDIA_DIR = path.join(DATA_DIR, "media");
const DB_PATH   = path.join(DATA_DIR, "deadp0et.db");

function ensureDirs() {
  fs.mkdirSync(DATA_DIR,  { recursive: true });
  fs.mkdirSync(MEDIA_DIR, { recursive: true });
}

let _db;
function getDb() {
  if (!_db) {
    ensureDirs();
    _db = new Database(DB_PATH);
    _db.pragma("journal_mode = WAL");
    _db.pragma("foreign_keys = ON");
    migrate(_db);
  }
  return _db;
}

function migrate(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id               INTEGER PRIMARY KEY AUTOINCREMENT,
      username         TEXT    NOT NULL UNIQUE COLLATE NOCASE,
      password_hash    TEXT    NOT NULL,
      public_key       TEXT    NOT NULL,
      enc_private_key  TEXT    NOT NULL,
      created_at       INTEGER NOT NULL DEFAULT (unixepoch())
    );

    CREATE TABLE IF NOT EXISTS conversations (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      user1_id   INTEGER NOT NULL,
      user2_id   INTEGER NOT NULL,
      created_at INTEGER NOT NULL DEFAULT (unixepoch()),
      FOREIGN KEY (user1_id) REFERENCES users(id),
      FOREIGN KEY (user2_id) REFERENCES users(id),
      UNIQUE(user1_id, user2_id)
    );

    CREATE TABLE IF NOT EXISTS messages (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      conversation_id INTEGER NOT NULL,
      sender_id       INTEGER NOT NULL,
      iv              TEXT    NOT NULL,
      ciphertext      TEXT    NOT NULL,
      media_id        INTEGER,
      created_at      INTEGER NOT NULL DEFAULT (unixepoch()),
      delivered_at    INTEGER,
      FOREIGN KEY (conversation_id) REFERENCES conversations(id),
      FOREIGN KEY (sender_id)       REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS media (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      uploader_id     INTEGER NOT NULL,
      conversation_id INTEGER NOT NULL,
      size            INTEGER NOT NULL,
      created_at      INTEGER NOT NULL DEFAULT (unixepoch()),
      FOREIGN KEY (uploader_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS push_subscriptions (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id      INTEGER NOT NULL,
      endpoint     TEXT    NOT NULL UNIQUE,
      subscription TEXT    NOT NULL,
      created_at   INTEGER NOT NULL DEFAULT (unixepoch()),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_msg_conv  ON messages(conversation_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_conv_u1   ON conversations(user1_id);
    CREATE INDEX IF NOT EXISTS idx_conv_u2   ON conversations(user2_id);
    CREATE INDEX IF NOT EXISTS idx_push_user ON push_subscriptions(user_id);
  `);
}

module.exports = { getDb, MEDIA_DIR };
