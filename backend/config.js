const path = require("path");

const ROOT_DIR = path.join(__dirname, "..");
const DATA_DIR = process.env.DATA_DIR || path.join(ROOT_DIR, "data");

module.exports = {
  HOST: process.env.HOST || "0.0.0.0",
  PORT: Number(process.env.PORT || 3000),
  SESSION_TTL_MS: Number(process.env.SESSION_TTL_MS || 7 * 24 * 60 * 60 * 1000),
  MAX_ACTIVE_SESSIONS_PER_ACCOUNT: Math.max(1, Number(process.env.MAX_ACTIVE_SESSIONS_PER_ACCOUNT || 12)),
  MAX_ACTIVE_SESSIONS_PER_DEVICE: Math.max(1, Number(process.env.MAX_ACTIVE_SESSIONS_PER_DEVICE || 4)),
  MAX_PASSWORD_VERIFIER_LENGTH: Number(process.env.MAX_PASSWORD_VERIFIER_LENGTH || 4096),
  AUTH_WINDOW_MS: Math.max(1000, Number(process.env.AUTH_WINDOW_MS || 10 * 60 * 1000)),
  AUTH_MAX_ATTEMPTS_PER_KEY: Math.max(1, Number(process.env.AUTH_MAX_ATTEMPTS_PER_KEY || 8)),
  AUTH_BLOCK_MS: Math.max(1000, Number(process.env.AUTH_BLOCK_MS || 15 * 60 * 1000)),
  PREKEY_RESERVATION_TTL_MS: Math.max(1000, Number(process.env.PREKEY_RESERVATION_TTL_MS || 10 * 60 * 1000)),
  ACKNOWLEDGED_MESSAGE_RETENTION_MS: Math.max(0, Number(
    process.env.ACKNOWLEDGED_MESSAGE_RETENTION_MS || 30 * 24 * 60 * 60 * 1000
  )),
  LOW_ONE_TIME_PREKEY_THRESHOLD: Math.max(1, Number(process.env.LOW_ONE_TIME_PREKEY_THRESHOLD || 5)),
  DATA_DIR,
  DATA_FILE: path.join(DATA_DIR, "store.json"),
  STATIC_FILES: {
    "/": { filePath: path.join(ROOT_DIR, "index.html"), contentType: "text/html; charset=utf-8" },
    "/index.html": { filePath: path.join(ROOT_DIR, "index.html"), contentType: "text/html; charset=utf-8" },
    "/app.js": { filePath: path.join(ROOT_DIR, "app.js"), contentType: "application/javascript; charset=utf-8" },
    "/protocol-client.js": {
      filePath: path.join(ROOT_DIR, "protocol-client.js"),
      contentType: "application/javascript; charset=utf-8"
    },
    "/styles.css": { filePath: path.join(ROOT_DIR, "styles.css"), contentType: "text/css; charset=utf-8" }
  }
};
