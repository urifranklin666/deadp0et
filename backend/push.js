const webpush = require("web-push");
const fs       = require("fs");
const path     = require("path");

const DATA_DIR   = path.join(__dirname, "../data");
const VAPID_PATH = path.join(DATA_DIR, "vapid.json");
const VAPID_EMAIL = process.env.VAPID_EMAIL || "mailto:admin@deadplug.digital";

let vapidPublicKey  = process.env.VAPID_PUBLIC_KEY;
let vapidPrivateKey = process.env.VAPID_PRIVATE_KEY;

function init() {
  if (vapidPublicKey && vapidPrivateKey) {
    webpush.setVapidDetails(VAPID_EMAIL, vapidPublicKey, vapidPrivateKey);
    return;
  }
  fs.mkdirSync(DATA_DIR, { recursive: true });
  try {
    const saved     = JSON.parse(fs.readFileSync(VAPID_PATH, "utf8"));
    vapidPublicKey  = saved.publicKey;
    vapidPrivateKey = saved.privateKey;
  } catch {
    const keys      = webpush.generateVAPIDKeys();
    vapidPublicKey  = keys.publicKey;
    vapidPrivateKey = keys.privateKey;
    fs.writeFileSync(VAPID_PATH, JSON.stringify(keys, null, 2));
    console.log("[push] Generated VAPID keys → data/vapid.json");
  }
  webpush.setVapidDetails(VAPID_EMAIL, vapidPublicKey, vapidPrivateKey);
}

init();

function getPublicKey() { return vapidPublicKey; }

function saveSubscription(userId, sub) {
  const { getDb } = require("./db");
  getDb().prepare(`
    INSERT INTO push_subscriptions (user_id, endpoint, subscription)
    VALUES (?, ?, ?)
    ON CONFLICT(endpoint) DO UPDATE SET subscription = excluded.subscription, user_id = excluded.user_id
  `).run(userId, sub.endpoint, JSON.stringify(sub));
}

function removeSubscription(endpoint) {
  const { getDb } = require("./db");
  getDb().prepare("DELETE FROM push_subscriptions WHERE endpoint = ?").run(endpoint);
}

async function sendPush(userId, payload) {
  const { getDb } = require("./db");
  const subs = getDb()
    .prepare("SELECT endpoint, subscription FROM push_subscriptions WHERE user_id = ?")
    .all(userId);
  for (const row of subs) {
    try {
      await webpush.sendNotification(JSON.parse(row.subscription), JSON.stringify(payload));
    } catch (err) {
      if (err.statusCode === 410 || err.statusCode === 404) {
        removeSubscription(row.endpoint);
      }
    }
  }
}

module.exports = { getPublicKey, saveSubscription, removeSubscription, sendPush };
