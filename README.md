# deadp0et

An end-to-end encrypted messenger. The server routes ciphertext — it never sees plaintext, keys, or metadata beyond what's strictly necessary to deliver a message.

Built for [deadplug.digital](https://deadplug.digital).

---

## How it works

**Key generation** happens entirely in the browser using the WebCrypto API. On registration, an ECDH P-256 keypair is generated client-side. The private key is encrypted with a key derived from your password via PBKDF2 (200k iterations, SHA-256), and the resulting ciphertext is stored on the server. The server never holds a raw private key.

**Per-conversation encryption** uses ECDH to derive a unique AES-GCM 256 shared secret between two users. Every message is encrypted before it leaves the browser.

**Media** gets its own random AES-GCM key per file. That file key is encrypted with the conversation key before upload. The server stores opaque binary blobs — it cannot read filenames, types, or content.

**Sessions** use JWT auth (30-day expiry). On returning visits, a password prompt re-derives the private key from the server-stored ciphertext — no key material persists in browser storage.

---

## Stack

- **Backend:** Node.js, `ws`, `better-sqlite3`, `bcryptjs`, `jsonwebtoken`
- **Frontend:** Vanilla JS + WebCrypto API — no framework, no bundler
- **Storage:** SQLite for accounts, conversations, and message envelopes; local filesystem for encrypted media blobs
- **Transport:** REST for auth, conversations, and media; WebSocket for real-time message delivery

---

## Running locally

```bash
npm install
npm start
```

Server listens on `http://0.0.0.0:3000` and serves the browser client from the same origin.

Set `JWT_SECRET` in your environment before running in production:

```bash
JWT_SECRET=your-secret-here npm start
```

---

## Docker

```bash
docker compose up -d --build
```

Data (SQLite DB + encrypted media) is persisted to `./data/`.

---

## Repository layout

```
server.js          — HTTP routing + WebSocket server
backend/
  db.js            — SQLite schema and migrations
  auth.js          — register, login, JWT middleware
  messages.js      — conversation and message storage
  media.js         — encrypted blob upload/download
  ws.js            — real-time delivery and ack
app.js             — browser client: crypto, state machine, UI
index.html         — app shell (auth, home, chat screens)
styles.css         — UI: deadplug.digital aesthetic
data/              — SQLite DB and encrypted media (gitignored)
```

---

## What the server can and cannot see

| | Visible to server |
|---|---|
| Usernames | yes |
| Password | hashed (bcrypt) |
| Public keys | yes (required for key exchange) |
| Private keys | encrypted ciphertext only |
| Message content | no |
| Media content | no |
| Filenames / MIME types | no |
| Conversation shared key | no |
