# deadp0et

`deadp0et` is evolving from a passphrase demo into a real secure-messaging architecture. The repo now combines a
browser-based protocol prototype with a modular Node.js backend for account creation, public key registration,
encrypted message envelopes, and server-assisted delivery that keeps plaintext on client devices.

## What this version includes

- Account creation and sign-in flows modeled in the browser
- Local generation of per-device ECDH identity keys and signed prekeys
- Recipient directory records that expose only public bundles
- Encrypted message envelopes sent through a real HTTP backend mailbox
- Local decryption of inbox messages addressed to the signed-in user
- Protocol and server API documentation in [`docs/protocol.md`](./docs/protocol.md) and [`docs/api-contract.md`](./docs/api-contract.md)

## Security shape

The current design aims for this trust model:

- The server knows usernames, device ids, and message routing metadata
- The server stores public keys and opaque ciphertext envelopes
- The sender encrypts before upload
- The recipient decrypts after download
- Private device keys stay local to the client

## Important caveat

This is still a prototype. It demonstrates the product and protocol direction, but it is not yet a hardened
production messenger. To get there, we still need:

- A real datastore behind the current file-backed repository layer
- A stronger registration and login flow with hardened password handling
- X3DH or an equivalent audited handshake
- A Double Ratchet or equivalent per-message ratchet
- Device recovery, backup, and account recovery flows
- Security review and independent cryptographic audit

## Files

- `index.html` and `styles.css`: product UI for account, directory, compose, and inbox flows
- `app.js`: browser-side protocol prototype and simulated server behavior
- `docs/protocol.md`: protocol design draft
- `docs/api-contract.md`: backend API contract

## Backend status

This repo now includes a working backend entrypoint in `server.js` plus modular backend code under `./backend/`.
It implements the documented API contract with:

- account creation and session issuance
- login throttling and active-session caps
- public device bundle lookup
- authenticated device registration and revocation
- prekey rotation for active devices
- one-time prekey reservation, release, and burn-on-ack flows
- encrypted envelope delivery to recipient devices
- delivered, expired, and read tracking for inbox messages
- file-backed persistence in `./data/store.json`

### Backend layout

- `server.js`: HTTP server entrypoint
- `backend/app.js`: route dispatch and top-level request handling
- `backend/http.js`: JSON/body/static helpers
- `backend/auth.js`: account creation, login, sessions, throttling
- `backend/prekeys.js`: bundle issuance and reservation lifecycle
- `backend/messages.js`: envelope delivery, inbox fetch, acknowledgement
- `backend/devices.js`: device registration, revocation, rotation, health metrics
- `backend/store.js`: file-backed repositories for accounts, sessions, messages, and reservations
- `backend/shared.js`: shared domain helpers and validators

### Current architecture notes

- Business logic is split by domain rather than kept in one server file.
- Services operate on explicit repositories instead of mutating a raw store object directly.
- Persistence is still JSON-file based, so the main next backend step is replacing the storage implementation without rewriting the service layer.

### Run it

```bash
npm start
```

The service listens on `http://0.0.0.0:3000` by default. Override with `PORT` or `HOST` if needed.

The backend also serves the browser client directly:

- `GET /` serves `index.html`
- `GET /app.js` serves the frontend script
- `GET /styles.css` serves the app stylesheet

That means local testing can happen at a single origin, usually `http://127.0.0.1:3000/`.

The frontend defaults its API base to `window.location.origin`, so when served through
`https://deadp0et.deadplug.digital` it will automatically talk to the correct proxied backend endpoint.

### Test it

```bash
npm test
```

The test suite uses Node's built-in `node:test` runner and exercises the backend over real HTTP requests with an
isolated temporary data directory. It currently covers account flows, session expiry and throttling, device
management, prekey reservation lifecycle, message delivery, acknowledgement, and health-related counters.

### Docker deployment

This repo now includes:

- `Dockerfile`
- `docker-compose.yml`

Start it with:

```bash
docker compose up -d --build
```

The container joins the existing external `proxy` network so Nginx Proxy Manager can route a hostname like
`deadp0et.deadplug.digital` to the upstream container `deadp0et` on port `3000`.

### Notes

- This is still a prototype backend. The browser still submits a simplified `passwordVerifier`, but the server now stores a derived record instead of the raw verifier.
- Sessions are opaque bearer tokens with a fixed expiration window.
- The backend exposes a `GET /health` endpoint with message, session, and prekey-reservation counters.
- It does not decrypt message contents.
- It is intended to give the frontend a real server surface that matches `docs/api-contract.md`.

### Discord GitHub updates

This repo includes a workflow at `.github/workflows/discord-updates.yml` that posts notifications to Discord for:

- pushes
- pull request opens/updates/merges/closes
- published releases

To enable it, add a repository secret:

- `DISCORD_WEBHOOK_URL`: your Discord channel webhook URL
