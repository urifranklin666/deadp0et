# deadp0et

`deadp0et` is a secure messaging app in active development. The repo currently includes a working backend, a React
Native / Expo mobile client, a browser reference client, and shared client logic used across both.

The product direction is straightforward:

- account-based secure messaging with per-device key material
- local encryption and decryption on client devices
- server-side routing, mailbox storage, and device bundle distribution
- multi-device account support with device trust and prekey management

## Current product surface

The mobile app now supports:

- account creation and login against the live backend
- secure local storage of session and device state
- real per-device key generation
- encrypted compose and inbox decrypt flows
- trust-on-first-use device verification with safety numbers
- trust record review and explicit re-trust of changed device keys
- device listing, low-prekey monitoring, local prekey replenishment, revocation of other devices
- registration of this phone as an additional device
- settings for backend URL, health checks, logout, and local state reset

The browser app remains in the repo as a reference client and development surface for the same backend and protocol.

## Repository layout

- `mobile/`: Expo / React Native client
- `packages/protocol-client/`: shared client helpers and API surface
- `protocol-client.js`: browser-safe shared helper bundle
- `backend/`: modular Node.js backend services
- `server.js`: backend entrypoint
- `app.js`, `index.html`, `styles.css`: browser reference client
- `docs/api-contract.md`: backend API contract
- `docs/protocol.md`: protocol and design notes

## Backend

The backend already implements the core app flows:

- account creation and session issuance
- login throttling and active-session limits
- public device bundle lookup
- authenticated device registration, revocation, and prekey rotation
- one-time prekey reservation and release lifecycle
- encrypted envelope delivery, inbox fetch, and acknowledgement
- health reporting and prekey-related counters

The service is split by domain under `backend/` so storage and delivery work can keep evolving without collapsing back
into one large server file.

## Running locally

Install dependencies:

```bash
npm install
```

Run the backend:

```bash
npm start
```

The backend listens on `http://0.0.0.0:3000` by default and serves the browser client from the same origin.

Run the mobile app:

```bash
npm --workspace mobile start
```

If you are working on the Expo client, use a current Node 20 release. The mobile workspace may install on older Node
versions, but Expo tooling is more reliable on Node 20.x.

## Testing

Run the backend test suite:

```bash
npm test
```

Run the mobile typecheck:

```bash
./node_modules/.bin/tsc -p mobile/tsconfig.json --noEmit
```

## Deployment

This repo includes:

- `Dockerfile`
- `docker-compose.yml`

Start the service with:

```bash
docker compose up -d --build
```

## Roadmap

The highest-value next steps are:

- push notification registration and delivery signaling
- richer mobile onboarding and device portability
- production datastore replacement for the file-backed repository
- stronger auth and recovery flows
- ratcheting and further protocol hardening
- media, conversation UX, and app polish

## Documentation

- API contract: [docs/api-contract.md](./docs/api-contract.md)
- Protocol notes: [docs/protocol.md](./docs/protocol.md)
