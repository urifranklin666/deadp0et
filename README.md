# deadp0et

`deadp0et` is evolving from a passphrase demo into a real secure-messaging architecture. This revision adds a
browser-based protocol prototype for account creation, public key registration, encrypted message envelopes, and
server-assisted delivery that keeps plaintext on client devices.

## What this version includes

- Account creation and sign-in flows modeled in the browser
- Local generation of per-device ECDH identity keys and signed prekeys
- Recipient directory records that expose only public bundles
- Encrypted message envelopes sent through a simulated server mailbox
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

- A proper backend with persistent storage and authenticated sessions
- A real registration and login flow with hardened password handling
- X3DH or an equivalent audited handshake
- A Double Ratchet or equivalent per-message ratchet
- Multi-device enrollment and revocation
- Security review and independent cryptographic audit

## Files

- `index.html` and `styles.css`: product UI for account, directory, compose, and inbox flows
- `app.js`: browser-side protocol prototype and simulated server behavior
- `docs/protocol.md`: protocol design draft
- `docs/api-contract.md`: backend API contract

## Next milestone

The next strong move is building the actual backend service that matches the API contract while keeping all
message encryption and decryption inside the client.
