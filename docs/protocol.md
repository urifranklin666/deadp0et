# deadp0et Protocol Draft

## Goals

- Let users create service accounts on our server
- Keep message plaintext unavailable to the server
- Support device-level key material generated on the client
- Provide a clean path toward multi-device support and forward secrecy

## Core model

Each account has:

- A server account record: `username`, password verifier, profile metadata
- One or more devices
- One device identity key pair per device
- One signed prekey per device
- A rotating set of one-time prekeys in production

The server stores:

- Account metadata
- Password authentication data
- Public key bundles for each device
- Message envelopes addressed to recipient devices

The server must not store:

- Plaintext message subjects or bodies
- Device private keys
- Recoverable symmetric message keys

## Account registration

1. The client creates an account with `username` and `password`
2. The client derives a password-authentication secret for the server
3. The client generates a device identity key pair locally
4. The client generates a signed prekey locally
5. The client uploads only the public bundle:

```json
{
  "username": "iris",
  "deviceId": "uuid",
  "identityKey": {"kty": "..."},
  "signedPrekey": {"kty": "..."},
  "prekeySignature": "base64"
}
```

In production, the server should never receive a raw password. Use an audited PAKE or a hardened verifier flow.

## Authentication

The current prototype models password login only. Production should use:

- Argon2id or a PAKE-backed verifier flow
- HttpOnly secure session cookies or short-lived access tokens
- Session binding to device registration state
- Rate limits and abuse controls

## Session establishment

To send a first message:

1. Sender authenticates to the server
2. Sender requests recipient device bundles
3. Sender picks one recipient device bundle
4. Sender generates an ephemeral ECDH key pair
5. Sender derives a shared secret from:
   sender ephemeral private key x recipient signed prekey public key
6. Sender derives a content-encryption key from the shared secret
7. Sender encrypts the message payload locally with AES-GCM
8. Sender uploads an envelope containing ciphertext plus routing metadata

The receiving client:

1. Authenticates to the server
2. Fetches encrypted envelopes addressed to its device
3. Uses its signed prekey private key plus sender ephemeral public key to derive the same shared secret
4. Decrypts the payload locally

## Envelope shape

```json
{
  "protocol": "deadp0et-envelope-v1",
  "from": "iris",
  "to": "noor",
  "envelopeId": "uuid",
  "ephemeralKey": {"kty": "..."},
  "recipientDeviceId": "uuid",
  "iv": "base64",
  "ciphertext": "base64"
}
```

## Security notes

This prototype is intentionally simplified. To become serious production security, `deadp0et` still needs:

- X3DH-style multi-prekey handshake rather than a single signed-prekey derivation
- A Double Ratchet or equivalent post-handshake message ratchet
- Key transparency or identity verification UX
- Multi-device enrollment and revocation
- Replay protection and envelope authenticity checks
- Audited cryptographic choices and implementation review

## Suggested backend responsibilities

- Create and authenticate accounts
- Store and rotate public prekey bundles
- Deliver per-device envelopes
- Track message ids, timestamps, and unread state
- Enforce rate limits, abuse detection, and retention rules
- Never decrypt message contents
