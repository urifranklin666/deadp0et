# deadp0et

`deadp0et` is a sleek prototype for secure encrypted messaging. The first version is intentionally simple:
it encrypts and decrypts messages directly in the browser using the Web Crypto API, packages ciphertext as
JSON, and avoids any server dependency.

## What it does today

- Encrypts plaintext with AES-GCM in the browser
- Derives keys from a shared passphrase using PBKDF2-SHA-256
- Produces a portable payload that can be pasted into any transport channel
- Decrypts matching payloads locally with the same passphrase

## Why this shape

This repository is a good starting point for a secure-messaging product because it lets us validate the user
experience first while keeping the cryptography local and inspectable. It is a prototype, not a full secure
messaging system yet.

## Running locally

Because this is a static app, you can open `index.html` directly in a modern browser or serve the folder with
any static file server.

## Production roadmap

Before calling this production-grade, we would want:

- Verified user identity and device trust
- A protocol designed for forward secrecy and message authenticity
- A backend for encrypted mailbox delivery, sync, and key distribution
- Security review and independent cryptographic audit

## Repository starter

Suggested next steps after the initial commit:

1. Push this project to a private GitHub repository named `deadp0et`
2. Add an issue tracker for roadmap items
3. Decide whether the next milestone is a richer front end, a backend, or a real messaging protocol
