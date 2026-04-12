# `@deadp0et/protocol-client`

Shared client logic for `deadp0et`.

This package is the extraction target for logic that should work in both:

- the existing browser prototype
- the future mobile app

It should stay free of:

- DOM access
- direct `localStorage` access
- React component code

Initial module responsibilities:

- `api.js`: backend HTTP client helpers
- `devices.js`: local device record helpers, serialization, hydration, and prekey-record transforms
- `trust.js`: device fingerprint and trust record helpers
- `storage-schema.js`: shared storage key names and data-shape notes

Current extraction status:

- browser and mobile can share API client logic
- browser and mobile can share local-device record transformations
- browser and mobile can share trust-state evaluation logic

Still intentionally outside this package for now:

- DOM behavior
- direct storage implementation
- Web Crypto key generation and envelope crypto primitives

Future work will move encryption, decryption, and key import/export orchestration here as browser-specific assumptions are removed from `app.js`.
