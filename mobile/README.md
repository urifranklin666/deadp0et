# deadp0et mobile

This directory contains the initial React Native / Expo scaffold for the mobile client.

Current status:

- navigation shell exists
- screen placeholders exist for signup, login, inbox, devices, and settings
- secure storage and push-notification wrappers are stubbed
- shared logic is beginning to move into `packages/protocol-client`
- the shared API client and local-device helper layer now exists, but the screens are not wired yet

Next implementation steps:

1. install workspace dependencies
2. connect signup and login screens to the shared API client
3. reuse shared local-device serialization/hydration helpers
4. implement secure local device persistence and inbox sync
