# deadp0et Server API Contract

## `POST /v1/accounts`

Creates a new account and registers the first device bundle.

Request:

```json
{
  "username": "iris",
  "passwordVerifier": "opaque-or-argon2-verifier",
  "device": {
    "deviceId": "uuid",
    "identityKey": {"kty": "..."},
    "signedPrekey": {"kty": "..."},
    "prekeySignature": "base64"
  }
}
```

Response:

```json
{
  "accountId": "uuid",
  "username": "iris",
  "session": {
    "accessToken": "opaque-token",
    "deviceId": "uuid",
    "expiresAt": "2026-04-17T00:00:00.000Z"
  }
}
```

## `POST /v1/sessions`

Authenticates an existing account and returns a session.

Behavior notes:

- Sessions are device-scoped.
- Expired or revoked-device sessions are rejected with `401`.
- Repeated failed login attempts are throttled and may return `429` with `Retry-After`.

## `GET /v1/users/:username/bundles`

Returns the active public key bundles for a recipient account.

Response:

```json
{
  "username": "noor",
  "lowOneTimePrekeyThreshold": 5,
  "prekeyWarnings": [
    {
      "deviceId": "uuid",
      "warning": "Low one-time prekeys for device uuid: 2 remaining (threshold 5)."
    }
  ],
  "devices": [
    {
      "deviceId": "uuid",
      "identityKey": {"kty": "..."},
      "signedPrekey": {"kty": "..."},
      "prekeySignature": "base64",
      "availableOneTimePrekeys": 2,
      "lowOneTimePrekeys": true,
      "prekeyWarning": "Low one-time prekeys for device uuid: 2 remaining (threshold 5)."
    }
  ]
}
```

## `POST /v1/users/:username/prekey-bundle`

Reserves and returns one delivery bundle for a recipient device. The response includes the signed prekey and at most
one one-time prekey. If one-time prekeys are depleted, `oneTimePrekey` is `null`. Reservation tokens are short-lived;
expired unused reservations are released back to available prekeys.

Request (optional `deviceId` targeting):

```json
{
  "deviceId": "uuid"
}
```

Response:

```json
{
  "username": "noor",
  "issuedAt": "2026-04-17T00:00:00.000Z",
  "device": {
    "deviceId": "uuid",
    "identityKey": {"kty": "..."},
    "signedPrekey": {"kty": "..."},
    "prekeySignature": "base64"
  },
  "oneTimePrekey": {"keyId": "otk-1", "key": {"kty": "..."}},
  "oneTimePrekeyReservedAt": "2026-04-17T00:00:00.000Z",
  "prekeyReservationToken": "opaque-reservation-token",
  "prekeyReservationExpiresAt": "2026-04-17T00:10:00.000Z"
}
```

## `POST /v1/messages`

Stores an encrypted envelope for delivery.

Request:

```json
{
  "to": "noor",
  "recipientDeviceId": "uuid",
  "envelope": {
    "protocol": "deadp0et-envelope-v1",
    "ephemeralKey": {"kty": "..."},
    "iv": "base64",
    "ciphertext": "base64",
    "oneTimePrekeyId": "optional-otk-id",
    "prekeyReservationToken": "required-token-from-prekey-bundle"
  }
}
```

## `GET /v1/messages/inbox`

Returns message envelopes addressed to the authenticated device or account.

Response fields may include delivery metadata such as `deliveredAt`, `readAt`, and `deliveryCount`. Messages whose
reservation TTL has expired before acknowledgement are omitted from inbox results.

The current backend defaults the inbox view to the authenticated session device unless a `deviceId` query parameter is
provided.

## `POST /v1/messages/inbox/ack`

Marks one or more inbox messages as read for the authenticated device.
For messages that used a one-time prekey, include a matching proof entry so the server can burn the reserved prekey.

Request:

```json
{
  "messageIds": ["uuid"],
  "oneTimePrekeyProofs": [
    {
      "messageId": "uuid",
      "oneTimePrekeyId": "otk-1"
    }
  ]
}
```

## `POST /v1/devices`

Registers an additional device for an authenticated account.

## `GET /v1/devices`

Lists the authenticated account's devices, including revoked devices.

Response includes per-device one-time prekey telemetry and a `prekeyWarnings` array for active low-prekey devices.

## `DELETE /v1/devices/:deviceId`

Revokes a device and prevents future deliveries to it.

## `POST /v1/prekeys/rotate`

Uploads fresh signed and one-time prekeys for a device.

## `GET /health`

Returns backend health and operational counters.

Response fields currently include:

- `status`
- `accounts`
- `sessions`
- `messages`
- `prekeyReservations`
- `deliveredPendingAckReservations`
- `releasedPrekeyReservations`
- `reservedOneTimePrekeys`
- `consumedOneTimePrekeys`
- `expiredMessages`
