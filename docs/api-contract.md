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

## `GET /v1/users/:username/bundles`

Returns the active public key bundles for a recipient account.

Response:

```json
{
  "username": "noor",
  "devices": [
    {
      "deviceId": "uuid",
      "identityKey": {"kty": "..."},
      "signedPrekey": {"kty": "..."},
      "prekeySignature": "base64"
    }
  ]
}
```

## `POST /v1/users/:username/prekey-bundle`

Reserves and returns one delivery bundle for a recipient device. The response includes the signed prekey and at most
one one-time prekey. If one-time prekeys are depleted, `oneTimePrekey` is `null`.

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
  "oneTimePrekeyConsumedAt": "2026-04-17T00:00:00.000Z"
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
    "ciphertext": "base64"
  }
}
```

## `GET /v1/messages/inbox`

Returns message envelopes addressed to the authenticated device or account.

Response fields may include delivery metadata such as `deliveredAt`, `readAt`, and `deliveryCount`.

## `POST /v1/messages/inbox/ack`

Marks one or more inbox messages as read for the authenticated device.

Request:

```json
{
  "messageIds": ["uuid"]
}
```

## `POST /v1/devices`

Registers an additional device for an authenticated account.

## `GET /v1/devices`

Lists the authenticated account's devices, including revoked devices.

## `DELETE /v1/devices/:deviceId`

Revokes a device and prevents future deliveries to it.

## `POST /v1/prekeys/rotate`

Uploads fresh signed and one-time prekeys for a device.
