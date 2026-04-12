import {
  appendLocalOneTimePrekeysRecord,
  hydrateLocalDeviceRecord,
  serializeLocalDeviceRecord
} from "@deadp0et/protocol-client";

const ONE_TIME_PREKEY_BATCH_SIZE = 8;

export type LocalPrivateKeys = {
  identityPrivateKey: CryptoKey;
  signedPrekeyPrivateKey: CryptoKey;
  oneTimePrekeyPrivateKeys: Record<string, CryptoKey>;
};

export type DeviceBundle = {
  privateKeys: LocalPrivateKeys;
  publicBundle: {
    deviceId: string;
    identityKey: JsonWebKey;
    signedPrekey: JsonWebKey;
    prekeySignature: string;
    oneTimePrekeys: Array<{ keyId: string; key: JsonWebKey }>;
  };
};

export type HydratedMobileDeviceRecord = {
  username: string;
  accountId: string;
  passwordVerifier: string;
  publicBundle: DeviceBundle["publicBundle"];
  privateKeys: LocalPrivateKeys;
};

function requireCrypto() {
  const cryptoObject = globalThis.crypto;
  if (!cryptoObject?.subtle) {
    throw new Error("WebCrypto is not available in this mobile runtime.");
  }
  return cryptoObject;
}

const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

export function bytesToBase64(bytes: Uint8Array) {
  let output = "";
  for (let index = 0; index < bytes.length; index += 3) {
    const byte1 = bytes[index] ?? 0;
    const byte2 = bytes[index + 1] ?? 0;
    const byte3 = bytes[index + 2] ?? 0;
    const triplet = (byte1 << 16) | (byte2 << 8) | byte3;

    output += BASE64_ALPHABET[(triplet >> 18) & 0x3f];
    output += BASE64_ALPHABET[(triplet >> 12) & 0x3f];
    output += index + 1 < bytes.length ? BASE64_ALPHABET[(triplet >> 6) & 0x3f] : "=";
    output += index + 2 < bytes.length ? BASE64_ALPHABET[triplet & 0x3f] : "=";
  }
  return output;
}

export function base64ToBytes(base64: string) {
  const normalized = String(base64 || "").replace(/[^A-Za-z0-9+/=]/g, "");
  if (!normalized) {
    return new Uint8Array();
  }

  const bytes: number[] = [];
  for (let index = 0; index < normalized.length; index += 4) {
    const char1 = normalized[index] || "A";
    const char2 = normalized[index + 1] || "A";
    const char3 = normalized[index + 2] || "A";
    const char4 = normalized[index + 3] || "A";

    const enc1 = BASE64_ALPHABET.indexOf(char1);
    const enc2 = BASE64_ALPHABET.indexOf(char2);
    const enc3 = char3 === "=" ? 0 : BASE64_ALPHABET.indexOf(char3);
    const enc4 = char4 === "=" ? 0 : BASE64_ALPHABET.indexOf(char4);

    const triplet = (enc1 << 18) | (enc2 << 12) | (enc3 << 6) | enc4;
    bytes.push((triplet >> 16) & 0xff);
    if (char3 !== "=") {
      bytes.push((triplet >> 8) & 0xff);
    }
    if (char4 !== "=") {
      bytes.push(triplet & 0xff);
    }
  }

  return Uint8Array.from(bytes);
}

export async function sha256(text: string) {
  const cryptoObject = requireCrypto();
  const bytes = new TextEncoder().encode(text);
  const digest = await cryptoObject.subtle.digest("SHA-256", bytes);
  return bytesToBase64(new Uint8Array(digest));
}

export async function sha256Hex(text: string) {
  const cryptoObject = requireCrypto();
  const bytes = new TextEncoder().encode(text);
  const digest = await cryptoObject.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");
}

export async function exportPrivateKey(privateKey: CryptoKey) {
  return requireCrypto().subtle.exportKey("jwk", privateKey);
}

export async function importPrivateKey(jwk: JsonWebKey) {
  return requireCrypto().subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
}

export async function generateOneTimePrekeySet(count = ONE_TIME_PREKEY_BATCH_SIZE) {
  const cryptoObject = requireCrypto();
  const publicOneTimePrekeys: Array<{ keyId: string; key: JsonWebKey }> = [];
  const privateOneTimePrekeyKeys: Record<string, CryptoKey> = {};

  for (let index = 0; index < count; index += 1) {
    const oneTimePrekeyPair = await cryptoObject.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"]
    );
    const keyId = cryptoObject.randomUUID();
    publicOneTimePrekeys.push({
      keyId,
      key: await cryptoObject.subtle.exportKey("jwk", oneTimePrekeyPair.publicKey)
    });
    privateOneTimePrekeyKeys[keyId] = oneTimePrekeyPair.privateKey;
  }

  return {
    publicOneTimePrekeys,
    privateOneTimePrekeyKeys
  };
}

export async function generateDeviceBundle() {
  const cryptoObject = requireCrypto();
  const identity = await cryptoObject.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
  const signedPrekey = await cryptoObject.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
  const identityPublic = await cryptoObject.subtle.exportKey("jwk", identity.publicKey);
  const prekeyPublic = await cryptoObject.subtle.exportKey("jwk", signedPrekey.publicKey);
  const oneTimePrekeySet = await generateOneTimePrekeySet();
  const prekeySignature = await sha256(JSON.stringify(identityPublic) + JSON.stringify(prekeyPublic));

  return {
    privateKeys: {
      identityPrivateKey: identity.privateKey,
      signedPrekeyPrivateKey: signedPrekey.privateKey,
      oneTimePrekeyPrivateKeys: oneTimePrekeySet.privateOneTimePrekeyKeys
    },
    publicBundle: {
      identityKey: identityPublic,
      signedPrekey: prekeyPublic,
      prekeySignature,
      oneTimePrekeys: oneTimePrekeySet.publicOneTimePrekeys,
      deviceId: cryptoObject.randomUUID()
    }
  } satisfies DeviceBundle;
}

export async function serializeMobileDeviceRecord({
  username,
  passwordVerifier,
  accountId,
  deviceBundle
}: {
  username: string;
  passwordVerifier: string;
  accountId: string;
  deviceBundle: DeviceBundle;
}) {
  return serializeLocalDeviceRecord({
    username,
    passwordVerifier,
    accountId,
    deviceBundle,
    exportPrivateKey
  });
}

export async function hydrateMobileDeviceRecord(record: unknown) {
  return hydrateLocalDeviceRecord(record, importPrivateKey) as Promise<HydratedMobileDeviceRecord | null>;
}

export async function deriveSharedSecret(privateKey: CryptoKey, remotePublicJwk: JsonWebKey) {
  const cryptoObject = requireCrypto();
  const remotePublicKey = await cryptoObject.subtle.importKey(
    "jwk",
    remotePublicJwk,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );
  const bits = await cryptoObject.subtle.deriveBits(
    { name: "ECDH", public: remotePublicKey },
    privateKey,
    256
  );
  return bytesToBase64(new Uint8Array(bits));
}

export async function deriveAesKey(sharedSecrets: string[] | string) {
  const cryptoObject = requireCrypto();
  const secretParts = Array.isArray(sharedSecrets) ? sharedSecrets : [sharedSecrets];
  const decodedParts = secretParts.map((secret) => base64ToBytes(secret));
  const totalLength = decodedParts.reduce((sum, bytes) => sum + bytes.length, 0);
  const joined = new Uint8Array(totalLength);
  let offset = 0;
  for (const bytes of decodedParts) {
    joined.set(bytes, offset);
    offset += bytes.length;
  }
  const digest = await cryptoObject.subtle.digest("SHA-256", joined);
  return cryptoObject.subtle.importKey("raw", digest, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

export async function encryptForRecipient({
  senderUsername,
  senderDeviceId,
  recipientBundle,
  subject,
  body
}: {
  senderUsername: string;
  senderDeviceId: string;
  recipientBundle: {
    device: {
      deviceId: string;
      signedPrekey: JsonWebKey;
    };
    username: string;
    oneTimePrekey?: { keyId: string; key: JsonWebKey } | null;
    prekeyReservationToken: string;
  };
  subject: string;
  body: string;
}) {
  const cryptoObject = requireCrypto();
  const ephemeral = await cryptoObject.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
  const ephemeralPublic = await cryptoObject.subtle.exportKey("jwk", ephemeral.publicKey);
  const sharedSecrets = [await deriveSharedSecret(ephemeral.privateKey, recipientBundle.device.signedPrekey)];
  let oneTimePrekeyId: string | null = null;

  if (recipientBundle.oneTimePrekey?.key) {
    sharedSecrets.push(await deriveSharedSecret(ephemeral.privateKey, recipientBundle.oneTimePrekey.key));
    oneTimePrekeyId = recipientBundle.oneTimePrekey.keyId || null;
  }

  const aesKey = await deriveAesKey(sharedSecrets);
  const iv = cryptoObject.getRandomValues(new Uint8Array(12));
  const payload = {
    subject,
    body,
    sentAt: new Date().toISOString(),
    senderDeviceId
  };
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));
  const ciphertext = await cryptoObject.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, plaintext);

  return {
    protocol: "deadp0et-envelope-v1",
    from: senderUsername,
    to: recipientBundle.username,
    envelopeId: cryptoObject.randomUUID(),
    recipientDeviceId: recipientBundle.device.deviceId,
    oneTimePrekeyId,
    prekeyReservationToken: recipientBundle.prekeyReservationToken,
    ephemeralKey: ephemeralPublic,
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext))
  };
}

export async function decryptEnvelope({
  privateKeys,
  envelope
}: {
  privateKeys: LocalPrivateKeys;
  envelope: {
    ephemeralKey: JsonWebKey;
    iv: string;
    ciphertext: string;
    oneTimePrekeyId?: string | null;
  };
}) {
  const cryptoObject = requireCrypto();
  const sharedSecrets = [await deriveSharedSecret(privateKeys.signedPrekeyPrivateKey, envelope.ephemeralKey)];
  const oneTimePrekeyId = typeof envelope.oneTimePrekeyId === "string" ? envelope.oneTimePrekeyId.trim() : "";

  if (oneTimePrekeyId) {
    const oneTimePrekeyPrivateKey = privateKeys.oneTimePrekeyPrivateKeys?.[oneTimePrekeyId];
    if (!oneTimePrekeyPrivateKey) {
      throw new Error("Missing local one-time prekey private key required for this envelope.");
    }
    sharedSecrets.push(await deriveSharedSecret(oneTimePrekeyPrivateKey, envelope.ephemeralKey));
  }

  const aesKey = await deriveAesKey(sharedSecrets);
  const plaintext = await cryptoObject.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(envelope.iv) },
    aesKey,
    base64ToBytes(envelope.ciphertext)
  );

  return {
    payload: JSON.parse(new TextDecoder().decode(plaintext)),
    oneTimePrekeyId: oneTimePrekeyId || null
  };
}

export async function appendOneTimePrekeysToStoredRecord(record: unknown, privateKeys: Record<string, CryptoKey>, publicKeys = []) {
  return appendLocalOneTimePrekeysRecord(record, privateKeys, publicKeys, exportPrivateKey);
}
