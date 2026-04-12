const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const net = require("node:net");
const { spawn } = require("node:child_process");

async function getFreePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close(() => resolve(address.port));
    });
    server.on("error", reject);
  });
}

async function waitForHealthy(baseUrl, timeoutMs = 5000) {
  const startedAt = Date.now();

  while (Date.now() - startedAt < timeoutMs) {
    try {
      const response = await fetch(`${baseUrl}/health`);
      if (response.ok) {
        return;
      }
    } catch (error) {
      // Retry until timeout.
    }

    await new Promise((resolve) => setTimeout(resolve, 100));
  }

  throw new Error(`Server at ${baseUrl} did not become healthy within ${timeoutMs}ms.`);
}

async function requestJson(baseUrl, pathname, options = {}) {
  const response = await fetch(`${baseUrl}${pathname}`, options);
  const text = await response.text();
  const body = text ? JSON.parse(text) : null;
  return {
    status: response.status,
    body
  };
}

async function startServer(t, extraEnv = {}, initialStore = null) {
  const port = await getFreePort();
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "deadp0et-test-"));
  const baseUrl = `http://127.0.0.1:${port}`;

  if (initialStore) {
    fs.writeFileSync(path.join(dataDir, "store.json"), JSON.stringify(initialStore, null, 2));
  }

  const child = spawn(process.execPath, ["server.js"], {
    cwd: path.join(__dirname, ".."),
    env: {
      ...process.env,
      PORT: String(port),
      DATA_DIR: dataDir,
      ...extraEnv
    },
    stdio: ["ignore", "pipe", "pipe"]
  });

  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => {
    stdout += chunk.toString();
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString();
  });

  t.after(async () => {
    child.kill("SIGTERM");
    await new Promise((resolve) => child.once("exit", resolve));
    fs.rmSync(dataDir, { recursive: true, force: true });
  });

  await waitForHealthy(baseUrl);
  return { baseUrl, dataDir, stdoutRef: () => stdout, stderrRef: () => stderr };
}

test("deadp0et backend API flow", async (t) => {
  const { baseUrl, dataDir, stdoutRef, stderrRef } = await startServer(t);

  const irisCreate = await requestJson(baseUrl, "/v1/accounts", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "iris",
      passwordVerifier: "demo-verifier",
      device: {
        deviceId: "device-iris-1",
        identityKey: { kty: "EC", crv: "P-256" },
        signedPrekey: { kty: "EC", crv: "P-256" },
        prekeySignature: "sig-1"
      }
    })
  });

  assert.equal(irisCreate.status, 201);
  assert.equal(irisCreate.body.username, "iris");
  assert.equal(irisCreate.body.session.deviceId, "device-iris-1");
  assert.match(irisCreate.body.session.expiresAt, /^\d{4}-\d{2}-\d{2}T/);

  const noorCreate = await requestJson(baseUrl, "/v1/accounts", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "noor",
      passwordVerifier: "demo-verifier",
      device: {
        deviceId: "device-noor-1",
        identityKey: { kty: "EC", crv: "P-256" },
        signedPrekey: { kty: "EC", crv: "P-256" },
        prekeySignature: "sig-2"
      }
    })
  });

  assert.equal(noorCreate.status, 201);

  const bundles = await requestJson(baseUrl, "/v1/users/noor/bundles");
  assert.equal(bundles.status, 200);
  assert.equal(typeof bundles.body.lowOneTimePrekeyThreshold, "number");
  assert.ok(Array.isArray(bundles.body.prekeyWarnings));
  assert.equal(bundles.body.devices.length, 1);
  assert.equal(bundles.body.devices[0].deviceId, "device-noor-1");
  assert.equal(typeof bundles.body.devices[0].availableOneTimePrekeys, "number");
  assert.equal(typeof bundles.body.devices[0].lowOneTimePrekeys, "boolean");

  const prekeyBundle = await requestJson(baseUrl, "/v1/users/noor/prekey-bundle", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({})
  });
  assert.equal(prekeyBundle.status, 200);
  assert.equal(typeof prekeyBundle.body.prekeyReservationToken, "string");
  assert.match(prekeyBundle.body.prekeyReservationToken, /^[a-f0-9]{64}$/);

  const deliver = await requestJson(baseUrl, "/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${irisCreate.body.session.accessToken}`
    },
    body: JSON.stringify({
      to: "noor",
      recipientDeviceId: "device-noor-1",
      envelope: {
        protocol: "deadp0et-envelope-v1",
        ephemeralKey: { kty: "EC", crv: "P-256" },
        iv: "demo-iv",
        ciphertext: "demo-ciphertext",
        prekeyReservationToken: prekeyBundle.body.prekeyReservationToken
      }
    })
  });

  assert.equal(deliver.status, 201);
  assert.ok(deliver.body.messageId);

  const inboxFirst = await requestJson(baseUrl, "/v1/messages/inbox", {
    headers: {
      Authorization: `Bearer ${noorCreate.body.session.accessToken}`
    }
  });

  assert.equal(inboxFirst.status, 200);
  assert.equal(inboxFirst.body.messages.length, 1);
  assert.equal(inboxFirst.body.messages[0].deliveryCount, 1);
  assert.equal(inboxFirst.body.messages[0].readAt, null);
  assert.match(inboxFirst.body.messages[0].deliveredAt, /^\d{4}-\d{2}-\d{2}T/);

  const ack = await requestJson(baseUrl, "/v1/messages/inbox/ack", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${noorCreate.body.session.accessToken}`
    },
    body: JSON.stringify({
      messageIds: [deliver.body.messageId]
    })
  });

  assert.equal(ack.status, 200);
  assert.equal(ack.body.acknowledged, 1);

  const inboxSecond = await requestJson(baseUrl, "/v1/messages/inbox", {
    headers: {
      Authorization: `Bearer ${noorCreate.body.session.accessToken}`
    }
  });

  assert.equal(inboxSecond.status, 200);
  assert.equal(inboxSecond.body.messages[0].deliveryCount, 2);
  assert.match(inboxSecond.body.messages[0].readAt, /^\d{4}-\d{2}-\d{2}T/);

  const revokeLastDevice = await requestJson(baseUrl, "/v1/devices/device-noor-1", {
    method: "DELETE",
    headers: {
      Authorization: `Bearer ${noorCreate.body.session.accessToken}`
    }
  });

  assert.equal(revokeLastDevice.status, 409);
  assert.match(revokeLastDevice.body.error.message, /last active device/);

  const login = await requestJson(baseUrl, "/v1/sessions", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "iris",
      passwordVerifier: "demo-verifier",
      deviceId: "device-iris-1"
    })
  });

  assert.equal(login.status, 200);
  assert.match(login.body.session.expiresAt, /^\d{4}-\d{2}-\d{2}T/);

  const health = await requestJson(baseUrl, "/health");
  assert.equal(health.status, 200);
  assert.equal(typeof health.body.prekeyReservations, "number");
  assert.equal(typeof health.body.deliveredPendingAckReservations, "number");
  assert.equal(typeof health.body.releasedPrekeyReservations, "number");
  assert.equal(typeof health.body.reservedOneTimePrekeys, "number");
  assert.equal(typeof health.body.consumedOneTimePrekeys, "number");
  assert.equal(typeof health.body.expiredMessages, "number");

  const storeFile = path.join(dataDir, "store.json");
  const store = JSON.parse(fs.readFileSync(storeFile, "utf8"));
  assert.equal(typeof store.accounts[0].verifier.digest, "string");
  assert.equal("passwordVerifier" in store.accounts[0], false);
  assert.match(stdoutRef(), /deadp0et backend listening/);
  assert.equal(stderrRef(), "");
});

test("deadp0et expires short-lived sessions", async (t) => {
  const { baseUrl } = await startServer(t, { SESSION_TTL_MS: "25" });

  const create = await requestJson(baseUrl, "/v1/accounts", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "iris",
      passwordVerifier: "demo-verifier",
      device: {
        deviceId: "device-iris-1",
        identityKey: { kty: "EC", crv: "P-256" },
        signedPrekey: { kty: "EC", crv: "P-256" },
        prekeySignature: "sig-1"
      }
    })
  });

  assert.equal(create.status, 201);
  await new Promise((resolve) => setTimeout(resolve, 60));

  const expiredSessionResult = await requestJson(baseUrl, "/v1/messages/inbox", {
    headers: {
      Authorization: `Bearer ${create.body.session.accessToken}`
    }
  });

  assert.equal(expiredSessionResult.status, 401);
  assert.match(expiredSessionResult.body.error.message, /expired/);
});

test("deadp0et supports multi-device registration, prekey rotation, and targeted revocation", async (t) => {
  const { baseUrl, dataDir } = await startServer(t);

  const create = await requestJson(baseUrl, "/v1/accounts", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "iris",
      passwordVerifier: "demo-verifier",
      device: {
        deviceId: "device-iris-1",
        identityKey: { kty: "EC", crv: "P-256" },
        signedPrekey: { kty: "EC", crv: "P-256" },
        prekeySignature: "sig-1"
      }
    })
  });

  assert.equal(create.status, 201);

  const addDevice = await requestJson(baseUrl, "/v1/devices", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${create.body.session.accessToken}`
    },
    body: JSON.stringify({
      device: {
        deviceId: "device-iris-2",
        identityKey: { kty: "EC", crv: "P-256", x: "identity-two" },
        signedPrekey: { kty: "EC", crv: "P-256", x: "prekey-two" },
        prekeySignature: "sig-2",
        oneTimePrekeys: [{ keyId: "otk-1", key: { kty: "EC", crv: "P-256", x: "otk-one" } }]
      }
    })
  });

  assert.equal(addDevice.status, 201);
  assert.equal(addDevice.body.device.deviceId, "device-iris-2");

  const listedDevices = await requestJson(baseUrl, "/v1/devices", {
    headers: {
      Authorization: `Bearer ${create.body.session.accessToken}`
    }
  });

  assert.equal(listedDevices.status, 200);
  assert.equal(typeof listedDevices.body.lowOneTimePrekeyThreshold, "number");
  assert.ok(Array.isArray(listedDevices.body.prekeyWarnings));
  assert.equal(listedDevices.body.devices.length, 2);
  assert.equal(typeof listedDevices.body.devices[0].availableOneTimePrekeys, "number");

  const bundlesAfterAdd = await requestJson(baseUrl, "/v1/users/iris/bundles");
  assert.equal(bundlesAfterAdd.status, 200);
  assert.equal(bundlesAfterAdd.body.devices.length, 2);

  const rotate = await requestJson(baseUrl, "/v1/prekeys/rotate", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${create.body.session.accessToken}`
    },
    body: JSON.stringify({
      deviceId: "device-iris-2",
      signedPrekey: { kty: "EC", crv: "P-256", x: "rotated-prekey" },
      prekeySignature: "rotated-sig",
      oneTimePrekeys: [
        { keyId: "otk-2", key: { kty: "EC", crv: "P-256", x: "otk-two" } },
        { keyId: "otk-3", key: { kty: "EC", crv: "P-256", x: "otk-three" } }
      ]
    })
  });

  assert.equal(rotate.status, 200);
  assert.equal(rotate.body.device.deviceId, "device-iris-2");
  assert.equal(rotate.body.device.prekeySignature, "rotated-sig");
  assert.equal(rotate.body.device.oneTimePrekeys.length, 2);

  const revokeSecondDevice = await requestJson(baseUrl, "/v1/devices/device-iris-2", {
    method: "DELETE",
    headers: {
      Authorization: `Bearer ${create.body.session.accessToken}`
    }
  });

  assert.equal(revokeSecondDevice.status, 200);
  assert.equal(revokeSecondDevice.body.deviceId, "device-iris-2");

  const bundlesAfterRevoke = await requestJson(baseUrl, "/v1/users/iris/bundles");
  assert.equal(bundlesAfterRevoke.status, 200);
  assert.equal(bundlesAfterRevoke.body.devices.length, 1);
  assert.equal(bundlesAfterRevoke.body.devices[0].deviceId, "device-iris-1");

  const storeFile = path.join(dataDir, "store.json");
  const store = JSON.parse(fs.readFileSync(storeFile, "utf8"));
  const secondDevice = store.accounts[0].devices.find((device) => device.deviceId === "device-iris-2");
  assert.equal(secondDevice.prekeySignature, "rotated-sig");
  assert.equal(secondDevice.oneTimePrekeys.length, 2);
  assert.match(secondDevice.revokedAt, /^\d{4}-\d{2}-\d{2}T/);
});

test("deadp0et reserves one-time prekeys on bundle issuance and defers consumption to ack", async (t) => {
  const { baseUrl, dataDir } = await startServer(t);

  const createRecipient = await requestJson(baseUrl, "/v1/accounts", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "noor",
      passwordVerifier: "demo-verifier",
      device: {
        deviceId: "device-noor-1",
        identityKey: { kty: "EC", crv: "P-256" },
        signedPrekey: { kty: "EC", crv: "P-256" },
        prekeySignature: "sig-1",
        oneTimePrekeys: [
          { keyId: "otk-1", key: { kty: "EC", crv: "P-256", x: "one" } },
          { keyId: "otk-2", key: { kty: "EC", crv: "P-256", x: "two" } }
        ]
      }
    })
  });
  assert.equal(createRecipient.status, 201);

  const firstBundle = await requestJson(baseUrl, "/v1/users/noor/prekey-bundle", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({})
  });
  assert.equal(firstBundle.status, 200);
  assert.equal(firstBundle.body.device.deviceId, "device-noor-1");
  assert.equal(firstBundle.body.oneTimePrekey.keyId, "otk-1");
  assert.match(firstBundle.body.oneTimePrekeyReservedAt, /^\d{4}-\d{2}-\d{2}T/);
  assert.match(firstBundle.body.prekeyReservationToken, /^[a-f0-9]{64}$/);
  assert.match(firstBundle.body.prekeyReservationExpiresAt, /^\d{4}-\d{2}-\d{2}T/);

  const secondBundle = await requestJson(baseUrl, "/v1/users/noor/prekey-bundle", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({})
  });
  assert.equal(secondBundle.status, 200);
  assert.equal(secondBundle.body.oneTimePrekey.keyId, "otk-2");
  assert.match(secondBundle.body.prekeyReservationToken, /^[a-f0-9]{64}$/);

  const thirdBundle = await requestJson(baseUrl, "/v1/users/noor/prekey-bundle", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({})
  });
  assert.equal(thirdBundle.status, 200);
  assert.equal(thirdBundle.body.oneTimePrekey, null);
  assert.equal(thirdBundle.body.oneTimePrekeyReservedAt, null);
  assert.match(thirdBundle.body.prekeyReservationToken, /^[a-f0-9]{64}$/);

  const storeFile = path.join(dataDir, "store.json");
  const persisted = JSON.parse(fs.readFileSync(storeFile, "utf8"));
  const recipient = persisted.accounts.find((account) => account.username === "noor");
  assert.ok(recipient);
  assert.equal(recipient.devices[0].oneTimePrekeys.length, 0);
  assert.equal(recipient.devices[0].reservedOneTimePrekeys.length, 2);
  assert.equal(recipient.devices[0].reservedOneTimePrekeys[0].prekey.keyId, "otk-1");
  assert.equal(recipient.devices[0].reservedOneTimePrekeys[1].prekey.keyId, "otk-2");
  assert.equal(recipient.devices[0].consumedOneTimePrekeys.length, 0);
});

test("deadp0et reports low one-time prekey warnings for active devices", async (t) => {
  const { baseUrl } = await startServer(t, {
    LOW_ONE_TIME_PREKEY_THRESHOLD: "2"
  });

  const createRecipient = await requestJson(baseUrl, "/v1/accounts", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "noor",
      passwordVerifier: "demo-verifier",
      device: {
        deviceId: "device-noor-1",
        identityKey: { kty: "EC", crv: "P-256" },
        signedPrekey: { kty: "EC", crv: "P-256" },
        prekeySignature: "sig-1",
        oneTimePrekeys: [{ keyId: "otk-1", key: { kty: "EC", crv: "P-256", x: "one" } }]
      }
    })
  });
  assert.equal(createRecipient.status, 201);

  const bundles = await requestJson(baseUrl, "/v1/users/noor/bundles");
  assert.equal(bundles.status, 200);
  assert.equal(bundles.body.lowOneTimePrekeyThreshold, 2);
  assert.equal(bundles.body.devices[0].availableOneTimePrekeys, 1);
  assert.equal(bundles.body.devices[0].lowOneTimePrekeys, true);
  assert.match(bundles.body.devices[0].prekeyWarning, /low one-time prekeys/i);
  assert.equal(bundles.body.prekeyWarnings.length, 1);
  assert.equal(bundles.body.prekeyWarnings[0].deviceId, "device-noor-1");
  assert.match(bundles.body.prekeyWarnings[0].warning, /threshold 2/i);

  const devices = await requestJson(baseUrl, "/v1/devices", {
    headers: {
      Authorization: `Bearer ${createRecipient.body.session.accessToken}`
    }
  });
  assert.equal(devices.status, 200);
  assert.equal(devices.body.lowOneTimePrekeyThreshold, 2);
  assert.equal(devices.body.devices[0].availableOneTimePrekeys, 1);
  assert.equal(devices.body.devices[0].lowOneTimePrekeys, true);
  assert.equal(devices.body.prekeyWarnings.length, 1);
});

test("deadp0et does not duplicate one-time prekeys under concurrent reservations", async (t) => {
  const { baseUrl } = await startServer(t);

  const createRecipient = await requestJson(baseUrl, "/v1/accounts", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "noor",
      passwordVerifier: "demo-verifier",
      device: {
        deviceId: "device-noor-1",
        identityKey: { kty: "EC", crv: "P-256" },
        signedPrekey: { kty: "EC", crv: "P-256" },
        prekeySignature: "sig-1",
        oneTimePrekeys: [
          { keyId: "otk-a", key: { kty: "EC", crv: "P-256", x: "a" } },
          { keyId: "otk-b", key: { kty: "EC", crv: "P-256", x: "b" } },
          { keyId: "otk-c", key: { kty: "EC", crv: "P-256", x: "c" } }
        ]
      }
    })
  });
  assert.equal(createRecipient.status, 201);

  const responses = await Promise.all(
    Array.from({ length: 5 }, () =>
      requestJson(baseUrl, "/v1/users/noor/prekey-bundle", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({})
      })
    )
  );

  const successful = responses.filter((response) => response.status === 200);
  assert.equal(successful.length, 5);
  const keyIds = successful.map((response) => response.body.oneTimePrekey && response.body.oneTimePrekey.keyId).filter(Boolean);
  assert.equal(new Set(keyIds).size, 3);
  assert.deepEqual(new Set(keyIds), new Set(["otk-a", "otk-b", "otk-c"]));
  const nullCount = successful.filter((response) => response.body.oneTimePrekey === null).length;
  assert.equal(nullCount, 2);
});

test("deadp0et releases expired unused prekey reservations back to availability", async (t) => {
  const { baseUrl } = await startServer(t, {
    PREKEY_RESERVATION_TTL_MS: "1000"
  });

  const createRecipient = await requestJson(baseUrl, "/v1/accounts", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "noor",
      passwordVerifier: "demo-verifier",
      device: {
        deviceId: "device-noor-1",
        identityKey: { kty: "EC", crv: "P-256" },
        signedPrekey: { kty: "EC", crv: "P-256" },
        prekeySignature: "sig-1",
        oneTimePrekeys: [{ keyId: "otk-1", key: { kty: "EC", crv: "P-256", x: "one" } }]
      }
    })
  });
  assert.equal(createRecipient.status, 201);

  const firstReservation = await requestJson(baseUrl, "/v1/users/noor/prekey-bundle", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({})
  });
  assert.equal(firstReservation.status, 200);
  assert.equal(firstReservation.body.oneTimePrekey.keyId, "otk-1");

  await new Promise((resolve) => setTimeout(resolve, 1200));

  const secondReservation = await requestJson(baseUrl, "/v1/users/noor/prekey-bundle", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({})
  });
  assert.equal(secondReservation.status, 200);
  assert.equal(secondReservation.body.oneTimePrekey.keyId, "otk-1");
});

test("deadp0et expires delivered unacked one-time-prekey messages after reservation TTL", async (t) => {
  const { baseUrl, dataDir } = await startServer(t, {
    PREKEY_RESERVATION_TTL_MS: "1000"
  });

  const sender = await requestJson(baseUrl, "/v1/accounts", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "iris",
      passwordVerifier: "demo-verifier",
      device: {
        deviceId: "device-iris-1",
        identityKey: { kty: "EC", crv: "P-256" },
        signedPrekey: { kty: "EC", crv: "P-256" },
        prekeySignature: "sig-iris"
      }
    })
  });
  assert.equal(sender.status, 201);

  const recipient = await requestJson(baseUrl, "/v1/accounts", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "noor",
      passwordVerifier: "demo-verifier",
      device: {
        deviceId: "device-noor-1",
        identityKey: { kty: "EC", crv: "P-256" },
        signedPrekey: { kty: "EC", crv: "P-256" },
        prekeySignature: "sig-noor",
        oneTimePrekeys: [{ keyId: "otk-1", key: { kty: "EC", crv: "P-256", x: "one" } }]
      }
    })
  });
  assert.equal(recipient.status, 201);

  const reserved = await requestJson(baseUrl, "/v1/users/noor/prekey-bundle", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({})
  });
  assert.equal(reserved.status, 200);

  const send = await requestJson(baseUrl, "/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${sender.body.session.accessToken}`
    },
    body: JSON.stringify({
      to: "noor",
      recipientDeviceId: "device-noor-1",
      envelope: {
        protocol: "deadp0et-envelope-v1",
        ephemeralKey: { kty: "EC", crv: "P-256" },
        iv: "demo-iv",
        ciphertext: "demo-ciphertext",
        oneTimePrekeyId: "otk-1",
        prekeyReservationToken: reserved.body.prekeyReservationToken
      }
    })
  });
  assert.equal(send.status, 201);

  const inboxBeforeExpiry = await requestJson(baseUrl, "/v1/messages/inbox", {
    headers: {
      Authorization: `Bearer ${recipient.body.session.accessToken}`
    }
  });
  assert.equal(inboxBeforeExpiry.status, 200);
  assert.equal(inboxBeforeExpiry.body.messages.length, 1);

  await new Promise((resolve) => setTimeout(resolve, 1200));

  const inboxAfterExpiry = await requestJson(baseUrl, "/v1/messages/inbox", {
    headers: {
      Authorization: `Bearer ${recipient.body.session.accessToken}`
    }
  });
  assert.equal(inboxAfterExpiry.status, 200);
  assert.equal(inboxAfterExpiry.body.messages.length, 0);

  const persisted = JSON.parse(fs.readFileSync(path.join(dataDir, "store.json"), "utf8"));
  const message = persisted.messages.find((entry) => entry.messageId === send.body.messageId);
  assert.ok(message);
  assert.match(message.expiredAt, /^\d{4}-\d{2}-\d{2}T/);
});

test("deadp0et enforces prekey reservation tokens for message delivery", async (t) => {
  const { baseUrl, dataDir } = await startServer(t);

  const sender = await requestJson(baseUrl, "/v1/accounts", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "iris",
      passwordVerifier: "demo-verifier",
      device: {
        deviceId: "device-iris-1",
        identityKey: { kty: "EC", crv: "P-256" },
        signedPrekey: { kty: "EC", crv: "P-256" },
        prekeySignature: "sig-iris"
      }
    })
  });
  assert.equal(sender.status, 201);

  const recipient = await requestJson(baseUrl, "/v1/accounts", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "noor",
      passwordVerifier: "demo-verifier",
      device: {
        deviceId: "device-noor-1",
        identityKey: { kty: "EC", crv: "P-256" },
        signedPrekey: { kty: "EC", crv: "P-256" },
        prekeySignature: "sig-noor",
        oneTimePrekeys: [{ keyId: "otk-1", key: { kty: "EC", crv: "P-256", x: "one" } }]
      }
    })
  });
  assert.equal(recipient.status, 201);

  const missingReservation = await requestJson(baseUrl, "/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${sender.body.session.accessToken}`
    },
    body: JSON.stringify({
      to: "noor",
      recipientDeviceId: "device-noor-1",
      envelope: {
        protocol: "deadp0et-envelope-v1",
        ephemeralKey: { kty: "EC", crv: "P-256" },
        iv: "demo-iv",
        ciphertext: "demo-ciphertext"
      }
    })
  });
  assert.equal(missingReservation.status, 400);
  assert.match(missingReservation.body.error.message, /prekeyReservationToken is required/i);

  const reserved = await requestJson(baseUrl, "/v1/users/noor/prekey-bundle", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({})
  });
  assert.equal(reserved.status, 200);
  assert.equal(reserved.body.oneTimePrekey.keyId, "otk-1");

  const invalidPrekeyId = await requestJson(baseUrl, "/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${sender.body.session.accessToken}`
    },
    body: JSON.stringify({
      to: "noor",
      recipientDeviceId: "device-noor-1",
      envelope: {
        protocol: "deadp0et-envelope-v1",
        ephemeralKey: { kty: "EC", crv: "P-256" },
        iv: "demo-iv",
        ciphertext: "demo-ciphertext",
        oneTimePrekeyId: "wrong-key-id",
        prekeyReservationToken: reserved.body.prekeyReservationToken
      }
    })
  });
  assert.equal(invalidPrekeyId.status, 409);
  assert.match(invalidPrekeyId.body.error.message, /does not match reserved prekey/i);

  const firstSend = await requestJson(baseUrl, "/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${sender.body.session.accessToken}`
    },
    body: JSON.stringify({
      to: "noor",
      recipientDeviceId: "device-noor-1",
      envelope: {
        protocol: "deadp0et-envelope-v1",
        ephemeralKey: { kty: "EC", crv: "P-256" },
        iv: "demo-iv",
        ciphertext: "demo-ciphertext",
        oneTimePrekeyId: "otk-1",
        prekeyReservationToken: reserved.body.prekeyReservationToken
      }
    })
  });
  assert.equal(firstSend.status, 201);

  const ackMissingProof = await requestJson(baseUrl, "/v1/messages/inbox/ack", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${recipient.body.session.accessToken}`
    },
    body: JSON.stringify({
      messageIds: [firstSend.body.messageId]
    })
  });
  assert.equal(ackMissingProof.status, 400);
  assert.match(ackMissingProof.body.error.message, /oneTimePrekeyProof is required/i);

  const ackWithProof = await requestJson(baseUrl, "/v1/messages/inbox/ack", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${recipient.body.session.accessToken}`
    },
    body: JSON.stringify({
      messageIds: [firstSend.body.messageId],
      oneTimePrekeyProofs: [
        {
          messageId: firstSend.body.messageId,
          oneTimePrekeyId: "otk-1"
        }
      ]
    })
  });
  assert.equal(ackWithProof.status, 200);
  assert.equal(ackWithProof.body.acknowledged, 1);
  const storeAfterAck = JSON.parse(fs.readFileSync(path.join(dataDir, "store.json"), "utf8"));
  const recipientAccount = storeAfterAck.accounts.find((account) => account.username === "noor");
  assert.ok(recipientAccount);
  assert.equal(recipientAccount.devices[0].reservedOneTimePrekeys.length, 0);
  assert.equal(recipientAccount.devices[0].consumedOneTimePrekeys.length, 1);
  assert.equal(recipientAccount.devices[0].consumedOneTimePrekeys[0].prekey.keyId, "otk-1");

  const replaySend = await requestJson(baseUrl, "/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${sender.body.session.accessToken}`
    },
    body: JSON.stringify({
      to: "noor",
      recipientDeviceId: "device-noor-1",
      envelope: {
        protocol: "deadp0et-envelope-v1",
        ephemeralKey: { kty: "EC", crv: "P-256" },
        iv: "demo-iv-2",
        ciphertext: "demo-ciphertext-2",
        oneTimePrekeyId: "otk-1",
        prekeyReservationToken: reserved.body.prekeyReservationToken
      }
    })
  });
  assert.equal(replaySend.status, 409);
  assert.match(replaySend.body.error.message, /invalid, expired, or already consumed|already consumed/i);
});

test("deadp0et migrates legacy passwordVerifier records on successful login", async (t) => {
  const legacyStore = {
    accounts: [
      {
        accountId: "legacy-account-1",
        username: "legacy",
        passwordVerifier: "legacy-verifier",
        createdAt: "2026-01-01T00:00:00.000Z",
        profile: {
          joinedAt: "2026-01-01T00:00:00.000Z"
        },
        devices: [
          {
            deviceId: "legacy-device-1",
            identityKey: { kty: "EC", crv: "P-256" },
            signedPrekey: { kty: "EC", crv: "P-256" },
            prekeySignature: "legacy-sig",
            oneTimePrekeys: [],
            registeredAt: "2026-01-01T00:00:00.000Z",
            revokedAt: null
          }
        ]
      }
    ],
    sessions: [],
    messages: []
  };

  const { baseUrl, dataDir } = await startServer(t, {}, legacyStore);
  const storeFile = path.join(dataDir, "store.json");

  const login = await requestJson(baseUrl, "/v1/sessions", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "legacy",
      passwordVerifier: "legacy-verifier",
      deviceId: "legacy-device-1"
    })
  });

  assert.equal(login.status, 200);
  assert.equal(login.body.username, "legacy");

  const migratedStore = JSON.parse(fs.readFileSync(storeFile, "utf8"));
  assert.equal(migratedStore.accounts[0].passwordVerifier, undefined);
  assert.equal(typeof migratedStore.accounts[0].verifier.digest, "string");
  assert.equal(migratedStore.accounts[0].verifier.algorithm, "scrypt");
});

test("deadp0et rejects malformed verifier records without crashing", async (t) => {
  const malformedStore = {
    accounts: [
      {
        accountId: "malformed-account-1",
        username: "malformed",
        verifier: {
          salt: "salt-1",
          digest: "abc",
          algorithm: "scrypt"
        },
        createdAt: "2026-01-01T00:00:00.000Z",
        profile: {
          joinedAt: "2026-01-01T00:00:00.000Z"
        },
        devices: [
          {
            deviceId: "malformed-device-1",
            identityKey: { kty: "EC", crv: "P-256" },
            signedPrekey: { kty: "EC", crv: "P-256" },
            prekeySignature: "malformed-sig",
            oneTimePrekeys: [],
            registeredAt: "2026-01-01T00:00:00.000Z",
            revokedAt: null
          }
        ]
      }
    ],
    sessions: [],
    messages: []
  };

  const { baseUrl } = await startServer(t, {}, malformedStore);

  const login = await requestJson(baseUrl, "/v1/sessions", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "malformed",
      passwordVerifier: "demo-verifier",
      deviceId: "malformed-device-1"
    })
  });

  assert.equal(login.status, 401);
  assert.match(login.body.error.message, /invalid credentials/i);
});

test("deadp0et invalidates sessions tied to revoked devices", async (t) => {
  const staleSessionStore = {
    accounts: [
      {
        accountId: "account-1",
        username: "iris",
        verifier: {
          salt: "abcd",
          digest: "beef",
          algorithm: "scrypt"
        },
        createdAt: "2026-01-01T00:00:00.000Z",
        profile: {
          joinedAt: "2026-01-01T00:00:00.000Z"
        },
        devices: [
          {
            deviceId: "device-iris-1",
            identityKey: { kty: "EC", crv: "P-256" },
            signedPrekey: { kty: "EC", crv: "P-256" },
            prekeySignature: "sig-1",
            oneTimePrekeys: [],
            registeredAt: "2026-01-01T00:00:00.000Z",
            revokedAt: "2026-01-02T00:00:00.000Z"
          }
        ]
      }
    ],
    sessions: [
      {
        sessionId: "session-1",
        accessToken: "stale-token",
        accountId: "account-1",
        deviceId: "device-iris-1",
        createdAt: "2026-01-01T00:00:00.000Z",
        expiresAt: "2099-01-01T00:00:00.000Z",
        revokedAt: null
      }
    ],
    messages: []
  };

  const { baseUrl, dataDir } = await startServer(t, {}, staleSessionStore);
  const storeFile = path.join(dataDir, "store.json");

  const inbox = await requestJson(baseUrl, "/v1/messages/inbox", {
    headers: {
      Authorization: "Bearer stale-token"
    }
  });

  assert.equal(inbox.status, 401);
  assert.match(inbox.body.error.message, /device is no longer active/i);

  const persisted = JSON.parse(fs.readFileSync(storeFile, "utf8"));
  assert.match(persisted.sessions[0].revokedAt, /^\d{4}-\d{2}-\d{2}T/);
});

test("deadp0et enforces active session caps by revoking oldest sessions", async (t) => {
  const { baseUrl, dataDir } = await startServer(t, {
    MAX_ACTIVE_SESSIONS_PER_ACCOUNT: "2",
    MAX_ACTIVE_SESSIONS_PER_DEVICE: "2"
  });

  const create = await requestJson(baseUrl, "/v1/accounts", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "iris",
      passwordVerifier: "demo-verifier",
      device: {
        deviceId: "device-iris-1",
        identityKey: { kty: "EC", crv: "P-256" },
        signedPrekey: { kty: "EC", crv: "P-256" },
        prekeySignature: "sig-1"
      }
    })
  });

  assert.equal(create.status, 201);
  const firstToken = create.body.session.accessToken;

  const secondLogin = await requestJson(baseUrl, "/v1/sessions", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "iris",
      passwordVerifier: "demo-verifier",
      deviceId: "device-iris-1"
    })
  });
  assert.equal(secondLogin.status, 200);

  const thirdLogin = await requestJson(baseUrl, "/v1/sessions", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "iris",
      passwordVerifier: "demo-verifier",
      deviceId: "device-iris-1"
    })
  });
  assert.equal(thirdLogin.status, 200);

  const firstTokenUse = await requestJson(baseUrl, "/v1/messages/inbox", {
    headers: {
      Authorization: `Bearer ${firstToken}`
    }
  });
  assert.equal(firstTokenUse.status, 401);

  const storeFile = path.join(dataDir, "store.json");
  const persisted = JSON.parse(fs.readFileSync(storeFile, "utf8"));
  const activeSessions = persisted.sessions.filter((session) => !session.revokedAt);
  assert.equal(activeSessions.length, 2);
});

test("deadp0et lists and revokes account sessions", async (t) => {
  const { baseUrl } = await startServer(t);

  const create = await requestJson(baseUrl, "/v1/accounts", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "iris",
      passwordVerifier: "demo-verifier",
      device: {
        deviceId: "device-iris-1",
        identityKey: { kty: "EC", crv: "P-256" },
        signedPrekey: { kty: "EC", crv: "P-256" },
        prekeySignature: "sig-1"
      }
    })
  });

  assert.equal(create.status, 201);

  const secondLogin = await requestJson(baseUrl, "/v1/sessions", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "iris",
      passwordVerifier: "demo-verifier",
      deviceId: "device-iris-1"
    })
  });

  assert.equal(secondLogin.status, 200);

  const listed = await requestJson(baseUrl, "/v1/sessions", {
    headers: {
      Authorization: `Bearer ${secondLogin.body.session.accessToken}`
    }
  });

  assert.equal(listed.status, 200);
  assert.equal(listed.body.username, "iris");
  assert.equal(listed.body.sessions.length, 2);
  assert.equal(listed.body.sessions.filter((session) => session.current).length, 1);
  assert.equal(listed.body.currentSessionId, listed.body.sessions.find((session) => session.current).sessionId);

  const originalSession = listed.body.sessions.find((session) => session.sessionId !== listed.body.currentSessionId);
  assert.ok(originalSession);

  const revokeOriginal = await requestJson(baseUrl, `/v1/sessions/${originalSession.sessionId}`, {
    method: "DELETE",
    headers: {
      Authorization: `Bearer ${secondLogin.body.session.accessToken}`
    }
  });

  assert.equal(revokeOriginal.status, 200);
  assert.equal(revokeOriginal.body.revoked, 1);
  assert.equal(revokeOriginal.body.sessionId, originalSession.sessionId);

  const revokedUse = await requestJson(baseUrl, "/v1/messages/inbox", {
    headers: {
      Authorization: `Bearer ${create.body.session.accessToken}`
    }
  });

  assert.equal(revokedUse.status, 401);

  const logoutCurrent = await requestJson(baseUrl, "/v1/sessions/current", {
    method: "DELETE",
    headers: {
      Authorization: `Bearer ${secondLogin.body.session.accessToken}`
    }
  });

  assert.equal(logoutCurrent.status, 200);
  assert.equal(logoutCurrent.body.revoked, 1);
  assert.equal(typeof logoutCurrent.body.sessionId, "string");

  const afterLogout = await requestJson(baseUrl, "/v1/sessions", {
    headers: {
      Authorization: `Bearer ${secondLogin.body.session.accessToken}`
    }
  });

  assert.equal(afterLogout.status, 401);
});

test("deadp0et does not let accounts revoke another account's sessions", async (t) => {
  const { baseUrl } = await startServer(t);

  const iris = await requestJson(baseUrl, "/v1/accounts", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "iris",
      passwordVerifier: "demo-verifier",
      device: {
        deviceId: "device-iris-1",
        identityKey: { kty: "EC", crv: "P-256" },
        signedPrekey: { kty: "EC", crv: "P-256" },
        prekeySignature: "sig-1"
      }
    })
  });

  const noor = await requestJson(baseUrl, "/v1/accounts", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "noor",
      passwordVerifier: "demo-verifier",
      device: {
        deviceId: "device-noor-1",
        identityKey: { kty: "EC", crv: "P-256" },
        signedPrekey: { kty: "EC", crv: "P-256" },
        prekeySignature: "sig-2"
      }
    })
  });

  assert.equal(iris.status, 201);
  assert.equal(noor.status, 201);

  const noorSessions = await requestJson(baseUrl, "/v1/sessions", {
    headers: {
      Authorization: `Bearer ${noor.body.session.accessToken}`
    }
  });

  assert.equal(noorSessions.status, 200);
  assert.equal(noorSessions.body.sessions.length, 1);

  const revokeByOtherAccount = await requestJson(baseUrl, `/v1/sessions/${noorSessions.body.sessions[0].sessionId}`, {
    method: "DELETE",
    headers: {
      Authorization: `Bearer ${iris.body.session.accessToken}`
    }
  });

  assert.equal(revokeByOtherAccount.status, 404);
});

test("deadp0et paginates inbox reads with cursors", async (t) => {
  const { baseUrl } = await startServer(t);

  const iris = await requestJson(baseUrl, "/v1/accounts", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "iris",
      passwordVerifier: "demo-verifier",
      device: {
        deviceId: "device-iris-1",
        identityKey: { kty: "EC", crv: "P-256" },
        signedPrekey: { kty: "EC", crv: "P-256" },
        prekeySignature: "sig-1"
      }
    })
  });

  const noor = await requestJson(baseUrl, "/v1/accounts", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "noor",
      passwordVerifier: "demo-verifier",
      device: {
        deviceId: "device-noor-1",
        identityKey: { kty: "EC", crv: "P-256" },
        signedPrekey: { kty: "EC", crv: "P-256" },
        prekeySignature: "sig-2"
      }
    })
  });

  assert.equal(iris.status, 201);
  assert.equal(noor.status, 201);

  for (const suffix of ["one", "two", "three"]) {
    const bundle = await requestJson(baseUrl, "/v1/users/noor/prekey-bundle", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({})
    });
    assert.equal(bundle.status, 200);

    const delivered = await requestJson(baseUrl, "/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${iris.body.session.accessToken}`
      },
      body: JSON.stringify({
        to: "noor",
        recipientDeviceId: "device-noor-1",
        envelope: {
          protocol: "deadp0et-envelope-v1",
          ephemeralKey: { kty: "EC", crv: "P-256", x: suffix },
          iv: `demo-iv-${suffix}`,
          ciphertext: `demo-ciphertext-${suffix}`,
          prekeyReservationToken: bundle.body.prekeyReservationToken
        }
      })
    });

    assert.equal(delivered.status, 201);
  }

  const firstPage = await requestJson(baseUrl, "/v1/messages/inbox?limit=2", {
    headers: {
      Authorization: `Bearer ${noor.body.session.accessToken}`
    }
  });

  assert.equal(firstPage.status, 200);
  assert.equal(firstPage.body.messages.length, 2);
  assert.equal(typeof firstPage.body.nextCursor, "string");
  assert.equal(firstPage.body.messages[0].deliveryCount, 1);
  assert.equal(firstPage.body.messages[1].deliveryCount, 1);

  const secondPage = await requestJson(baseUrl, `/v1/messages/inbox?limit=2&cursor=${encodeURIComponent(firstPage.body.nextCursor)}`, {
    headers: {
      Authorization: `Bearer ${noor.body.session.accessToken}`
    }
  });

  assert.equal(secondPage.status, 200);
  assert.equal(secondPage.body.messages.length, 1);
  assert.equal(secondPage.body.nextCursor, null);
  assert.equal(secondPage.body.messages[0].deliveryCount, 1);

  const invalidCursor = await requestJson(baseUrl, "/v1/messages/inbox?cursor=not-valid", {
    headers: {
      Authorization: `Bearer ${noor.body.session.accessToken}`
    }
  });

  assert.equal(invalidCursor.status, 400);
});

test("deadp0et exposes non-mutating paged message history", async (t) => {
  const { baseUrl } = await startServer(t);

  const iris = await requestJson(baseUrl, "/v1/accounts", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "iris",
      passwordVerifier: "demo-verifier",
      device: {
        deviceId: "device-iris-1",
        identityKey: { kty: "EC", crv: "P-256" },
        signedPrekey: { kty: "EC", crv: "P-256" },
        prekeySignature: "sig-1"
      }
    })
  });

  const noor = await requestJson(baseUrl, "/v1/accounts", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "noor",
      passwordVerifier: "demo-verifier",
      device: {
        deviceId: "device-noor-1",
        identityKey: { kty: "EC", crv: "P-256" },
        signedPrekey: { kty: "EC", crv: "P-256" },
        prekeySignature: "sig-2"
      }
    })
  });

  assert.equal(iris.status, 201);
  assert.equal(noor.status, 201);

  const toNoorBundle = await requestJson(baseUrl, "/v1/users/noor/prekey-bundle", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({})
  });
  assert.equal(toNoorBundle.status, 200);

  const irisToNoor = await requestJson(baseUrl, "/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${iris.body.session.accessToken}`
    },
    body: JSON.stringify({
      to: "noor",
      recipientDeviceId: "device-noor-1",
      envelope: {
        protocol: "deadp0et-envelope-v1",
        ephemeralKey: { kty: "EC", crv: "P-256", x: "history-one" },
        iv: "iv-history-one",
        ciphertext: "cipher-history-one",
        prekeyReservationToken: toNoorBundle.body.prekeyReservationToken
      }
    })
  });
  assert.equal(irisToNoor.status, 201);

  const toIrisBundle = await requestJson(baseUrl, "/v1/users/iris/prekey-bundle", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({})
  });
  assert.equal(toIrisBundle.status, 200);

  const noorToIris = await requestJson(baseUrl, "/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${noor.body.session.accessToken}`
    },
    body: JSON.stringify({
      to: "iris",
      recipientDeviceId: "device-iris-1",
      envelope: {
        protocol: "deadp0et-envelope-v1",
        ephemeralKey: { kty: "EC", crv: "P-256", x: "history-two" },
        iv: "iv-history-two",
        ciphertext: "cipher-history-two",
        prekeyReservationToken: toIrisBundle.body.prekeyReservationToken
      }
    })
  });
  assert.equal(noorToIris.status, 201);

  const historyPage = await requestJson(baseUrl, "/v1/messages/history?correspondent=noor&limit=1", {
    headers: {
      Authorization: `Bearer ${iris.body.session.accessToken}`
    }
  });

  assert.equal(historyPage.status, 200);
  assert.equal(historyPage.body.messages.length, 1);
  assert.equal(historyPage.body.correspondent, "noor");
  assert.equal(typeof historyPage.body.nextCursor, "string");
  assert.equal(historyPage.body.messages[0].deliveryCount, 0);
  assert.equal(historyPage.body.messages[0].deliveredAt, null);

  const historyOlderPage = await requestJson(baseUrl, `/v1/messages/history?correspondent=noor&limit=1&before=${encodeURIComponent(historyPage.body.nextCursor)}`, {
    headers: {
      Authorization: `Bearer ${iris.body.session.accessToken}`
    }
  });

  assert.equal(historyOlderPage.status, 200);
  assert.equal(historyOlderPage.body.messages.length, 1);
  assert.equal(historyOlderPage.body.nextCursor, null);

  const invalidHistoryCursor = await requestJson(baseUrl, "/v1/messages/history?before=nope", {
    headers: {
      Authorization: `Bearer ${iris.body.session.accessToken}`
    }
  });

  assert.equal(invalidHistoryCursor.status, 400);
});

test("deadp0et exposes paged conversation summaries", async (t) => {
  const { baseUrl } = await startServer(t);

  const iris = await requestJson(baseUrl, "/v1/accounts", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "iris",
      passwordVerifier: "demo-verifier",
      device: {
        deviceId: "device-iris-1",
        identityKey: { kty: "EC", crv: "P-256" },
        signedPrekey: { kty: "EC", crv: "P-256" },
        prekeySignature: "sig-1"
      }
    })
  });

  const noor = await requestJson(baseUrl, "/v1/accounts", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "noor",
      passwordVerifier: "demo-verifier",
      device: {
        deviceId: "device-noor-1",
        identityKey: { kty: "EC", crv: "P-256" },
        signedPrekey: { kty: "EC", crv: "P-256" },
        prekeySignature: "sig-2"
      }
    })
  });

  const rune = await requestJson(baseUrl, "/v1/accounts", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "rune",
      passwordVerifier: "demo-verifier",
      device: {
        deviceId: "device-rune-1",
        identityKey: { kty: "EC", crv: "P-256" },
        signedPrekey: { kty: "EC", crv: "P-256" },
        prekeySignature: "sig-3"
      }
    })
  });

  assert.equal(iris.status, 201);
  assert.equal(noor.status, 201);
  assert.equal(rune.status, 201);

  const bundleToIrisFromNoor = await requestJson(baseUrl, "/v1/users/iris/prekey-bundle", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({})
  });
  const bundleToIrisFromRune = await requestJson(baseUrl, "/v1/users/iris/prekey-bundle", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({})
  });
  const bundleToNoorFromIris = await requestJson(baseUrl, "/v1/users/noor/prekey-bundle", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({})
  });

  assert.equal(bundleToIrisFromNoor.status, 200);
  assert.equal(bundleToIrisFromRune.status, 200);
  assert.equal(bundleToNoorFromIris.status, 200);

  const noorToIris = await requestJson(baseUrl, "/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${noor.body.session.accessToken}`
    },
    body: JSON.stringify({
      to: "iris",
      recipientDeviceId: "device-iris-1",
      envelope: {
        protocol: "deadp0et-envelope-v1",
        ephemeralKey: { kty: "EC", crv: "P-256", x: "conv-one" },
        iv: "iv-conv-one",
        ciphertext: "cipher-conv-one",
        prekeyReservationToken: bundleToIrisFromNoor.body.prekeyReservationToken
      }
    })
  });

  const runeToIris = await requestJson(baseUrl, "/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${rune.body.session.accessToken}`
    },
    body: JSON.stringify({
      to: "iris",
      recipientDeviceId: "device-iris-1",
      envelope: {
        protocol: "deadp0et-envelope-v1",
        ephemeralKey: { kty: "EC", crv: "P-256", x: "conv-two" },
        iv: "iv-conv-two",
        ciphertext: "cipher-conv-two",
        prekeyReservationToken: bundleToIrisFromRune.body.prekeyReservationToken
      }
    })
  });

  const irisToNoor = await requestJson(baseUrl, "/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${iris.body.session.accessToken}`
    },
    body: JSON.stringify({
      to: "noor",
      recipientDeviceId: "device-noor-1",
      envelope: {
        protocol: "deadp0et-envelope-v1",
        ephemeralKey: { kty: "EC", crv: "P-256", x: "conv-three" },
        iv: "iv-conv-three",
        ciphertext: "cipher-conv-three",
        prekeyReservationToken: bundleToNoorFromIris.body.prekeyReservationToken
      }
    })
  });

  assert.equal(noorToIris.status, 201);
  assert.equal(runeToIris.status, 201);
  assert.equal(irisToNoor.status, 201);

  const summariesFirstPage = await requestJson(baseUrl, "/v1/messages/conversations?limit=1", {
    headers: {
      Authorization: `Bearer ${iris.body.session.accessToken}`
    }
  });

  assert.equal(summariesFirstPage.status, 200);
  assert.equal(summariesFirstPage.body.conversations.length, 1);
  assert.equal(typeof summariesFirstPage.body.nextCursor, "string");
  assert.equal(summariesFirstPage.body.conversations[0].correspondent, "noor");
  assert.equal(summariesFirstPage.body.conversations[0].messageCount, 2);
  assert.equal(summariesFirstPage.body.conversations[0].unreadCount, 1);
  assert.equal(summariesFirstPage.body.conversations[0].latestMessage.from, "iris");

  const summariesSecondPage = await requestJson(baseUrl, `/v1/messages/conversations?limit=1&before=${encodeURIComponent(summariesFirstPage.body.nextCursor)}`, {
    headers: {
      Authorization: `Bearer ${iris.body.session.accessToken}`
    }
  });

  assert.equal(summariesSecondPage.status, 200);
  assert.equal(summariesSecondPage.body.conversations.length, 1);
  assert.equal(summariesSecondPage.body.conversations[0].correspondent, "rune");
  assert.equal(summariesSecondPage.body.conversations[0].unreadCount, 1);
  assert.equal(summariesSecondPage.body.nextCursor, null);

  const invalidConversationCursor = await requestJson(baseUrl, "/v1/messages/conversations?before=bad-cursor", {
    headers: {
      Authorization: `Bearer ${iris.body.session.accessToken}`
    }
  });

  assert.equal(invalidConversationCursor.status, 400);
});

test("deadp0et throttles repeated login failures and recovers after block window", async (t) => {
  const { baseUrl } = await startServer(t, {
    AUTH_WINDOW_MS: "60000",
    AUTH_MAX_ATTEMPTS_PER_KEY: "2",
    AUTH_BLOCK_MS: "120"
  });

  const create = await requestJson(baseUrl, "/v1/accounts", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "iris",
      passwordVerifier: "demo-verifier",
      device: {
        deviceId: "device-iris-1",
        identityKey: { kty: "EC", crv: "P-256" },
        signedPrekey: { kty: "EC", crv: "P-256" },
        prekeySignature: "sig-1"
      }
    })
  });
  assert.equal(create.status, 201);

  const badLoginOne = await fetch(`${baseUrl}/v1/sessions`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "iris",
      passwordVerifier: "bad-verifier",
      deviceId: "device-iris-1"
    })
  });
  assert.equal(badLoginOne.status, 401);

  const badLoginTwo = await fetch(`${baseUrl}/v1/sessions`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "iris",
      passwordVerifier: "still-bad",
      deviceId: "device-iris-1"
    })
  });
  assert.equal(badLoginTwo.status, 401);

  const blockedLogin = await fetch(`${baseUrl}/v1/sessions`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "iris",
      passwordVerifier: "demo-verifier",
      deviceId: "device-iris-1"
    })
  });
  const blockedBody = JSON.parse(await blockedLogin.text());
  assert.equal(blockedLogin.status, 429);
  assert.match(blockedBody.error.message, /too many login attempts/i);
  assert.ok(blockedLogin.headers.get("retry-after"));

  await new Promise((resolve) => setTimeout(resolve, 1150));

  const recoveredLogin = await requestJson(baseUrl, "/v1/sessions", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "iris",
      passwordVerifier: "demo-verifier",
      deviceId: "device-iris-1"
    })
  });
  assert.equal(recoveredLogin.status, 200);
});
