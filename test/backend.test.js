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
  assert.equal(bundles.body.devices.length, 1);
  assert.equal(bundles.body.devices[0].deviceId, "device-noor-1");

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
        ciphertext: "demo-ciphertext"
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
  assert.equal(listedDevices.body.devices.length, 2);

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
