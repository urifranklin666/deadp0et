const server = {
  users: new Map(),
  messages: []
};

const state = {
  currentUser: null,
  currentUsername: "",
  lastEnvelope: ""
};

const signupUsername = document.querySelector("#signup-username");
const signupPassword = document.querySelector("#signup-password");
const sessionOutput = document.querySelector("#session-output");
const directoryOutput = document.querySelector("#directory-output");
const recipientUsername = document.querySelector("#recipient-username");
const messageSubject = document.querySelector("#message-subject");
const messageBody = document.querySelector("#message-body");
const envelopeOutput = document.querySelector("#envelope-output");
const inboxOutput = document.querySelector("#inbox-output");
const plaintextOutput = document.querySelector("#plaintext-output");
const signupButton = document.querySelector("#signup-button");
const loginButton = document.querySelector("#login-button");
const bootstrapButton = document.querySelector("#bootstrap-button");
const sendButton = document.querySelector("#send-button");
const copyEnvelopeButton = document.querySelector("#copy-envelope-button");
const refreshInboxButton = document.querySelector("#refresh-inbox-button");
const decryptSelectedButton = document.querySelector("#decrypt-selected-button");
const statusNode = document.querySelector("#status");

function setStatus(message, type = "info") {
  statusNode.textContent = message;
  statusNode.style.color = type === "error" ? "var(--danger)" : "var(--accent)";
}

function bytesToBase64(bytes) {
  let binary = "";
  bytes.forEach((value) => {
    binary += String.fromCharCode(value);
  });
  return btoa(binary);
}

function base64ToBytes(base64) {
  const binary = atob(base64);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function normalizeUsername(username) {
  return username.trim().toLowerCase();
}

async function sha256(text) {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return bytesToBase64(new Uint8Array(digest));
}

async function deriveAesKey(sharedSecret) {
  const secretBytes = base64ToBytes(sharedSecret);
  const digest = await crypto.subtle.digest("SHA-256", secretBytes);
  return crypto.subtle.importKey(
    "raw",
    digest,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function generateDeviceBundle() {
  const identity = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
  const signedPrekey = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
  const identityPublic = await crypto.subtle.exportKey("jwk", identity.publicKey);
  const prekeyPublic = await crypto.subtle.exportKey("jwk", signedPrekey.publicKey);
  const prekeySignature = await sha256(JSON.stringify(identityPublic) + JSON.stringify(prekeyPublic));

  return {
    privateKeys: {
      identityPrivateKey: identity.privateKey,
      signedPrekeyPrivateKey: signedPrekey.privateKey
    },
    publicBundle: {
      identityKey: identityPublic,
      signedPrekey: prekeyPublic,
      prekeySignature,
      deviceId: crypto.randomUUID()
    }
  };
}

async function deriveSharedSecret(privateKey, remotePublicJwk) {
  const remotePublicKey = await crypto.subtle.importKey(
    "jwk",
    remotePublicJwk,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: remotePublicKey },
    privateKey,
    256
  );
  return bytesToBase64(new Uint8Array(bits));
}

function renderDirectory() {
  const users = [...server.users.values()].map((user) => ({
    username: user.username,
    profile: {
      joinedAt: user.joinedAt,
      deviceId: user.deviceBundle.deviceId
    },
    publicBundle: user.publicBundle
  }));

  directoryOutput.value = users.length
    ? JSON.stringify(users, null, 2)
    : "No registered users yet.";
}

function renderSession() {
  if (!state.currentUser) {
    sessionOutput.value = "No active session.";
    return;
  }

  sessionOutput.value = JSON.stringify({
    username: state.currentUser.username,
    auth: {
      tokenType: "demo-session",
      note: "Production should use an HttpOnly session cookie or short-lived access token."
    },
    device: state.currentUser.publicBundle,
    protocol: {
      identityCurve: "P-256 ECDH",
      contentCipher: "AES-GCM-256",
      serverVisibility: "metadata + ciphertext envelope only"
    }
  }, null, 2);
}

function renderInbox() {
  if (!state.currentUser) {
    inboxOutput.value = "Sign in to fetch encrypted messages.";
    return [];
  }

  const inbox = server.messages.filter((message) => message.to === state.currentUser.username);
  inboxOutput.value = inbox.length
    ? JSON.stringify(inbox, null, 2)
    : "No encrypted envelopes for this account yet.";
  return inbox;
}

async function createAccount() {
  const username = normalizeUsername(signupUsername.value);
  const password = signupPassword.value;

  if (!username || !password) {
    setStatus("Enter a username and password to create an account.", "error");
    return;
  }

  if (server.users.has(username)) {
    setStatus("That username already exists in the directory.", "error");
    return;
  }

  signupButton.disabled = true;
  setStatus("Generating local device keys and registering the account...");

  try {
    const deviceBundle = await generateDeviceBundle();
    const passwordHash = await sha256(password);
    const user = {
      username,
      joinedAt: new Date().toISOString(),
      passwordHash,
      privateKeys: deviceBundle.privateKeys,
      publicBundle: deviceBundle.publicBundle,
      deviceBundle: deviceBundle.publicBundle
    };

    server.users.set(username, user);
    state.currentUser = user;
    state.currentUsername = username;
    renderDirectory();
    renderSession();
    renderInbox();
    setStatus(`Account ${username} created. Public keys published, private keys kept local.`);
  } catch (error) {
    setStatus(error.message, "error");
  } finally {
    signupButton.disabled = false;
  }
}

async function signIn() {
  const username = normalizeUsername(signupUsername.value);
  const password = signupPassword.value;
  const user = server.users.get(username);

  if (!user) {
    setStatus("No such account exists in the local server model.", "error");
    return;
  }

  const passwordHash = await sha256(password);
  if (passwordHash !== user.passwordHash) {
    setStatus("Password did not match the stored account hash.", "error");
    return;
  }

  state.currentUser = user;
  state.currentUsername = username;
  renderSession();
  renderInbox();
  setStatus(`Signed in as ${username}.`);
}

async function encryptForRecipient(sender, recipient, subject, body) {
  const ephemeral = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
  const ephemeralPublic = await crypto.subtle.exportKey("jwk", ephemeral.publicKey);
  const sharedSecret = await deriveSharedSecret(ephemeral.privateKey, recipient.publicBundle.signedPrekey);
  const aesKey = await deriveAesKey(sharedSecret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const payload = {
    subject,
    body,
    sentAt: new Date().toISOString(),
    senderDeviceId: sender.publicBundle.deviceId
  };
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, plaintext);

  return {
    protocol: "deadp0et-envelope-v1",
    from: sender.username,
    to: recipient.username,
    envelopeId: crypto.randomUUID(),
    ephemeralKey: ephemeralPublic,
    recipientDeviceId: recipient.publicBundle.deviceId,
    recipientIdentityKey: recipient.publicBundle.identityKey,
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext))
  };
}

async function sendMessage() {
  if (!state.currentUser) {
    setStatus("Create or sign in to an account before sending messages.", "error");
    return;
  }

  const to = normalizeUsername(recipientUsername.value);
  const subject = messageSubject.value.trim();
  const body = messageBody.value.trim();
  const recipient = server.users.get(to);

  if (!to || !subject || !body) {
    setStatus("Recipient, subject, and message body are all required.", "error");
    return;
  }

  if (!recipient) {
    setStatus("Recipient was not found in the directory.", "error");
    return;
  }

  if (recipient.username === state.currentUser.username) {
    setStatus("Send to a different account so we exercise the full recipient flow.", "error");
    return;
  }

  sendButton.disabled = true;
  setStatus("Fetching recipient prekey bundle and sealing the message...");

  try {
    const envelope = await encryptForRecipient(state.currentUser, recipient, subject, body);
    server.messages.push(envelope);
    state.lastEnvelope = JSON.stringify(envelope, null, 2);
    envelopeOutput.value = state.lastEnvelope;
    copyEnvelopeButton.disabled = false;
    renderInbox();
    setStatus(`Encrypted envelope stored for ${recipient.username}. Server only sees metadata and ciphertext.`);
  } catch (error) {
    setStatus(error.message, "error");
  } finally {
    sendButton.disabled = false;
  }
}

async function decryptLatest() {
  if (!state.currentUser) {
    setStatus("Sign in before trying to decrypt inbox messages.", "error");
    return;
  }

  const inbox = renderInbox();
  const latest = inbox[inbox.length - 1];

  if (!latest) {
    setStatus("No messages are waiting for this account.", "error");
    return;
  }

  try {
    const sharedSecret = await deriveSharedSecret(
      state.currentUser.privateKeys.signedPrekeyPrivateKey,
      latest.ephemeralKey
    );
    const aesKey = await deriveAesKey(sharedSecret);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64ToBytes(latest.iv) },
      aesKey,
      base64ToBytes(latest.ciphertext)
    );
    const decoded = JSON.parse(new TextDecoder().decode(plaintext));
    plaintextOutput.value = JSON.stringify(decoded, null, 2);
    setStatus(`Latest message from ${latest.from} decrypted locally.`);
  } catch (error) {
    plaintextOutput.value = "";
    setStatus("Unable to decrypt the latest envelope.", "error");
  }
}

async function copyLastEnvelope() {
  if (!state.lastEnvelope) {
    return;
  }

  try {
    await navigator.clipboard.writeText(state.lastEnvelope);
    setStatus("Last encrypted envelope copied to the clipboard.");
  } catch (error) {
    setStatus("Clipboard access was blocked. Copy the envelope manually.", "error");
  }
}

async function bootstrapDemoUsers() {
  if (server.users.size > 0) {
    setStatus("Demo users are already loaded. Sign in as iris or noor with password lantern.", "error");
    return;
  }

  signupUsername.value = "iris";
  signupPassword.value = "lantern";
  await createAccount();

  signupUsername.value = "noor";
  signupPassword.value = "lantern";
  await createAccount();

  signupUsername.value = "iris";
  signupPassword.value = "lantern";
  await signIn();

  recipientUsername.value = "noor";
  messageSubject.value = "First secure hello";
  messageBody.value = "This models what our server-assisted encrypted delivery can look like.";
  setStatus("Demo users loaded. Signed in as iris; send a message to noor or sign in as noor to decrypt one.");
}

signupButton.addEventListener("click", () => {
  createAccount().catch((error) => setStatus(error.message, "error"));
});

loginButton.addEventListener("click", () => {
  signIn().catch((error) => setStatus(error.message, "error"));
});

bootstrapButton.addEventListener("click", () => {
  bootstrapDemoUsers().catch((error) => setStatus(error.message, "error"));
});

sendButton.addEventListener("click", () => {
  sendMessage().catch((error) => setStatus(error.message, "error"));
});

copyEnvelopeButton.addEventListener("click", () => {
  copyLastEnvelope().catch((error) => setStatus(error.message, "error"));
});

refreshInboxButton.addEventListener("click", () => {
  renderInbox();
  setStatus(state.currentUser ? `Fetched inbox for ${state.currentUser.username}.` : "Sign in to fetch an inbox.", state.currentUser ? "info" : "error");
});

decryptSelectedButton.addEventListener("click", () => {
  decryptLatest().catch((error) => setStatus(error.message, "error"));
});

renderDirectory();
renderSession();
renderInbox();
