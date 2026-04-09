const PBKDF2_ITERATIONS = 250000;
const SALT_BYTES = 16;
const IV_BYTES = 12;

const composePassphrase = document.querySelector("#compose-passphrase");
const composeMessage = document.querySelector("#compose-message");
const encryptedOutput = document.querySelector("#encrypted-output");
const decryptPassphrase = document.querySelector("#decrypt-passphrase");
const encryptedInput = document.querySelector("#encrypted-input");
const decryptedOutput = document.querySelector("#decrypted-output");
const encryptButton = document.querySelector("#encrypt-button");
const decryptButton = document.querySelector("#decrypt-button");
const copyButton = document.querySelector("#copy-button");
const sampleButton = document.querySelector("#sample-button");
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

async function deriveKey(passphrase, salt) {
  const encoder = new TextEncoder();
  const passphraseKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(passphrase),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256"
    },
    passphraseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptMessage(message, passphrase) {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const key = await deriveKey(passphrase, salt);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoder.encode(message)
  );

  return JSON.stringify({
    v: 1,
    alg: "AES-GCM",
    kdf: "PBKDF2-SHA-256",
    iter: PBKDF2_ITERATIONS,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    data: bytesToBase64(new Uint8Array(ciphertext))
  });
}

async function decryptMessage(payloadText, passphrase) {
  let payload;
  try {
    payload = JSON.parse(payloadText);
  } catch (error) {
    throw new Error("Payload is not valid JSON.");
  }

  if (payload.v !== 1 || payload.alg !== "AES-GCM" || payload.kdf !== "PBKDF2-SHA-256") {
    throw new Error("Payload format is not supported.");
  }

  const salt = base64ToBytes(payload.salt);
  const iv = base64ToBytes(payload.iv);
  const ciphertext = base64ToBytes(payload.data);
  const key = await deriveKey(passphrase, salt);

  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      ciphertext
    );
    return new TextDecoder().decode(plaintext);
  } catch (error) {
    throw new Error("Passphrase mismatch or corrupted payload.");
  }
}

async function handleEncrypt() {
  const passphrase = composePassphrase.value.trim();
  const message = composeMessage.value.trim();

  if (!passphrase || !message) {
    setStatus("Enter both a passphrase and message before encrypting.", "error");
    return;
  }

  encryptButton.disabled = true;
  setStatus("Encrypting message...");

  try {
    const payload = await encryptMessage(message, passphrase);
    encryptedOutput.value = payload;
    encryptedInput.value = payload;
    copyButton.disabled = false;
    setStatus("Message encrypted. Share the payload and keep the passphrase separate.");
  } catch (error) {
    setStatus(error.message, "error");
  } finally {
    encryptButton.disabled = false;
  }
}

async function handleDecrypt() {
  const passphrase = decryptPassphrase.value.trim();
  const payloadText = encryptedInput.value.trim();

  if (!passphrase || !payloadText) {
    setStatus("Enter the passphrase and encrypted payload before decrypting.", "error");
    return;
  }

  decryptButton.disabled = true;
  setStatus("Decrypting message...");

  try {
    const plaintext = await decryptMessage(payloadText, passphrase);
    decryptedOutput.value = plaintext;
    setStatus("Message decrypted successfully.");
  } catch (error) {
    decryptedOutput.value = "";
    setStatus(error.message, "error");
  } finally {
    decryptButton.disabled = false;
  }
}

async function handleCopy() {
  if (!encryptedOutput.value) {
    return;
  }

  try {
    await navigator.clipboard.writeText(encryptedOutput.value);
    setStatus("Encrypted payload copied to the clipboard.");
  } catch (error) {
    setStatus("Clipboard access was blocked. Copy the payload manually.", "error");
  }
}

async function loadSample() {
  const passphrase = "deadp0et-demo";
  const message = "Meet at the old bookstore. Bring the notebook, not the phone.";
  composePassphrase.value = passphrase;
  composeMessage.value = message;
  decryptPassphrase.value = passphrase;
  encryptedOutput.value = await encryptMessage(message, passphrase);
  encryptedInput.value = encryptedOutput.value;
  copyButton.disabled = false;
  setStatus("Sample payload loaded. Use the passphrase deadp0et-demo to decrypt it.");
}

encryptButton.addEventListener("click", handleEncrypt);
decryptButton.addEventListener("click", handleDecrypt);
copyButton.addEventListener("click", handleCopy);
sampleButton.addEventListener("click", () => {
  loadSample().catch((error) => setStatus(error.message, "error"));
});
