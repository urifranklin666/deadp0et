// deadp0et messenger client
// Crypto: ECDH P-256 keypair per user, AES-GCM 256 per conversation, PBKDF2 private-key wrapping

const App = (() => {

  // ── State ────────────────────────────────────────────────────────
  let jwt         = null;
  let myUserId    = null;
  let myUsername  = null;
  let myKeyPair   = null;      // { publicKey: CryptoKey, privateKey: CryptoKey }
  let ws          = null;
  let activeConvId = null;
  const sharedKeys  = new Map(); // convId → AES-GCM CryptoKey
  const peerPubKeys = new Map(); // userId → ECDH CryptoKey (public)

  // Typing indicator state
  let typingThrottle  = null;
  let typingHideTimer = null;

  // ── DOM shorthand ────────────────────────────────────────────────
  const $ = id => document.getElementById(id);

  // ── Crypto ───────────────────────────────────────────────────────

  async function generateKeyPair() {
    return crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true, ["deriveKey"]
    );
  }

  async function exportPublicKeyJwk(kp) {
    return crypto.subtle.exportKey("jwk", kp.publicKey);
  }

  async function importPublicKey(jwk) {
    return crypto.subtle.importKey(
      "jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, false, []
    );
  }

  async function exportPrivateKeyRaw(kp) {
    const jwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
    return new TextEncoder().encode(JSON.stringify(jwk));
  }

  async function importPrivateKeyFromRaw(raw) {
    const jwk = JSON.parse(new TextDecoder().decode(raw));
    return crypto.subtle.importKey(
      "jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"]
    );
  }

  // Derive an AES-GCM key from a password + salt via PBKDF2
  async function pbkdf2Key(password, saltB64) {
    const salt    = b64ToBytes(saltB64);
    const keyMat  = await crypto.subtle.importKey(
      "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: 200_000, hash: "SHA-256" },
      keyMat,
      { name: "AES-GCM", length: 256 },
      false, ["encrypt", "decrypt"]
    );
  }

  // Encrypt private key bytes with the PBKDF2 wrapper key
  async function wrapPrivateKey(kp, password) {
    const salt       = crypto.getRandomValues(new Uint8Array(16));
    const saltB64    = bytesToB64(salt);
    const wrapKey    = await pbkdf2Key(password, saltB64);
    const privRaw    = await exportPrivateKeyRaw(kp);
    const iv         = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, wrapKey, privRaw);
    return { salt: saltB64, iv: bytesToB64(iv), ct: bytesToB64(new Uint8Array(ciphertext)) };
  }

  async function unwrapPrivateKey(bundle, password) {
    const wrapKey = await pbkdf2Key(password, bundle.salt);
    const iv      = b64ToBytes(bundle.iv);
    const ct      = b64ToBytes(bundle.ct);
    const raw     = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, wrapKey, ct);
    return importPrivateKeyFromRaw(new Uint8Array(raw));
  }

  // Derive the shared AES-GCM key between me and a peer (ECDH)
  async function deriveConvKey(myPrivKey, theirPubKey) {
    return crypto.subtle.deriveKey(
      { name: "ECDH", public: theirPubKey },
      myPrivKey,
      { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
    );
  }

  async function aesEncrypt(key, plainBytes) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plainBytes);
    return { iv: bytesToB64(iv), ct: bytesToB64(new Uint8Array(ct)) };
  }

  async function aesDecrypt(key, ivB64, ctB64) {
    const iv = b64ToBytes(ivB64);
    const ct = b64ToBytes(ctB64);
    return crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  }

  async function encryptMessage(convId, payload) {
    const key   = await getSharedKey(convId);
    const bytes = new TextEncoder().encode(JSON.stringify(payload));
    return aesEncrypt(key, bytes);
  }

  async function decryptMessage(convId, ivB64, ctB64) {
    const key  = await getSharedKey(convId);
    const raw  = await aesDecrypt(key, ivB64, ctB64);
    return JSON.parse(new TextDecoder().decode(raw));
  }

  // ── Key cache ────────────────────────────────────────────────────

  async function getSharedKey(convId) {
    if (sharedKeys.has(convId)) return sharedKeys.get(convId);
    // Need peer's public key — fetch from conversations cache
    const conv   = conversationsCache.find(c => c.id === convId);
    if (!conv) throw new Error("Conversation not found: " + convId);
    const peerPk = await getPeerPublicKey(conv.peer_id);
    const key    = await deriveConvKey(myKeyPair.privateKey, peerPk);
    sharedKeys.set(convId, key);
    return key;
  }

  async function getPeerPublicKey(userId) {
    if (peerPubKeys.has(userId)) return peerPubKeys.get(userId);
    const res  = await apiFetch(`/api/users/${userId}/publickey`);
    const data = await res.json();
    const pk   = await importPublicKey(data.publicKey);
    peerPubKeys.set(userId, pk);
    return pk;
  }

  // ── Media crypto ─────────────────────────────────────────────────

  async function encryptFile(file, convId) {
    const convKey = await getSharedKey(convId);
    const bytes   = await file.arrayBuffer();

    // Random per-file key
    const fileKey = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
    );
    const fileKeyRaw = await crypto.subtle.exportKey("raw", fileKey);

    // Encrypt file bytes
    const { iv: fileIv, ct: fileCt } = await aesEncrypt(fileKey, bytes);

    // Encrypt the file key with the conversation key
    const { iv: keyIv, ct: keyCt } = await aesEncrypt(convKey, new Uint8Array(fileKeyRaw));

    return { fileCt, fileIv, keyIv, keyCt, name: file.name, type: file.type, size: file.size };
  }

  async function decryptFileBytes(convId, blob, fileIv, keyIv, keyCt) {
    const convKey    = await getSharedKey(convId);
    const fileKeyRaw = await aesDecrypt(convKey, keyIv, keyCt);
    const fileKey    = await crypto.subtle.importKey(
      "raw", fileKeyRaw, { name: "AES-GCM" }, false, ["decrypt"]
    );
    const plainBytes = await aesDecrypt(fileKey, fileIv, bytesToB64(new Uint8Array(await blob.arrayBuffer())));
    return plainBytes;
  }

  // ── B64 utils ────────────────────────────────────────────────────

  function bytesToB64(buf) {
    return btoa(String.fromCharCode(...(buf instanceof Uint8Array ? buf : new Uint8Array(buf))));
  }

  function b64ToBytes(b64) {
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  }

  // ── API ──────────────────────────────────────────────────────────

  async function apiFetch(url, opts = {}) {
    const headers = { ...(opts.headers || {}) };
    if (jwt) headers["Authorization"] = `Bearer ${jwt}`;
    const res = await fetch(url, { ...opts, headers });
    if (res.status === 401) { logout(); throw new Error("Session expired."); }
    return res;
  }

  // ── Auth ─────────────────────────────────────────────────────────

  async function register(username, password) {
    setAuthError("");
    setAuthLoading(true);
    try {
      const kp          = await generateKeyPair();
      const publicKey   = await exportPublicKeyJwk(kp);
      const encPriv     = await wrapPrivateKey(kp, password);

      const res  = await fetch("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password, publicKey, encPrivateKey: encPriv }),
      });
      const data = await res.json();
      if (!res.ok) { setAuthError(data.error); return; }

      myKeyPair  = kp;
      onLoginSuccess(data.token, data.userId, data.username);
    } catch (e) {
      setAuthError("Registration failed. Try again.");
    } finally {
      setAuthLoading(false);
    }
  }

  async function login(username, password) {
    setAuthError("");
    setAuthLoading(true);
    try {
      const res  = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();
      if (!res.ok) { setAuthError(data.error); return; }

      // Decrypt private key
      let privKey;
      try {
        privKey = await unwrapPrivateKey(data.encPrivateKey, password);
      } catch {
        setAuthError("Wrong password or corrupted key.");
        return;
      }

      // Reconstruct the full keypair (we need the public key too for derivation)
      const pubKeyRes = await fetch(`/api/users/${data.userId}/publickey`, {
        headers: { "Authorization": `Bearer ${data.token}` },
      });
      const pubKeyData = await pubKeyRes.json();
      const pubKey     = await importPublicKey(pubKeyData.publicKey);

      myKeyPair = { publicKey: pubKey, privateKey: privKey };
      onLoginSuccess(data.token, data.userId, data.username);
    } catch (e) {
      setAuthError("Login failed. Try again.");
    } finally {
      setAuthLoading(false);
    }
  }

  function onLoginSuccess(token, userId, username) {
    jwt        = token;
    myUserId   = userId;
    myUsername = username;
    sessionStorage.setItem("dp_session", JSON.stringify({ jwt, myUserId, myUsername }));
    connectWs();
    loadConversations().then(() => showScreen("home"));
    setStatus("connected", myUsername);
    registerPush();
  }

  function logout() {
    sessionStorage.removeItem("dp_session");
    jwt = null; myUserId = null; myUsername = null;
    myKeyPair = null; sharedKeys.clear(); peerPubKeys.clear();
    if (ws) { ws.close(); ws = null; }
    setStatus("offline", "e2e encrypted");
    showScreen("auth");
  }

  // ── WebSocket ────────────────────────────────────────────────────

  function connectWs() {
    if (ws) ws.close();
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    ws = new WebSocket(`${proto}//${location.host}/ws?token=${jwt}`);
    ws.onmessage = async (e) => {
      const msg = JSON.parse(e.data);
      switch (msg.type) {
        case "auth_ok": break;
        case "ack":     handleAck(msg); break;
        case "message": await handleIncomingMessage(msg); break;
        case "typing":  handleTyping(msg); break;
      }
    };
    ws.onclose = () => {
      // Reconnect after brief delay if still logged in
      if (jwt) setTimeout(connectWs, 3000);
    };
    ws.onerror = () => {};
  }

  function handleAck({ tempId, messageId }) {
    const el = document.querySelector(`[data-temp="${tempId}"]`);
    if (el) {
      el.dataset.id = messageId;
      delete el.dataset.temp;
      el.querySelector(".msg-tick")?.classList.add("tick-sent");
    }
  }

  async function handleIncomingMessage(msg) {
    // Make sure we have the conversation in cache
    let conv = conversationsCache.find(c => c.id === msg.conversationId);
    if (!conv) {
      await loadConversations();
      conv = conversationsCache.find(c => c.id === msg.conversationId);
    }
    if (!conv) return;

    // Decrypt
    let payload;
    try {
      payload = await decryptMessage(msg.conversationId, msg.iv, msg.ciphertext);
    } catch {
      payload = { text: "[decryption failed]" };
    }

    // Update conversation list
    renderConversationsList();

    // Append to open chat if it matches
    if (activeConvId === msg.conversationId) {
      // Normalise field names: WS uses snake_case, fall back to old camelCase if present
      appendMessageEl({
        ...msg,
        sender_id:  msg.sender_id  ?? msg.senderId,
        created_at: msg.created_at ?? msg.createdAt,
        payload,
        incoming: true,
        isNew:    true,
      });
      hideTypingIndicator();
      scrollChatBottom();
    } else {
      // Badge on the conversation item
      const item = document.querySelector(`[data-conv-id="${msg.conversationId}"]`);
      if (item) item.classList.add("has-unread");
    }
  }

  function handleTyping({ conversationId }) {
    if (conversationId !== activeConvId) return;
    const el = $("typing-indicator");
    if (!el) return;
    el.hidden = false;
    clearTimeout(typingHideTimer);
    typingHideTimer = setTimeout(hideTypingIndicator, 3000);
  }

  function hideTypingIndicator() {
    const el = $("typing-indicator");
    if (el) el.hidden = true;
    clearTimeout(typingHideTimer);
  }

  function sendTypingEvent() {
    if (!ws || ws.readyState !== WebSocket.OPEN || !activeConvId) return;
    if (typingThrottle) return;
    ws.send(JSON.stringify({ type: "typing", conversationId: activeConvId }));
    typingThrottle = setTimeout(() => { typingThrottle = null; }, 3000);
  }

  // ── Conversations ────────────────────────────────────────────────

  let conversationsCache = [];

  async function loadConversations() {
    const res  = await apiFetch("/api/conversations");
    conversationsCache = await res.json();
    renderConversationsList();
  }

  function renderConversationsList() {
    const list = $("conv-list");
    if (!list) return;
    list.innerHTML = "";

    if (conversationsCache.length === 0) {
      list.innerHTML = `<p class="conv-empty">No conversations yet.<br>Search for a username to start.</p>`;
      return;
    }

    conversationsCache.forEach(conv => {
      const initial = (conv.peer_username || "?")[0].toUpperCase();
      const time    = conv.last_at ? formatTime(conv.last_at * 1000) : "";
      const el      = document.createElement("div");
      el.className  = "conv-item" + (conv.unread > 0 ? " has-unread" : "");
      el.dataset.convId = conv.id;
      el.innerHTML  = `
        <div class="conv-avatar">${initial}</div>
        <div class="conv-info">
          <span class="conv-name">${escHtml(conv.peer_username)}</span>
          <span class="conv-preview">encrypted message</span>
        </div>
        ${time ? `<span class="conv-time">${time}</span>` : ""}
        ${conv.unread > 0 ? `<span class="conv-badge">${conv.unread}</span>` : ""}
      `;
      el.addEventListener("click", () => openConversation(conv.id, conv.peer_id, conv.peer_username));
      list.appendChild(el);
    });
  }

  async function openConversation(convId, peerId, peerUsername) {
    activeConvId = convId;

    // Warm up the shared key
    if (!sharedKeys.has(convId)) {
      const conv = conversationsCache.find(c => c.id === convId) || { peer_id: peerId };
      await getPeerPublicKey(conv.peer_id || peerId);
      await getSharedKey(convId);
    }

    // Update header
    $("chat-peer-name").textContent = peerUsername || "…";

    showScreen("chat");
    $("chat-messages").innerHTML = "";
    hideTypingIndicator();
    $("chat-input").focus();

    // Load message history
    await loadMessages(convId);
    scrollChatBottom();
  }

  async function startNewChat(username) {
    if (!username || username === myUsername) return;
    const searchRes  = await apiFetch(`/api/users/search?q=${encodeURIComponent(username)}`);
    const results    = await searchRes.json();
    const peer       = results.find(u => u.username.toLowerCase() === username.toLowerCase());
    if (!peer) { setSearchError("User not found."); return; }

    const convRes  = await apiFetch("/api/conversations", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ peerId: peer.id }),
    });
    const conv = await convRes.json();

    // Merge into cache
    if (!conversationsCache.find(c => c.id === conv.id)) {
      conversationsCache.unshift({ ...conv, peer_id: peer.id, peer_username: peer.username, unread: 0 });
    }

    closeNewChatModal();
    openConversation(conv.id, peer.id, peer.username);
  }

  // ── Messages ─────────────────────────────────────────────────────

  async function loadMessages(convId) {
    const res  = await apiFetch(`/api/conversations/${convId}/messages`);
    const msgs = await res.json();
    for (const msg of msgs) {
      let payload;
      try {
        payload = await decryptMessage(convId, msg.iv, msg.ciphertext);
      } catch {
        payload = { text: "[decryption failed]" };
      }
      appendMessageEl({ ...msg, payload, incoming: msg.sender_id !== myUserId });
    }
  }

  let tempIdCounter = 0;

  async function sendMessage() {
    const input  = $("chat-input");
    const text   = input.value.trim();
    if (!text && !pendingMediaData) return;
    if (!activeConvId) return;

    input.value = "";
    autoResize(input);
    clearTimeout(typingThrottle); typingThrottle = null;

    const payload = { text: text || "" };
    let mediaUploadId = null;

    if (pendingMediaData) {
      const { encData, meta, convId } = pendingMediaData;
      // Upload encrypted bytes
      const bytes   = b64ToBytes(encData.fileCt);
      const upRes   = await apiFetch(`/api/media?convId=${convId}`, {
        method: "POST",
        headers: { "Content-Type": "application/octet-stream" },
        body: bytes,
      });
      if (upRes.ok) {
        const { mediaId } = await upRes.json();
        mediaUploadId = mediaId;
        payload.media = {
          mediaId,
          fileIv: encData.fileIv,
          keyIv:  encData.keyIv,
          keyCt:  encData.keyCt,
          name:   meta.name,
          type:   meta.type,
          size:   meta.size,
        };
      }
      clearMediaPreview();
    }

    const { iv, ct } = await encryptMessage(activeConvId, payload);

    const tempId = ++tempIdCounter;
    const now    = Date.now();

    // Optimistic render
    appendMessageEl({
      id:             null,
      conversation_id: activeConvId,
      sender_id:      myUserId,
      payload,
      incoming:       false,
      created_at:     Math.floor(now / 1000),
      tempId,
      isNew:          true,
    });
    scrollChatBottom();

    // Send via WebSocket
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({
        type:           "send",
        tempId,
        conversationId: activeConvId,
        iv,
        ciphertext:     ct,
        mediaId:        mediaUploadId,
      }));
    }
  }

  let pendingMediaData = null;

  async function handleFileSelected(file) {
    if (!file || !activeConvId) return;
    if (file.size > 25 * 1024 * 1024) { alert("Max file size is 25 MB."); return; }

    showMediaLoading(true);
    try {
      const encData = await encryptFile(file, activeConvId);
      pendingMediaData = { encData, meta: { name: file.name, type: file.type, size: file.size }, convId: activeConvId };
      showMediaPreview(file);
    } catch {
      alert("Failed to encrypt file.");
    } finally {
      showMediaLoading(false);
    }
  }

  function clearMediaPreview() {
    pendingMediaData = null;
    const preview = $("media-preview");
    if (preview) preview.innerHTML = "";
    const wrap = $("media-preview-wrap");
    if (wrap) wrap.hidden = true;
  }

  function showMediaPreview(file) {
    const wrap    = $("media-preview-wrap");
    const preview = $("media-preview");
    if (!wrap || !preview) return;
    wrap.hidden = false;

    if (file.type.startsWith("image/")) {
      const url  = URL.createObjectURL(file);
      const img  = document.createElement("img");
      img.src    = url;
      img.className = "media-thumb";
      preview.innerHTML = "";
      preview.appendChild(img);
    } else {
      preview.innerHTML = `<span class="media-file-chip">📎 ${escHtml(file.name)}</span>`;
    }
  }

  function showMediaLoading(on) {
    const btn = $("btn-attach");
    if (btn) btn.disabled = on;
  }

  function appendMessageEl({ id, sender_id, payload, incoming, created_at, tempId, isNew = false }) {
    const list = $("chat-messages");
    if (!list) return;

    // Grouped message detection: same sender within 60 seconds
    const prev    = list.lastElementChild;
    const grouped = prev &&
      !prev.classList.contains("msg-system") &&
      prev.dataset.senderId === String(sender_id) &&
      (created_at - parseInt(prev.dataset.ts || 0, 10)) < 60;

    if (grouped) {
      const hasStart = prev.classList.contains("msg-group-start");
      const hasMid   = prev.classList.contains("msg-group-mid");
      const hasEnd   = prev.classList.contains("msg-group-end");
      if (!hasStart && !hasMid && !hasEnd) {
        prev.classList.add("msg-group-start");
      } else if (hasEnd) {
        prev.classList.remove("msg-group-end");
        if (!hasStart) prev.classList.add("msg-group-mid");
      }
    }

    const wrap = document.createElement("div");
    wrap.className = `msg ${incoming ? "msg-them" : "msg-me"}`;
    wrap.dataset.senderId = String(sender_id);
    wrap.dataset.ts       = String(created_at);
    if (grouped) wrap.classList.add("msg-group-end");
    if (isNew)   wrap.classList.add("entering");
    if (tempId) wrap.dataset.temp = tempId;
    if (id)     wrap.dataset.id   = id;

    const bubble = document.createElement("div");
    bubble.className = "msg-bubble";

    if (payload.media) {
      bubble.appendChild(buildMediaEl(payload.media, incoming));
    }

    if (payload.text) {
      const textEl = document.createElement("span");
      textEl.className = "msg-text";
      textEl.textContent = payload.text;
      bubble.appendChild(textEl);
    }

    const footer = document.createElement("div");
    footer.className = "msg-footer";
    footer.innerHTML = `<span class="msg-ts">${formatTime(created_at * 1000)}</span>`;
    if (!incoming) {
      footer.innerHTML += `<span class="msg-tick ${id ? "tick-sent" : ""}">✓</span>`;
    }

    wrap.appendChild(bubble);
    wrap.appendChild(footer);
    list.appendChild(wrap);
  }

  function buildMediaEl(media, incoming) {
    const wrap = document.createElement("div");
    wrap.className = "msg-media";

    if (media.type && media.type.startsWith("image/")) {
      const btn = document.createElement("button");
      btn.className = "msg-media-load";
      btn.textContent = `🔒 ${escHtml(media.name || "image")}  ·  tap to decrypt`;
      btn.addEventListener("click", async () => {
        btn.disabled   = true;
        btn.textContent = "Decrypting…";
        try {
          const response  = await apiFetch(`/api/media/${media.mediaId}`);
          const blob      = await response.blob();
          const plainBuf  = await decryptFileBytes(
            activeConvId, blob, media.fileIv, media.keyIv, media.keyCt
          );
          const imgUrl = URL.createObjectURL(new Blob([plainBuf], { type: media.type }));
          const img    = document.createElement("img");
          img.src      = imgUrl;
          img.className = "msg-media-img";
          wrap.replaceChild(img, btn);
        } catch {
          btn.textContent = "⚠ Decryption failed";
        }
      });
      wrap.appendChild(btn);
    } else {
      const btn  = document.createElement("button");
      btn.className = "msg-media-load";
      btn.textContent = `📎 ${escHtml(media.name || "file")} — tap to decrypt & download`;
      btn.addEventListener("click", async () => {
        btn.disabled   = true;
        btn.textContent = "Decrypting…";
        try {
          const response = await apiFetch(`/api/media/${media.mediaId}`);
          const blob     = await response.blob();
          const plain    = await decryptFileBytes(
            activeConvId, blob, media.fileIv, media.keyIv, media.keyCt
          );
          const a   = document.createElement("a");
          a.href    = URL.createObjectURL(new Blob([plain], { type: media.type || "application/octet-stream" }));
          a.download = media.name || "file";
          a.click();
          btn.textContent = `✓ ${escHtml(media.name || "file")}`;
        } catch {
          btn.textContent = "⚠ Decryption failed";
        }
      });
      wrap.appendChild(btn);
    }

    return wrap;
  }

  // ── UI helpers ───────────────────────────────────────────────────

  function showScreen(name) {
    document.querySelectorAll(".screen").forEach(s => {
      s.classList.toggle("active", s.id === `screen-${name}`);
    });
  }

  function setStatus(state, label) {
    const badge  = $("header-badge");
    const status = badge.closest(".header-status") || badge.parentElement;
    badge.textContent = label;
    status.className  = `header-status s-${state}`;
  }

  function setAuthError(msg) {
    const el = $("auth-error");
    if (el) { el.textContent = msg; el.hidden = !msg; }
  }

  function setAuthLoading(on) {
    const btn = $("btn-auth-submit");
    if (btn) { btn.disabled = on; btn.textContent = on ? "…" : authMode === "login" ? "Sign In" : "Create Account"; }
  }

  function setSearchError(msg) {
    const el = $("search-error");
    if (el) { el.textContent = msg; el.hidden = !msg; }
  }

  function openNewChatModal() {
    const m = $("modal-new-chat");
    if (m) { m.hidden = false; $("new-chat-input").focus(); }
  }

  function closeNewChatModal() {
    const m = $("modal-new-chat");
    if (m) { m.hidden = true; $("new-chat-input").value = ""; setSearchError(""); }
  }

  function scrollChatBottom() {
    const list = $("chat-messages");
    if (list) list.scrollTop = list.scrollHeight;
  }

  function autoResize(el) {
    el.style.height = "auto";
    el.style.height = Math.min(el.scrollHeight, 120) + "px";
  }

  function formatTime(ms) {
    const d   = new Date(ms);
    const now = new Date();
    if (d.toDateString() === now.toDateString()) {
      return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    }
    return d.toLocaleDateString([], { month: "short", day: "numeric" });
  }

  function escHtml(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  // ── Auth mode toggle ─────────────────────────────────────────────

  let authMode = "login";

  function setAuthMode(mode) {
    authMode = mode;
    $("auth-toggle-login").classList.toggle("active", mode === "login");
    $("auth-toggle-register").classList.toggle("active", mode === "register");
    $("btn-auth-submit").textContent = mode === "login" ? "Sign In" : "Create Account";
    setAuthError("");
  }

  // ── Push notifications ───────────────────────────────────────────

  async function registerPush() {
    if (!("serviceWorker" in navigator) || !("PushManager" in window)) return;
    try {
      const reg = await navigator.serviceWorker.register("/sw.js");

      const keyRes = await apiFetch("/api/push/vapid-public-key");
      const { publicKey } = await keyRes.json();
      if (!publicKey) return;

      const perm = await Notification.requestPermission();
      if (perm !== "granted") return;

      let sub = await reg.pushManager.getSubscription();
      if (!sub) {
        sub = await reg.pushManager.subscribe({
          userVisibleOnly: true,
          applicationServerKey: urlBase64ToUint8Array(publicKey),
        });
      }

      await apiFetch("/api/push/subscribe", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(sub.toJSON()),
      });
    } catch (e) {
      console.warn("[push]", e);
    }
  }

  function urlBase64ToUint8Array(b64) {
    const pad = "=".repeat((4 - (b64.length % 4)) % 4);
    const raw = atob((b64 + pad).replace(/-/g, "+").replace(/_/g, "/"));
    return Uint8Array.from([...raw].map(c => c.charCodeAt(0)));
  }

  // ── Init ─────────────────────────────────────────────────────────

  async function init() {
    // ── Wire up all event listeners unconditionally ───────────────

    // Auth form
    $("auth-toggle-login").addEventListener("click", () => setAuthMode("login"));
    $("auth-toggle-register").addEventListener("click", () => setAuthMode("register"));

    $("btn-auth-submit").addEventListener("click", async () => {
      const username = $("auth-username").value.trim();
      const password = $("auth-password").value;
      if (authMode === "login") await login(username, password);
      else await register(username, password);
    });

    ["auth-username", "auth-password"].forEach(id => {
      $(id).addEventListener("keydown", e => { if (e.key === "Enter") $("btn-auth-submit").click(); });
    });

    // Unlock screen
    $("btn-unlock").addEventListener("click", async () => {
      const password = $("unlock-password").value;
      $("btn-unlock").disabled = true;
      try {
        const res  = await fetch("/api/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: myUsername, password }),
        });
        const data = await res.json();
        if (!res.ok) { $("unlock-error").textContent = data.error; $("unlock-error").hidden = false; return; }

        const privKey = await unwrapPrivateKey(data.encPrivateKey, password);
        const pkRes   = await fetch(`/api/users/${data.userId}/publickey`, {
          headers: { "Authorization": `Bearer ${jwt}` },
        });
        const pkData  = await pkRes.json();
        const pubKey  = await importPublicKey(pkData.publicKey);
        myKeyPair = { publicKey: pubKey, privateKey: privKey };
        jwt = data.token;
        connectWs();
        await loadConversations();
        showScreen("home");
        setStatus("connected", myUsername);
        registerPush();
      } catch { $("unlock-error").textContent = "Failed. Try again."; $("unlock-error").hidden = false; }
      finally  { $("btn-unlock").disabled = false; }
    });

    $("unlock-password").addEventListener("keydown", e => { if (e.key === "Enter") $("btn-unlock").click(); });
    $("btn-unlock-logout").addEventListener("click", () => { sessionStorage.clear(); logout(); });

    // Home screen
    $("btn-new-chat").addEventListener("click", openNewChatModal);
    $("btn-logout").addEventListener("click", logout);

    // New chat modal
    $("btn-modal-close").addEventListener("click", closeNewChatModal);
    $("btn-modal-start").addEventListener("click", async () => {
      const u = $("new-chat-input").value.trim();
      if (u) await startNewChat(u);
    });
    $("new-chat-input").addEventListener("keydown", e => { if (e.key === "Enter") $("btn-modal-start").click(); });
    $("modal-new-chat").addEventListener("click", e => { if (e.target === $("modal-new-chat")) closeNewChatModal(); });

    // Chat screen
    $("btn-back").addEventListener("click", () => {
      activeConvId = null;
      loadConversations().then(() => showScreen("home"));
    });

    const chatInput = $("chat-input");
    chatInput.addEventListener("keydown", e => {
      if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(); }
    });
    chatInput.addEventListener("input", () => { autoResize(chatInput); sendTypingEvent(); });

    $("btn-send").addEventListener("click", sendMessage);

    $("btn-attach").addEventListener("click", () => $("file-input").click());
    $("file-input").addEventListener("change", e => {
      const f = e.target.files[0];
      if (f) handleFileSelected(f);
      e.target.value = "";
    });

    $("btn-media-cancel").addEventListener("click", clearMediaPreview);

    // Drag-and-drop on chat
    const chatArea = $("screen-chat");
    chatArea.addEventListener("dragover", e => e.preventDefault());
    chatArea.addEventListener("drop", e => {
      e.preventDefault();
      const f = e.dataTransfer.files[0];
      if (f) handleFileSelected(f);
    });

    // ── Determine initial screen ──────────────────────────────────

    const saved = sessionStorage.getItem("dp_session");
    if (saved) {
      try {
        const s = JSON.parse(saved);
        jwt = s.jwt; myUserId = s.myUserId; myUsername = s.myUsername;
        $("unlock-username").textContent = myUsername;
        showScreen("unlock");
        return;
      } catch { sessionStorage.removeItem("dp_session"); }
    }

    setStatus("offline", "e2e encrypted");
    showScreen("auth");
  }

  return { init };
})();

document.addEventListener("DOMContentLoaded", App.init);
