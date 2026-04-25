const http = require("http");
const fs   = require("fs");
const path = require("path");
const { WebSocketServer } = require("ws");

const { register, login, requireAuth, searchUsers, getPublicKey } = require("./backend/auth");
const { getOrCreateConversation, listConversations, getMessages }  = require("./backend/messages");
const { uploadMedia, downloadMedia }                               = require("./backend/media");
const { setupWs }                                                  = require("./backend/ws");

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || "0.0.0.0";

// ── Helpers ───────────────────────────────────────────────────────────

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js":   "application/javascript; charset=utf-8",
  ".css":  "text/css; charset=utf-8",
  ".svg":  "image/svg+xml",
  ".ico":  "image/x-icon",
};

function serveStatic(res, urlPath) {
  const filePath = path.join(__dirname, urlPath.replace(/\.\./g, ""));
  const ext      = path.extname(filePath);
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); res.end("Not found"); return; }
    res.writeHead(200, {
      "Content-Type": MIME[ext] || "application/octet-stream",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    });
    res.end(data);
  });
}

function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(payload);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", c => { body += c; if (body.length > 1e6) req.destroy(); });
    req.on("end",  () => { try { resolve(JSON.parse(body)); } catch { reject(new Error("Bad JSON")); } });
    req.on("error", reject);
  });
}

// ── Request handler ───────────────────────────────────────────────────

async function handleRequest(req, res) {
  const url      = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;
  const method   = req.method;

  // ── API routes ─────────────────────────────────────────────────

  if (pathname === "/api/auth/register" && method === "POST") {
    const body   = await readJson(req);
    const result = await register(body);
    return json(res, result.status, result.body);
  }

  if (pathname === "/api/auth/login" && method === "POST") {
    const body   = await readJson(req);
    const result = await login(body);
    return json(res, result.status, result.body);
  }

  // All routes below require auth
  const user = requireAuth(req);
  if (pathname.startsWith("/api/") && !user) {
    return json(res, 401, { error: "Unauthorized." });
  }

  if (pathname === "/api/users/search" && method === "GET") {
    const q = url.searchParams.get("q") || "";
    return json(res, 200, searchUsers(q, user.id));
  }

  const userKeyMatch = pathname.match(/^\/api\/users\/(\d+)\/publickey$/);
  if (userKeyMatch && method === "GET") {
    const pk = getPublicKey(Number(userKeyMatch[1]));
    if (!pk) return json(res, 404, { error: "User not found." });
    return json(res, 200, { publicKey: pk });
  }

  if (pathname === "/api/conversations" && method === "GET") {
    return json(res, 200, listConversations(user.id));
  }

  if (pathname === "/api/conversations" && method === "POST") {
    const { peerId } = await readJson(req);
    if (!peerId || peerId === user.id) {
      return json(res, 400, { error: "Invalid peerId." });
    }
    const conv = getOrCreateConversation(user.id, peerId);
    return json(res, 200, conv);
  }

  const convMsgMatch = pathname.match(/^\/api\/conversations\/(\d+)\/messages$/);
  if (convMsgMatch && method === "GET") {
    const convId = Number(convMsgMatch[1]);
    const before = url.searchParams.get("before") ? Number(url.searchParams.get("before")) : null;
    const msgs   = getMessages(convId, user.id, before);
    return json(res, 200, msgs);
  }

  if (pathname === "/api/media" && method === "POST") {
    const convId = Number(url.searchParams.get("convId") || 0);
    const result = await uploadMedia(req, user.id, convId);
    if (result.body) return json(res, result.status, result.body);
    return json(res, result.status, {});
  }

  const mediaMatch = pathname.match(/^\/api\/media\/(\d+)$/);
  if (mediaMatch && method === "GET") {
    const result = downloadMedia(Number(mediaMatch[1]), user.id);
    if (result.status !== 200) { res.writeHead(result.status); res.end(); return; }
    res.writeHead(200, {
      "Content-Type": "application/octet-stream",
      "Content-Length": result.size,
      "Cache-Control": "no-store",
    });
    fs.createReadStream(result.filePath).pipe(res);
    return;
  }

  // ── Static files ───────────────────────────────────────────────

  let filePath = pathname === "/" ? "/index.html" : pathname;
  // Only serve known static files
  if (["/index.html", "/app.js", "/styles.css", "/logo.svg"].includes(filePath)) {
    return serveStatic(res, filePath);
  }

  // SPA fallback — any unknown path returns the app shell
  serveStatic(res, "/index.html");
}

// ── Boot ──────────────────────────────────────────────────────────────

const server = http.createServer(async (req, res) => {
  try {
    await handleRequest(req, res);
  } catch (err) {
    console.error(err);
    if (!res.headersSent) json(res, 500, { error: "Internal server error." });
  }
});

const wss = new WebSocketServer({ server, path: "/ws" });
setupWs(wss);

server.listen(PORT, HOST, () => {
  console.log(`deadp0et listening on http://${HOST}:${PORT}`);
});
