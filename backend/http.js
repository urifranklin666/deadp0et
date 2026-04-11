const fs = require("fs");

function sendJson(response, statusCode, payload) {
  response.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store"
  });
  response.end(JSON.stringify(payload, null, 2));
}

function sendError(response, statusCode, message, details) {
  sendJson(response, statusCode, {
    error: {
      message,
      details: details || null
    }
  });
}

function notFound(response) {
  sendError(response, 404, "Route not found.");
}

function methodNotAllowed(response, method) {
  sendError(response, 405, `Method ${method} is not allowed for this route.`);
}

function readJsonBody(request) {
  return new Promise((resolve, reject) => {
    let body = "";
    request.on("data", (chunk) => {
      body += chunk;
      if (body.length > 1024 * 1024) {
        reject(new Error("Request body exceeds 1 MiB."));
        request.destroy();
      }
    });
    request.on("end", () => {
      if (!body) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(body));
      } catch (error) {
        reject(new Error("Request body must be valid JSON."));
      }
    });
    request.on("error", reject);
  });
}

function parseUrl(request) {
  return new URL(request.url, `http://${request.headers.host || "localhost"}`);
}

function handleStatic(response, pathname, staticFiles) {
  const asset = staticFiles[pathname];
  if (!asset) {
    return false;
  }

  try {
    const content = fs.readFileSync(asset.filePath);
    response.writeHead(200, {
      "Content-Type": asset.contentType,
      "Cache-Control": pathname === "/" || pathname === "/index.html" ? "no-store" : "public, max-age=300"
    });
    response.end(content);
    return true;
  } catch (error) {
    sendError(response, 500, "Unable to serve static asset.", error.message);
    return true;
  }
}

module.exports = {
  handleStatic,
  methodNotAllowed,
  notFound,
  parseUrl,
  readJsonBody,
  sendError,
  sendJson
};
