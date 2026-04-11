const { handleStatic, methodNotAllowed, notFound, parseUrl, sendError } = require("./http");

function createRequestHandler(config, service) {
  return async function handleRequest(request, response) {
    response.setHeader("Access-Control-Allow-Origin", "*");
    response.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    response.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");

    if (request.method === "OPTIONS") {
      response.writeHead(204);
      response.end();
      return;
    }

    try {
      const url = parseUrl(request);
      const pathname = url.pathname;

      if (request.method === "GET" && pathname === "/health") {
        service.handleHealth(response);
        return;
      }

      if (pathname === "/v1/accounts") {
        if (request.method !== "POST") {
          methodNotAllowed(response, request.method);
          return;
        }
        await service.handleCreateAccount(request, response);
        return;
      }

      if (pathname === "/v1/sessions") {
        if (request.method !== "POST") {
          methodNotAllowed(response, request.method);
          return;
        }
        await service.handleCreateSession(request, response);
        return;
      }

      if (request.method === "GET" && pathname.startsWith("/v1/users/") && pathname.endsWith("/bundles")) {
        const username = decodeURIComponent(pathname.slice("/v1/users/".length, -"/bundles".length));
        service.handleGetBundles(response, username);
        return;
      }

      if (pathname.startsWith("/v1/users/") && pathname.endsWith("/prekey-bundle")) {
        if (request.method !== "POST") {
          methodNotAllowed(response, request.method);
          return;
        }
        const username = decodeURIComponent(pathname.slice("/v1/users/".length, -"/prekey-bundle".length));
        await service.handleIssuePrekeyBundle(request, response, username);
        return;
      }

      if (pathname === "/v1/messages") {
        if (request.method !== "POST") {
          methodNotAllowed(response, request.method);
          return;
        }
        await service.handleStoreMessage(request, response);
        return;
      }

      if (pathname === "/v1/messages/inbox") {
        if (request.method === "GET") {
          service.handleInbox(request, response);
          return;
        }
        if (request.method === "POST") {
          await service.handleAcknowledgeInbox(request, response);
          return;
        }
        methodNotAllowed(response, request.method);
        return;
      }

      if (pathname === "/v1/messages/inbox/ack") {
        if (request.method !== "POST") {
          methodNotAllowed(response, request.method);
          return;
        }
        await service.handleAcknowledgeInbox(request, response);
        return;
      }

      if (pathname === "/v1/devices") {
        if (request.method === "GET") {
          service.handleListDevices(request, response);
          return;
        }
        if (request.method === "POST") {
          await service.handleRegisterDevice(request, response);
          return;
        }
        methodNotAllowed(response, request.method);
        return;
      }

      if (request.method === "DELETE" && pathname.startsWith("/v1/devices/")) {
        const auth = service.requireAuth(request, response);
        if (!auth) {
          return;
        }
        const deviceId = decodeURIComponent(pathname.slice("/v1/devices/".length));
        service.handleDeleteDevice(response, auth, deviceId);
        return;
      }

      if (pathname === "/v1/prekeys/rotate") {
        if (request.method !== "POST") {
          methodNotAllowed(response, request.method);
          return;
        }
        await service.handleRotatePrekeys(request, response);
        return;
      }

      if (request.method === "GET" && handleStatic(response, pathname, config.STATIC_FILES)) {
        return;
      }

      notFound(response);
    } catch (error) {
      sendError(response, 500, "Internal server error.", error.message);
    }
  };
}

module.exports = {
  createRequestHandler
};
