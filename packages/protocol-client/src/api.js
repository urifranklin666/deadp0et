function normalizeApiBase(apiBase) {
  return String(apiBase || "").trim().replace(/\/+$/, "");
}

async function requestJson(apiBase, pathname, options = {}) {
  const base = normalizeApiBase(apiBase);
  const response = await fetch(`${base}${pathname}`, options);
  const text = await response.text();
  const body = text ? JSON.parse(text) : null;

  if (!response.ok) {
    const error = new Error(body?.error?.message || `Request failed with status ${response.status}.`);
    error.status = response.status;
    error.body = body;
    throw error;
  }

  return body;
}

/**
 * @param {{
 *   apiBase?: string,
 *   getApiBase?: (() => string) | null,
 *   getAccessToken?: (() => string | null) | null
 * }} [options]
 */
function createApiClient({ apiBase, getApiBase = null, getAccessToken = null } = {}) {
  function resolveApiBase() {
    const base = typeof getApiBase === "function" ? getApiBase() : apiBase;
    return normalizeApiBase(base);
  }

  function buildAuthHeaders(headers = {}) {
    const accessToken = typeof getAccessToken === "function" ? getAccessToken() : null;
    if (!accessToken) {
      return headers;
    }
    return {
      ...headers,
      Authorization: `Bearer ${accessToken}`
    };
  }

  function request(pathname, options = {}) {
    return requestJson(resolveApiBase(), pathname, options);
  }

  return {
    request,
    getHealth() {
      return request("/health");
    },
    createAccount(payload) {
      return request("/v1/accounts", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
    },
    createSession(payload) {
      return request("/v1/sessions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
    },
    getBundles(username) {
      return request(`/v1/users/${encodeURIComponent(username)}/bundles`);
    },
    issuePrekeyBundle(username, payload = {}) {
      return request(`/v1/users/${encodeURIComponent(username)}/prekey-bundle`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
    },
    getInbox() {
      return request("/v1/messages/inbox", {
        method: "GET",
        headers: buildAuthHeaders()
      });
    },
    acknowledgeInbox(payload) {
      return request("/v1/messages/inbox/ack", {
        method: "POST",
        headers: buildAuthHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify(payload)
      });
    },
    storeMessage(payload) {
      return request("/v1/messages", {
        method: "POST",
        headers: buildAuthHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify(payload)
      });
    },
    listDevices() {
      return request("/v1/devices", {
        headers: buildAuthHeaders()
      });
    },
    registerDevice(payload) {
      return request("/v1/devices", {
        method: "POST",
        headers: buildAuthHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify(payload)
      });
    },
    revokeDevice(deviceId) {
      return request(`/v1/devices/${encodeURIComponent(deviceId)}`, {
        method: "DELETE",
        headers: buildAuthHeaders()
      });
    },
    rotatePrekeys(payload) {
      return request("/v1/prekeys/rotate", {
        method: "POST",
        headers: buildAuthHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify(payload)
      });
    }
  };
}

module.exports = {
  createApiClient,
  normalizeApiBase,
  requestJson
};
