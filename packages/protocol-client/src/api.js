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

  function buildQuery(params) {
    const search = new URLSearchParams();
    for (const [key, value] of Object.entries(params || {})) {
      if (value === undefined || value === null || value === "") {
        continue;
      }
      search.set(key, String(value));
    }
    const query = search.toString();
    return query ? `?${query}` : "";
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
    listSessions() {
      return request("/v1/sessions", {
        method: "GET",
        headers: buildAuthHeaders()
      });
    },
    revokeCurrentSession() {
      return request("/v1/sessions/current", {
        method: "DELETE",
        headers: buildAuthHeaders()
      });
    },
    revokeSession(sessionId) {
      return request(`/v1/sessions/${encodeURIComponent(sessionId)}`, {
        method: "DELETE",
        headers: buildAuthHeaders()
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
    getInboxPage(params = {}) {
      return request(`/v1/messages/inbox${buildQuery(params)}`, {
        method: "GET",
        headers: buildAuthHeaders()
      });
    },
    getHistory(params = {}) {
      return request(`/v1/messages/history${buildQuery(params)}`, {
        method: "GET",
        headers: buildAuthHeaders()
      });
    },
    listConversations(params = {}) {
      return request(`/v1/messages/conversations${buildQuery(params)}`, {
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
    },
    listPushRegistrations() {
      return request("/v1/push/registrations", {
        method: "GET",
        headers: buildAuthHeaders()
      });
    },
    registerPushToken(payload) {
      return request("/v1/push/register", {
        method: "POST",
        headers: buildAuthHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify(payload)
      });
    },
    revokePushToken(token) {
      return request(`/v1/push/register/${encodeURIComponent(token)}`, {
        method: "DELETE",
        headers: buildAuthHeaders()
      });
    }
  };
}

module.exports = {
  createApiClient,
  normalizeApiBase,
  requestJson
};
