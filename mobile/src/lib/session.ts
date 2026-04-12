import { createApiClient } from "@deadp0et/protocol-client";

import { MOBILE_DEFAULTS } from "./config";

export function createMobileApi(accessToken: string | null = null) {
  return createApiClient({
    apiBase: MOBILE_DEFAULTS.apiBase,
    getAccessToken: () => accessToken
  });
}
