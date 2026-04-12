import { Link, useRouter } from "expo-router";
import { useFocusEffect } from "expo-router";
import { useCallback, useState } from "react";
import { Pressable, ScrollView, StyleSheet, Text, TextInput, View } from "react-native";

import { MOBILE_DEFAULTS } from "../src/lib/config";
import {
  clearContactTrust,
  clearLocalDevice,
  clearPreferredApiBase,
  clearSession,
  loadPreferredApiBase,
  savePreferredApiBase,
  saveSession
} from "../src/lib/secure-storage";
import { createMobileApi, loadStoredAuthState } from "../src/lib/session";

export default function SettingsScreen() {
  const router = useRouter();
  const [loading, setLoading] = useState(true);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [apiBase, setApiBase] = useState(MOBILE_DEFAULTS.apiBase);
  const [username, setUsername] = useState("");
  const [deviceId, setDeviceId] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [accountId, setAccountId] = useState("");

  const loadSettingsState = useCallback(async () => {
    setLoading(true);

    try {
      const preferredApiBase = await loadPreferredApiBase();
      if (preferredApiBase) {
        setApiBase(preferredApiBase);
      } else {
        setApiBase(MOBILE_DEFAULTS.apiBase);
      }

      try {
        const auth = await loadStoredAuthState();
        setUsername(auth.localDeviceRecord.username || "");
        setDeviceId(auth.session.deviceId || "");
        setExpiresAt(auth.session.expiresAt || "");
        setAccountId(auth.localDeviceRecord.accountId || "");
      } catch {
        setUsername("");
        setDeviceId("");
        setExpiresAt("");
        setAccountId("");
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useFocusEffect(
    useCallback(() => {
      loadSettingsState().catch(() => {});
    }, [loadSettingsState])
  );

  async function handleSaveApiBase() {
    const actionKey = "save-api-base";
    setBusyAction(actionKey);
    setStatus("Saving backend URL...");

    try {
      const trimmedApiBase = apiBase.trim() || MOBILE_DEFAULTS.apiBase;
      await savePreferredApiBase(trimmedApiBase);

      try {
        const auth = await loadStoredAuthState();
        await saveSession(JSON.stringify({
          apiBase: trimmedApiBase,
          session: auth.session
        }));
      } catch {
        // Keep the preferred API base even when there is no current session yet.
      }

      setApiBase(trimmedApiBase);
      setStatus(`Saved backend URL ${trimmedApiBase}.`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Unable to save the backend URL.");
    } finally {
      setBusyAction(null);
    }
  }

  async function handleHealthCheck() {
    const actionKey = "health-check";
    setBusyAction(actionKey);
    setStatus(`Checking backend health at ${apiBase.trim() || MOBILE_DEFAULTS.apiBase}...`);

    try {
      const api = createMobileApi(apiBase.trim() || MOBILE_DEFAULTS.apiBase, null);
      const payload = await api.getHealth();
      setStatus(
        `${payload.status}: ${payload.accounts} account(s), ${payload.sessions} active session(s), ${payload.messages} message(s).`
      );
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Backend health check failed.");
    } finally {
      setBusyAction(null);
    }
  }

  async function handleLogout() {
    const actionKey = "logout";
    setBusyAction(actionKey);
    setStatus("Clearing the saved session...");

    try {
      await clearSession();
      setStatus("Saved session cleared. Local device keys are still stored on this phone.");
      router.replace("/login");
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Unable to clear the saved session.");
    } finally {
      setBusyAction(null);
    }
  }

  async function handleResetLocalState() {
    const actionKey = "reset-local-state";
    setBusyAction(actionKey);
    setStatus("Clearing all locally stored state...");

    try {
      await clearSession();
      await clearLocalDevice();
      await clearContactTrust();
      await clearPreferredApiBase();
      setApiBase(MOBILE_DEFAULTS.apiBase);
      setUsername("");
      setDeviceId("");
      setExpiresAt("");
      setAccountId("");
      setStatus("Cleared session, local device record, trust records, and saved backend URL.");
      router.replace("/login");
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Unable to clear local app state.");
    } finally {
      setBusyAction(null);
    }
  }

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <Text style={styles.title}>Settings</Text>
      <Text style={styles.body}>
        Backend configuration, session diagnostics, logout, and local reset controls are available here. Notification
        settings and app lock still need separate work.
      </Text>

      <View style={styles.card}>
        <Text style={styles.cardTitle}>Session</Text>
        <Text style={styles.meta}>Username: {username || "not signed in"}</Text>
        <Text style={styles.meta}>Account ID: {accountId || "unknown"}</Text>
        <Text style={styles.meta}>Device ID: {deviceId || "unknown"}</Text>
        <Text style={styles.meta}>Expires: {expiresAt || "unknown"}</Text>
      </View>

      <View style={styles.card}>
        <Text style={styles.cardTitle}>Backend</Text>
        <TextInput
          value={apiBase}
          onChangeText={setApiBase}
          autoCapitalize="none"
          autoCorrect={false}
          style={styles.input}
        />
        <View style={styles.actions}>
          <Pressable
            onPress={() => handleSaveApiBase().catch(() => {})}
            disabled={busyAction === "save-api-base" || loading}
            style={styles.button}
          >
            <Text style={styles.buttonText}>{busyAction === "save-api-base" ? "Saving..." : "Save backend URL"}</Text>
          </Pressable>
          <Pressable
            onPress={() => handleHealthCheck().catch(() => {})}
            disabled={busyAction === "health-check" || loading}
            style={styles.secondaryButton}
          >
            <Text style={styles.secondaryButtonText}>{busyAction === "health-check" ? "Checking..." : "Check backend health"}</Text>
          </Pressable>
        </View>
      </View>

      <View style={styles.card}>
        <Text style={styles.cardTitle}>Security</Text>
        <Link href="/trust" asChild>
          <Pressable style={styles.secondaryButton}>
            <Text style={styles.secondaryButtonText}>Manage trusted devices</Text>
          </Pressable>
        </Link>
        <Pressable
          onPress={() => handleLogout().catch(() => {})}
          disabled={busyAction === "logout"}
          style={styles.secondaryButton}
        >
          <Text style={styles.secondaryButtonText}>{busyAction === "logout" ? "Clearing..." : "Log out of this session"}</Text>
        </Pressable>
        <Pressable
          onPress={() => handleResetLocalState().catch(() => {})}
          disabled={busyAction === "reset-local-state"}
          style={styles.alertButton}
        >
          <Text style={styles.alertButtonText}>
            {busyAction === "reset-local-state" ? "Clearing..." : "Clear all local app state"}
          </Text>
        </Pressable>
      </View>

      {status ? <Text style={styles.status}>{status}</Text> : null}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flexGrow: 1,
    padding: 24,
    backgroundColor: "#f5f0e8",
    gap: 16
  },
  title: {
    marginTop: 24,
    color: "#1d1b19",
    fontSize: 30,
    fontWeight: "800"
  },
  body: {
    color: "#453f39",
    fontSize: 16,
    lineHeight: 24
  },
  card: {
    padding: 18,
    borderRadius: 18,
    backgroundColor: "#fffaf3",
    borderWidth: 1,
    borderColor: "#dbc8b8",
    gap: 10
  },
  cardTitle: {
    color: "#1d1b19",
    fontSize: 18,
    fontWeight: "700"
  },
  meta: {
    color: "#453f39",
    fontSize: 14,
    lineHeight: 20
  },
  input: {
    borderWidth: 1,
    borderColor: "#dbc8b8",
    borderRadius: 12,
    backgroundColor: "#fff",
    paddingHorizontal: 14,
    paddingVertical: 12,
    color: "#1d1b19",
    fontSize: 16
  },
  actions: {
    gap: 10
  },
  button: {
    paddingVertical: 14,
    paddingHorizontal: 16,
    borderRadius: 14,
    backgroundColor: "#1d1b19",
    alignItems: "center"
  },
  buttonText: {
    color: "#f8f3ec",
    fontSize: 16,
    fontWeight: "700"
  },
  secondaryButton: {
    paddingVertical: 14,
    paddingHorizontal: 16,
    borderRadius: 14,
    borderWidth: 1,
    borderColor: "#c89c86",
    backgroundColor: "#fff7f1",
    alignItems: "center"
  },
  secondaryButtonText: {
    color: "#8c3f2b",
    fontSize: 16,
    fontWeight: "700"
  },
  alertButton: {
    paddingVertical: 14,
    paddingHorizontal: 16,
    borderRadius: 14,
    backgroundColor: "#8c3f2b",
    alignItems: "center"
  },
  alertButtonText: {
    color: "#fff7f1",
    fontSize: 16,
    fontWeight: "700"
  },
  status: {
    color: "#8c3f2b",
    fontSize: 14,
    lineHeight: 20
  }
});
