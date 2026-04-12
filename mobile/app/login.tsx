import { Link, useRouter } from "expo-router";
import { useState } from "react";
import { Pressable, StyleSheet, Text } from "react-native";

import { AuthForm } from "../src/components/auth-form";
import { AuthScreen } from "../src/components/auth-screen";
import { MOBILE_DEFAULTS } from "../src/lib/config";
import { sha256 } from "../src/lib/crypto";
import { loadLocalDevice, loadPreferredApiBase, savePreferredApiBase, saveSession } from "../src/lib/secure-storage";
import { createMobileApi } from "../src/lib/session";
import { normalizeUsername } from "@deadp0et/protocol-client";
import { useEffect } from "react";

export default function LoginScreen() {
  const router = useRouter();
  const [apiBase, setApiBase] = useState(MOBILE_DEFAULTS.apiBase);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<string | null>(null);

  useEffect(() => {
    loadPreferredApiBase()
      .then((storedApiBase) => {
        if (storedApiBase) {
          setApiBase(storedApiBase);
        }
      })
      .catch(() => {});
  }, []);

  async function handleLogin() {
    const normalizedUsername = normalizeUsername(username);
    const trimmedPassword = password.trim();

    if (!normalizedUsername || !trimmedPassword) {
      setStatus("Username and password are required.");
      return;
    }

    setBusy(true);
    setStatus("Authenticating with the backend...");

    try {
      const rawLocalDevice = await loadLocalDevice();
      if (!rawLocalDevice) {
        throw new Error("No local device record is stored on this phone yet. Create or import a device first.");
      }

      const localDevice = JSON.parse(rawLocalDevice);
      const passwordVerifier = await sha256(trimmedPassword);

      if (normalizeUsername(localDevice.username) !== normalizedUsername) {
        throw new Error("Stored local device belongs to a different username.");
      }

      if (localDevice.passwordVerifier !== passwordVerifier) {
        throw new Error("Password does not match the verifier stored for this local device.");
      }

      const api = createMobileApi(apiBase, null);
      const payload = await api.createSession({
        username: normalizedUsername,
        passwordVerifier,
        deviceId: localDevice.deviceId
      });

      await saveSession(JSON.stringify({
        apiBase,
        session: payload.session
      }));
      await savePreferredApiBase(apiBase);
      setStatus(`Signed in as ${payload.username} on device ${payload.session.deviceId}.`);
      router.replace("/inbox");
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Unable to log in.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthScreen
      title="Log in"
      description="This screen authenticates against the live backend and restores the active session for the local device stored on this phone."
      footer={
        <Link href="/signup" asChild>
          <Pressable>
            <Text style={styles.link}>Need a new account? Create one.</Text>
          </Pressable>
        </Link>
      }
    >
      <AuthForm
        apiBase={apiBase}
        busy={busy}
        buttonLabel="Log in"
        helper="Login uses the password verifier for the serialized local device record already stored on this phone."
        password={password}
        setApiBase={setApiBase}
        setPassword={setPassword}
        setUsername={setUsername}
        status={status}
        username={username}
        onSubmit={() => {
          handleLogin().catch(() => {});
        }}
      />
    </AuthScreen>
  );
}

const styles = StyleSheet.create({
  link: {
    color: "#8c3f2b",
    fontSize: 15,
    fontWeight: "700"
  }
});
