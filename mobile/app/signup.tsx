import { Link, useRouter } from "expo-router";
import { useState } from "react";
import { Pressable, StyleSheet, Text } from "react-native";

import { AuthForm } from "../src/components/auth-form";
import { AuthScreen } from "../src/components/auth-screen";
import { MOBILE_DEFAULTS } from "../src/lib/config";
import { generateDeviceBundle, serializeMobileDeviceRecord, sha256 } from "../src/lib/crypto";
import { saveLocalDevice, saveSession } from "../src/lib/secure-storage";
import { createMobileApi } from "../src/lib/session";
import { normalizeUsername } from "@deadp0et/protocol-client";

export default function SignupScreen() {
  const router = useRouter();
  const [apiBase, setApiBase] = useState(MOBILE_DEFAULTS.apiBase);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<string | null>(null);

  async function handleSignup() {
    const normalizedUsername = normalizeUsername(username);
    const trimmedPassword = password.trim();

    if (!normalizedUsername || !trimmedPassword) {
      setStatus("Username and password are required.");
      return;
    }

    setBusy(true);
    setStatus("Creating account and registering the first mobile device...");

    try {
      const api = createMobileApi(apiBase, null);
      const deviceBundle = await generateDeviceBundle();
      const passwordVerifier = await sha256(trimmedPassword);

      const payload = await api.createAccount({
        username: normalizedUsername,
        passwordVerifier,
        device: deviceBundle.publicBundle
      });

      const localDevice = await serializeMobileDeviceRecord({
        username: normalizedUsername,
        passwordVerifier,
        accountId: payload.accountId,
        deviceBundle
      });

      await saveSession(JSON.stringify({
        apiBase,
        session: payload.session
      }));
      await saveLocalDevice(JSON.stringify(localDevice));

      setStatus(`Account ${payload.username} created for device ${payload.session.deviceId}.`);
      router.replace("/inbox");
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Unable to create account.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthScreen
      title="Create account"
      description="This screen generates real local device keys with WebCrypto, registers the first device against the live backend, and stores the serialized mobile device record securely on the phone."
      footer={
        <Link href="/login" asChild>
          <Pressable>
            <Text style={styles.link}>Already have an account? Log in.</Text>
          </Pressable>
        </Link>
      }
    >
      <AuthForm
        apiBase={apiBase}
        busy={busy}
        buttonLabel="Create account"
        helper="Account creation now generates a real ECDH identity, signed prekey, and one-time prekey batch before registering this device."
        password={password}
        setApiBase={setApiBase}
        setPassword={setPassword}
        setUsername={setUsername}
        status={status}
        username={username}
        onSubmit={() => {
          handleSignup().catch(() => {});
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
