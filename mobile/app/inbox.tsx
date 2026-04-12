import { Link, useFocusEffect, useRouter } from "expo-router";
import { useCallback, useState } from "react";
import { Pressable, ScrollView, StyleSheet, Text, View } from "react-native";
import { consumeLocalOneTimePrekeyRecord } from "@deadp0et/protocol-client";

import { decryptEnvelope } from "../src/lib/crypto";
import { clearLocalDevice, clearSession, loadLocalDevice, saveLocalDevice } from "../src/lib/secure-storage";
import { createMobileApi, loadStoredAuthState, type StoredSessionEnvelope } from "../src/lib/session";

type InboxMessage = {
  messageId: string;
  from: string;
  recipientDeviceId: string;
  storedAt: string;
  deliveredAt: string | null;
  readAt: string | null;
  deliveryCount: number;
  envelope?: {
    protocol?: string;
    ephemeralKey: JsonWebKey;
    iv: string;
    ciphertext: string;
    oneTimePrekeyId?: string | null;
  };
};

export default function InboxScreen() {
  const router = useRouter();
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const [messages, setMessages] = useState<InboxMessage[]>([]);
  const [sessionInfo, setSessionInfo] = useState<StoredSessionEnvelope["session"] | null>(null);
  const [apiBase, setApiBase] = useState("");
  const [username, setUsername] = useState("");
  const [plaintext, setPlaintext] = useState<string | null>(null);

  const restoreAndFetch = useCallback(async () => {
    setLoading(true);
    setStatus("Restoring local mobile session...");

    try {
      const auth = await loadStoredAuthState();
      setApiBase(auth.apiBase);
      setSessionInfo(auth.session);
      setUsername(auth.localDeviceRecord.username || "");

      const api = createMobileApi(auth.apiBase, auth.session.accessToken);
      const payload = await api.getInbox();

      setMessages(Array.isArray(payload.messages) ? payload.messages : []);
      setStatus(
        Array.isArray(payload.messages) && payload.messages.length
          ? `Loaded ${payload.messages.length} encrypted message(s) for ${payload.deviceId}.`
          : `No encrypted messages are queued for ${payload.deviceId}.`
      );
    } catch (error) {
      setMessages([]);
      setSessionInfo(null);
      setUsername("");
      setPlaintext(null);
      setStatus(error instanceof Error ? error.message : "Unable to restore the mobile inbox.");
    } finally {
      setLoading(false);
    }
  }, []);

  useFocusEffect(
    useCallback(() => {
      restoreAndFetch().catch(() => {});
    }, [restoreAndFetch])
  );

  async function handleRefresh() {
    setRefreshing(true);
    await restoreAndFetch();
    setRefreshing(false);
  }

  async function handleClearAndExit() {
    await clearSession();
    await clearLocalDevice();
    setMessages([]);
    setSessionInfo(null);
    setUsername("");
    setPlaintext(null);
    router.replace("/login");
  }

  async function handleDecrypt(message: InboxMessage) {
    setStatus(`Decrypting ${message.messageId} locally...`);

    try {
      const auth = await loadStoredAuthState();
      if (!auth.hydratedDevice) {
        throw new Error("Saved local device keys could not be restored.");
      }
      if (!message.envelope) {
        throw new Error("Selected inbox message is missing an envelope payload.");
      }

      const decrypted = await decryptEnvelope({
        privateKeys: auth.hydratedDevice.privateKeys,
        envelope: {
          ephemeralKey: message.envelope.ephemeralKey,
          iv: message.envelope.iv,
          ciphertext: message.envelope.ciphertext,
          oneTimePrekeyId: message.envelope.oneTimePrekeyId
        }
      });

      const api = createMobileApi(auth.apiBase, auth.session.accessToken);
      const ackPayload: {
        messageIds: string[];
        oneTimePrekeyProofs?: Array<{ messageId: string; oneTimePrekeyId: string }>;
      } = {
        messageIds: [message.messageId]
      };

      if (decrypted.oneTimePrekeyId) {
        ackPayload.oneTimePrekeyProofs = [{
          messageId: message.messageId,
          oneTimePrekeyId: decrypted.oneTimePrekeyId
        }];
      }

      await api.acknowledgeInbox(ackPayload);

      if (decrypted.oneTimePrekeyId) {
        const rawLocalDevice = await loadLocalDevice();
        if (rawLocalDevice) {
          const parsedRecord = JSON.parse(rawLocalDevice);
          const nextRecord = consumeLocalOneTimePrekeyRecord(parsedRecord, decrypted.oneTimePrekeyId);
          if (nextRecord) {
            await saveLocalDevice(JSON.stringify(nextRecord));
          }
        }
      }

      await restoreAndFetch();
      setPlaintext(JSON.stringify(decrypted.payload, null, 2));
      setStatus(
        decrypted.oneTimePrekeyId
          ? `Decrypted ${message.messageId} and acknowledged one-time prekey ${decrypted.oneTimePrekeyId}.`
          : `Decrypted ${message.messageId}.`
      );
    } catch (error) {
      setPlaintext(null);
      setStatus(error instanceof Error ? error.message : "Unable to decrypt the selected envelope.");
    }
  }

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <Text style={styles.eyebrow}>deadp0et mobile</Text>
      <Text style={styles.title}>Inbox</Text>
      <Text style={styles.description}>
        This screen restores the saved mobile session and local device record from secure storage, then fetches
        device-scoped inbox state from the backend.
      </Text>

      <View style={styles.card}>
        <Text style={styles.sectionTitle}>Session</Text>
        <Text style={styles.meta}>Backend: {apiBase}</Text>
        <Text style={styles.meta}>Username: {username || "unknown"}</Text>
        <Text style={styles.meta}>Device: {sessionInfo?.deviceId || "not loaded"}</Text>
        <Text style={styles.meta}>Expires: {sessionInfo?.expiresAt || "unknown"}</Text>
      </View>

      <View style={styles.actions}>
        <Pressable onPress={() => handleRefresh().catch(() => {})} disabled={loading || refreshing} style={styles.button}>
          <Text style={styles.buttonText}>{loading || refreshing ? "Refreshing..." : "Refresh inbox"}</Text>
        </Pressable>
        <Link href="/compose" asChild>
          <Pressable style={styles.button}>
            <Text style={styles.buttonText}>Compose message</Text>
          </Pressable>
        </Link>
        <Pressable onPress={() => handleClearAndExit().catch(() => {})} style={styles.secondaryButton}>
          <Text style={styles.secondaryButtonText}>Clear local auth</Text>
        </Pressable>
      </View>

      {status ? <Text style={styles.status}>{status}</Text> : null}

      <View style={styles.card}>
        <Text style={styles.sectionTitle}>Messages</Text>
        {!messages.length ? <Text style={styles.empty}>No encrypted envelopes loaded.</Text> : null}
        {messages.map((message) => (
          <View key={message.messageId} style={styles.messageCard}>
            <Text style={styles.messageFrom}>From: {message.from}</Text>
            <Text style={styles.messageMeta}>Message: {message.messageId}</Text>
            <Text style={styles.messageMeta}>Stored: {message.storedAt}</Text>
            <Text style={styles.messageMeta}>Read: {message.readAt || "not yet"}</Text>
            <Text style={styles.messageMeta}>Deliveries: {message.deliveryCount}</Text>
            <Text style={styles.messageMeta}>Protocol: {message.envelope?.protocol || "unknown"}</Text>
            <Pressable onPress={() => handleDecrypt(message).catch(() => {})} style={styles.decryptButton}>
              <Text style={styles.decryptButtonText}>Decrypt and acknowledge</Text>
            </Pressable>
          </View>
        ))}
      </View>

      {plaintext ? (
        <View style={styles.card}>
          <Text style={styles.sectionTitle}>Decrypted payload</Text>
          <Text style={styles.output}>{plaintext}</Text>
        </View>
      ) : null}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flexGrow: 1,
    padding: 24,
    gap: 18,
    backgroundColor: "#f5f0e8"
  },
  eyebrow: {
    marginTop: 24,
    color: "#8c3f2b",
    fontSize: 14,
    fontWeight: "700",
    letterSpacing: 1.2,
    textTransform: "uppercase"
  },
  title: {
    color: "#1d1b19",
    fontSize: 30,
    fontWeight: "800",
    lineHeight: 36
  },
  description: {
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
    gap: 8
  },
  sectionTitle: {
    color: "#1d1b19",
    fontSize: 18,
    fontWeight: "700"
  },
  meta: {
    color: "#453f39",
    fontSize: 14,
    lineHeight: 20
  },
  actions: {
    gap: 12
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
  status: {
    color: "#8c3f2b",
    fontSize: 14,
    lineHeight: 20
  },
  empty: {
    color: "#6b6158",
    fontSize: 15
  },
  messageCard: {
    paddingTop: 12,
    marginTop: 4,
    borderTopWidth: 1,
    borderTopColor: "#e5d6ca",
    gap: 4
  },
  decryptButton: {
    marginTop: 8,
    paddingVertical: 10,
    paddingHorizontal: 12,
    borderRadius: 12,
    backgroundColor: "#efe0d4",
    alignItems: "center"
  },
  decryptButtonText: {
    color: "#8c3f2b",
    fontSize: 14,
    fontWeight: "700"
  },
  messageFrom: {
    color: "#1d1b19",
    fontSize: 15,
    fontWeight: "700"
  },
  messageMeta: {
    color: "#453f39",
    fontSize: 13,
    lineHeight: 18
  },
  output: {
    color: "#453f39",
    fontSize: 12,
    lineHeight: 18,
    fontFamily: "monospace"
  }
});
