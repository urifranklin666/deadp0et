import { useLocalSearchParams, useRouter } from "expo-router";
import { useEffect, useMemo, useState } from "react";
import { Pressable, ScrollView, StyleSheet, Text, TextInput, View } from "react-native";

import { encryptForRecipient } from "../src/lib/crypto";
import {
  loadComposeDrafts,
  loadConversationCache,
  saveComposeDrafts,
  saveConversationCache
} from "../src/lib/secure-storage";
import { loadStoredAuthState, createMobileApi } from "../src/lib/session";
import { assessMobileDeviceTrust, trustCurrentMobileDevice } from "../src/lib/trust";
import { normalizeUsername } from "@deadp0et/protocol-client";

type PrekeyBundle = {
  username: string;
  device: {
    deviceId: string;
    identityKey: JsonWebKey;
    signedPrekey: JsonWebKey;
    prekeySignature: string;
  };
  oneTimePrekey?: { keyId: string; key: JsonWebKey } | null;
  prekeyReservationToken: string;
};

type PendingTrust = {
  username: string;
  device: PrekeyBundle["device"];
  safetyNumber: string;
};

type ComposeDraft = {
  recipient: string;
  subject: string;
  body: string;
  updatedAt: string;
};

type ComposeDraftMap = Record<string, ComposeDraft>;

type CachedConversationMessage = {
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
  decryptedPayload?: {
    subject?: string;
    body?: string;
    sentAt?: string;
    senderDeviceId?: string;
  } | null;
  locallyReadAt?: string | null;
  localOnly?: boolean;
};

type ConversationCacheState = {
  selectedConversation?: string | null;
  messages: Record<string, CachedConversationMessage>;
};

function normalizeDrafts(raw: string | null): ComposeDraftMap {
  if (!raw) {
    return {};
  }

  try {
    const parsed = JSON.parse(raw) as ComposeDraftMap | null;
    return parsed || {};
  } catch {
    return {};
  }
}

function normalizeConversationCache(raw: string | null): ConversationCacheState {
  if (!raw) {
    return {
      selectedConversation: null,
      messages: {}
    };
  }

  try {
    const parsed = JSON.parse(raw) as ConversationCacheState | null;
    return {
      selectedConversation: parsed?.selectedConversation || null,
      messages: parsed?.messages || {}
    };
  } catch {
    return {
      selectedConversation: null,
      messages: {}
    };
  }
}

export default function ComposeScreen() {
  const router = useRouter();
  const params = useLocalSearchParams<{ recipient?: string }>();
  const routeRecipient = useMemo(
    () => (typeof params.recipient === "string" ? normalizeUsername(params.recipient) : ""),
    [params.recipient]
  );
  const [recipient, setRecipient] = useState(routeRecipient);
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const [lastEnvelope, setLastEnvelope] = useState<string>("");
  const [trustNote, setTrustNote] = useState<string | null>(null);
  const [pendingTrust, setPendingTrust] = useState<PendingTrust | null>(null);
  const [draftsLoaded, setDraftsLoaded] = useState(false);

  useEffect(() => {
    const normalizedRecipient = routeRecipient || normalizeUsername(recipient);

    loadComposeDrafts()
      .then((rawDrafts) => {
        const drafts = normalizeDrafts(rawDrafts);
        const activeDraft = normalizedRecipient ? drafts[normalizedRecipient] : null;

        if (routeRecipient) {
          setRecipient(routeRecipient);
        }
        if (activeDraft) {
          setSubject(activeDraft.subject || "");
          setBody(activeDraft.body || "");
        } else if (routeRecipient) {
          setSubject("");
          setBody("");
        }
      })
      .finally(() => {
        setDraftsLoaded(true);
      });
  }, [routeRecipient]);

  useEffect(() => {
    if (!draftsLoaded) {
      return;
    }

    const normalizedRecipient = normalizeUsername(recipient);
    const trimmedSubject = subject;
    const currentBody = body;

    loadComposeDrafts()
      .then((rawDrafts) => {
        const drafts = normalizeDrafts(rawDrafts);
        const nextDrafts = { ...drafts };

        if (!normalizedRecipient) {
          return saveComposeDrafts(JSON.stringify(nextDrafts));
        }

        if (!trimmedSubject.trim() && !currentBody.trim()) {
          delete nextDrafts[normalizedRecipient];
        } else {
          nextDrafts[normalizedRecipient] = {
            recipient: normalizedRecipient,
            subject: trimmedSubject,
            body: currentBody,
            updatedAt: new Date().toISOString()
          };
        }

        return saveComposeDrafts(JSON.stringify(nextDrafts));
      })
      .catch(() => {});
  }, [recipient, subject, body, draftsLoaded]);

  async function handleSend() {
    const to = normalizeUsername(recipient);
    const trimmedSubject = subject.trim();
    const trimmedBody = body.trim();

    if (!to || !trimmedSubject || !trimmedBody) {
      setStatus("Recipient, subject, and message body are required.");
      return;
    }

    setBusy(true);
    setStatus(`Reserving recipient prekey bundle for ${to}...`);
    setPendingTrust(null);
    setTrustNote(null);

    try {
      const auth = await loadStoredAuthState();
      if (!auth.hydratedDevice) {
        throw new Error("Saved local device keys could not be restored.");
      }
      if (to === normalizeUsername(auth.hydratedDevice.username)) {
        throw new Error("Send to a different account so the recipient bundle path is exercised.");
      }

      const api = createMobileApi(auth.apiBase, auth.session.accessToken);
      const prekeyBundle = await api.issuePrekeyBundle(to, {}) as PrekeyBundle;

      if (!prekeyBundle?.device?.deviceId) {
        throw new Error("Recipient has no active prekey bundle.");
      }

      const trust = await assessMobileDeviceTrust(prekeyBundle.username, prekeyBundle.device);
      setTrustNote(`Safety number: ${trust.safetyNumber}. ${trust.note}`);
      if (!trust.trusted) {
        setPendingTrust({
          username: prekeyBundle.username,
          device: prekeyBundle.device,
          safetyNumber: trust.safetyNumber
        });
        throw new Error(
          `Recipient device keys changed for ${prekeyBundle.device.deviceId}. Review the safety number and trust the current device keys before sending.`
        );
      }

      const envelope = await encryptForRecipient({
        senderUsername: auth.hydratedDevice.username,
        senderDeviceId: auth.hydratedDevice.publicBundle.deviceId,
        recipientBundle: prekeyBundle,
        subject: trimmedSubject,
        body: trimmedBody
      });

      const stored = await api.storeMessage({
        to: prekeyBundle.username,
        recipientDeviceId: prekeyBundle.device.deviceId,
        envelope: {
          protocol: envelope.protocol,
          ephemeralKey: envelope.ephemeralKey,
          iv: envelope.iv,
          ciphertext: envelope.ciphertext,
          oneTimePrekeyId: envelope.oneTimePrekeyId,
          prekeyReservationToken: envelope.prekeyReservationToken
        }
      });

      setLastEnvelope(JSON.stringify({
        ...envelope,
        messageId: stored.messageId,
        storedAt: stored.storedAt
      }, null, 2));
      setStatus(
        envelope.oneTimePrekeyId
          ? `Encrypted envelope stored for ${prekeyBundle.username} on ${prekeyBundle.device.deviceId} using one-time prekey ${envelope.oneTimePrekeyId}.`
          : `Encrypted envelope stored for ${prekeyBundle.username} on ${prekeyBundle.device.deviceId}.`
      );

      const rawConversationCache = await loadConversationCache();
      const conversationCache = normalizeConversationCache(rawConversationCache);
      const sentAt = new Date().toISOString();
      const localMessageId = `local-sent:${stored.messageId}`;
      const nextMessages = {
        ...(conversationCache.messages || {}),
        [localMessageId]: {
          messageId: localMessageId,
          from: prekeyBundle.username,
          recipientDeviceId: prekeyBundle.device.deviceId,
          storedAt: stored.storedAt || sentAt,
          deliveredAt: sentAt,
          readAt: sentAt,
          deliveryCount: 1,
          envelope: {
            protocol: envelope.protocol,
            ephemeralKey: envelope.ephemeralKey,
            iv: envelope.iv,
            ciphertext: envelope.ciphertext,
            oneTimePrekeyId: envelope.oneTimePrekeyId
          },
          decryptedPayload: {
            subject: trimmedSubject,
            body: trimmedBody,
            sentAt,
            senderDeviceId: auth.hydratedDevice.publicBundle.deviceId
          },
          locallyReadAt: sentAt,
          localOnly: true
        }
      };
      await saveConversationCache(JSON.stringify({
        selectedConversation: prekeyBundle.username,
        messages: nextMessages
      }));

      const rawDrafts = await loadComposeDrafts();
      const drafts = normalizeDrafts(rawDrafts);
      delete drafts[to];
      await saveComposeDrafts(JSON.stringify(drafts));
      setPendingTrust(null);
      setSubject("");
      setBody("");
      router.replace("/inbox");
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Unable to send the encrypted envelope.");
    } finally {
      setBusy(false);
    }
  }

  async function handleTrustCurrentDevice() {
    if (!pendingTrust) {
      return;
    }

    setBusy(true);
    setStatus(`Trusting current device keys for ${pendingTrust.username}...`);

    try {
      const trusted = await trustCurrentMobileDevice(pendingTrust.username, pendingTrust.device);
      setTrustNote(`Safety number: ${trusted.safetyNumber}. Current device keys are now trusted.`);
      setPendingTrust(null);
      setStatus(`Trusted current keys for ${pendingTrust.username} on device ${pendingTrust.device.deviceId}. Send again to continue.`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Unable to trust the current device keys.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <Text style={styles.eyebrow}>deadp0et mobile</Text>
      <Text style={styles.title}>Compose</Text>
      <Text style={styles.description}>
        This screen reserves a recipient prekey bundle, encrypts the payload locally on the phone, and stores the
        ciphertext envelope through the existing backend message API.
      </Text>

      <View style={styles.card}>
        <Text style={styles.label}>Recipient username</Text>
        <TextInput value={recipient} onChangeText={setRecipient} autoCapitalize="none" style={styles.input} />
        <Text style={styles.label}>Subject</Text>
        <TextInput value={subject} onChangeText={setSubject} style={styles.input} />
        <Text style={styles.label}>Message body</Text>
        <TextInput
          value={body}
          onChangeText={setBody}
          multiline
          textAlignVertical="top"
          style={[styles.input, styles.bodyInput]}
        />
      </View>

      <View style={styles.actions}>
        <Pressable onPress={() => handleSend().catch(() => {})} disabled={busy} style={styles.button}>
          <Text style={styles.buttonText}>{busy ? "Encrypting..." : "Encrypt and send"}</Text>
        </Pressable>
        <Pressable onPress={() => router.replace("/inbox")} style={styles.secondaryButton}>
          <Text style={styles.secondaryButtonText}>Back to inbox</Text>
        </Pressable>
      </View>

      {status ? <Text style={styles.status}>{status}</Text> : null}
      {trustNote ? <Text style={styles.status}>{trustNote}</Text> : null}

      {pendingTrust ? (
        <View style={styles.card}>
          <Text style={styles.sectionTitle}>Trust check required</Text>
          <Text style={styles.detail}>Recipient: {pendingTrust.username}</Text>
          <Text style={styles.detail}>Device: {pendingTrust.device.deviceId}</Text>
          <Text style={styles.detail}>Safety number: {pendingTrust.safetyNumber}</Text>
          <Pressable onPress={() => handleTrustCurrentDevice().catch(() => {})} disabled={busy} style={styles.secondaryButton}>
            <Text style={styles.secondaryButtonText}>Trust current device keys</Text>
          </Pressable>
        </View>
      ) : null}

      {lastEnvelope ? (
        <View style={styles.card}>
          <Text style={styles.sectionTitle}>Last envelope</Text>
          <Text style={styles.output}>{lastEnvelope}</Text>
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
    backgroundColor: "#0a0a0a"
  },
  eyebrow: {
    marginTop: 24,
    color: "#cc0000",
    fontSize: 14,
    fontWeight: "700",
    letterSpacing: 1.2,
    textTransform: "uppercase",
    fontFamily: "Courier"
  },
  title: {
    color: "#f5f5f5",
    fontSize: 30,
    fontWeight: "800",
    lineHeight: 36
  },
  description: {
    color: "#b0b0b0",
    fontSize: 16,
    lineHeight: 24
  },
  card: {
    padding: 18,
    borderRadius: 18,
    backgroundColor: "#111111",
    borderWidth: 1,
    borderColor: "#2a0000",
    gap: 8
  },
  label: {
    color: "#f5f5f5",
    fontSize: 15,
    fontWeight: "700",
    fontFamily: "Courier"
  },
  input: {
    borderWidth: 1,
    borderColor: "#4d0000",
    borderRadius: 12,
    backgroundColor: "#0e0e0e",
    paddingHorizontal: 14,
    paddingVertical: 12,
    color: "#e0e0e0",
    fontSize: 16
  },
  bodyInput: {
    minHeight: 140
  },
  actions: {
    gap: 12
  },
  button: {
    paddingVertical: 14,
    paddingHorizontal: 16,
    borderRadius: 14,
    backgroundColor: "#cc0000",
    alignItems: "center"
  },
  buttonText: {
    color: "#ffffff",
    fontSize: 16,
    fontWeight: "700"
  },
  secondaryButton: {
    paddingVertical: 14,
    paddingHorizontal: 16,
    borderRadius: 14,
    borderWidth: 1,
    borderColor: "#4d0000",
    backgroundColor: "#111111",
    alignItems: "center"
  },
  secondaryButtonText: {
    color: "#cc0000",
    fontSize: 16,
    fontWeight: "700"
  },
  status: {
    color: "#ff2222",
    fontSize: 14,
    lineHeight: 20
  },
  detail: {
    color: "#b0b0b0",
    fontSize: 14,
    lineHeight: 20
  },
  sectionTitle: {
    color: "#f5f5f5",
    fontSize: 18,
    fontWeight: "700",
    fontFamily: "Courier"
  },
  output: {
    color: "#b0b0b0",
    fontSize: 12,
    lineHeight: 18,
    fontFamily: "monospace"
  }
});
