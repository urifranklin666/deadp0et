import { Link, useFocusEffect, useRouter } from "expo-router";
import { useCallback, useMemo, useState } from "react";
import { Pressable, ScrollView, StyleSheet, Text, View } from "react-native";
import { consumeLocalOneTimePrekeyRecord } from "@deadp0et/protocol-client";

import { decryptEnvelope } from "../src/lib/crypto";
import {
  clearConversationCache,
  clearLocalDevice,
  clearSession,
  loadConversationCache,
  loadLocalDevice,
  saveConversationCache,
  saveLocalDevice
} from "../src/lib/secure-storage";
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

type DecryptedPayload = {
  subject?: string;
  body?: string;
  sentAt?: string;
  senderDeviceId?: string;
};

type CachedConversationMessage = {
  messageId: string;
  from: string;
  recipientDeviceId: string;
  storedAt: string;
  deliveredAt: string | null;
  readAt: string | null;
  deliveryCount: number;
  envelope?: InboxMessage["envelope"];
  decryptedPayload?: DecryptedPayload | null;
  locallyReadAt?: string | null;
};

type Conversation = {
  correspondent: string;
  latestStoredAt: string;
  unreadCount: number;
  messages: CachedConversationMessage[];
};

type ConversationCacheState = {
  selectedConversation?: string | null;
  messages: Record<string, CachedConversationMessage>;
};

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

export default function InboxScreen() {
  const router = useRouter();
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const [messages, setMessages] = useState<InboxMessage[]>([]);
  const [cachedMessages, setCachedMessages] = useState<Record<string, CachedConversationMessage>>({});
  const [sessionInfo, setSessionInfo] = useState<StoredSessionEnvelope["session"] | null>(null);
  const [apiBase, setApiBase] = useState("");
  const [username, setUsername] = useState("");
  const [selectedConversation, setSelectedConversation] = useState<string | null>(null);

  const persistConversationCache = useCallback(async (
    nextMessages: Record<string, CachedConversationMessage>,
    nextSelectedConversation: string | null
  ) => {
    await saveConversationCache(JSON.stringify({
      selectedConversation: nextSelectedConversation,
      messages: nextMessages
    }));
  }, []);

  const restoreAndFetch = useCallback(async () => {
    setLoading(true);
    setStatus("Restoring local mobile session...");

    try {
      const cacheState = normalizeConversationCache(await loadConversationCache());
      const auth = await loadStoredAuthState();
      setApiBase(auth.apiBase);
      setSessionInfo(auth.session);
      setUsername(auth.localDeviceRecord.username || "");
      setSelectedConversation((current) => current || cacheState.selectedConversation || null);

      const api = createMobileApi(auth.apiBase, auth.session.accessToken);
      const payload = await api.getInbox();
      const liveMessages = Array.isArray(payload.messages) ? payload.messages : [];
      const mergedMessages: Record<string, CachedConversationMessage> = {
        ...(cacheState.messages || {})
      };

      for (const message of liveMessages) {
        const existing = mergedMessages[message.messageId];
        mergedMessages[message.messageId] = {
          ...existing,
          ...message,
          decryptedPayload: existing?.decryptedPayload || null,
          locallyReadAt: existing?.locallyReadAt || null
        };
      }

      setMessages(liveMessages);
      setCachedMessages(mergedMessages);
      await persistConversationCache(
        mergedMessages,
        selectedConversation || cacheState.selectedConversation || null
      );
      setStatus(
        liveMessages.length
          ? `Loaded ${liveMessages.length} encrypted message(s) for ${payload.deviceId}.`
          : `No encrypted messages are queued for ${payload.deviceId}.`
      );
    } catch (error) {
      setMessages([]);
      setCachedMessages({});
      setSessionInfo(null);
      setUsername("");
      setSelectedConversation(null);
      setStatus(error instanceof Error ? error.message : "Unable to restore the mobile inbox.");
    } finally {
      setLoading(false);
    }
  }, [persistConversationCache, selectedConversation]);

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
    await clearConversationCache();
    setMessages([]);
    setCachedMessages({});
    setSessionInfo(null);
    setUsername("");
    setSelectedConversation(null);
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

      const nextCachedMessages = {
        ...cachedMessages,
        [message.messageId]: {
          ...(cachedMessages[message.messageId] || message),
          ...message,
          decryptedPayload: decrypted.payload,
          locallyReadAt: new Date().toISOString(),
          readAt: new Date().toISOString()
        }
      };
      setCachedMessages(nextCachedMessages);
      await persistConversationCache(nextCachedMessages, selectedConversation);
      await restoreAndFetch();
      setStatus(
        decrypted.oneTimePrekeyId
          ? `Decrypted ${message.messageId} and acknowledged one-time prekey ${decrypted.oneTimePrekeyId}.`
          : `Decrypted ${message.messageId}.`
      );
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Unable to decrypt the selected envelope.");
    }
  }

  const conversations = useMemo<Conversation[]>(() => {
    const grouped = new Map<string, CachedConversationMessage[]>();
    for (const message of Object.values(cachedMessages)) {
      const key = message.from || "unknown";
      const bucket = grouped.get(key) || [];
      bucket.push(message);
      grouped.set(key, bucket);
    }

    return Array.from(grouped.entries())
      .map(([correspondent, conversationMessages]) => {
        const sortedMessages = [...conversationMessages].sort(
          (left, right) => new Date(right.storedAt).getTime() - new Date(left.storedAt).getTime()
        );
        return {
          correspondent,
          latestStoredAt: sortedMessages[0]?.storedAt || "",
          unreadCount: sortedMessages.filter((message) => !message.locallyReadAt && !message.readAt).length,
          messages: sortedMessages
        };
      })
      .sort((left, right) => new Date(right.latestStoredAt).getTime() - new Date(left.latestStoredAt).getTime());
  }, [cachedMessages]);

  const activeConversation = conversations.find((conversation) => conversation.correspondent === selectedConversation)
    || conversations[0]
    || null;

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <Text style={styles.eyebrow}>deadp0et mobile</Text>
      <Text style={styles.title}>Inbox</Text>
      <Text style={styles.description}>
        Conversations are grouped by correspondent and styled against the same black-and-red shell as the site. Open a
        thread, decrypt the messages addressed to this device, and jump straight into a reply.
      </Text>

      <View style={styles.card}>
        <Text style={styles.sectionTitle}>Session</Text>
        <Text style={styles.meta}>Backend: {apiBase}</Text>
        <Text style={styles.meta}>Username: {username || "unknown"}</Text>
        <Text style={styles.meta}>Device: {sessionInfo?.deviceId || "not loaded"}</Text>
        <Text style={styles.meta}>Expires: {sessionInfo?.expiresAt || "unknown"}</Text>
        <Text style={styles.meta}>Threads: {conversations.length}</Text>
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
        <Text style={styles.sectionTitle}>Conversations</Text>
        {!conversations.length ? <Text style={styles.empty}>No encrypted conversations loaded.</Text> : null}
        <View style={styles.threadList}>
          {conversations.map((conversation) => (
            <Pressable
              key={conversation.correspondent}
              onPress={() => {
                setSelectedConversation(conversation.correspondent);
                persistConversationCache(cachedMessages, conversation.correspondent).catch(() => {});
              }}
              style={[
                styles.threadRow,
                activeConversation?.correspondent === conversation.correspondent ? styles.threadRowActive : null
              ]}
            >
              <View style={styles.threadAvatar}>
                <Text style={styles.threadAvatarText}>{conversation.correspondent.slice(0, 1).toUpperCase()}</Text>
              </View>
              <View style={styles.threadBody}>
                <Text style={styles.threadName}>{conversation.correspondent}</Text>
                <Text style={styles.threadMeta}>
                  {conversation.messages.length} message(s) · {conversation.unreadCount} unread
                </Text>
              </View>
              <Text style={styles.threadTime}>{new Date(conversation.latestStoredAt).toLocaleDateString()}</Text>
            </Pressable>
          ))}
        </View>
      </View>

      {activeConversation ? (
        <View style={styles.card}>
          <View style={styles.threadHeader}>
            <View>
              <Text style={styles.sectionTitle}>{activeConversation.correspondent}</Text>
              <Text style={styles.meta}>{activeConversation.messages.length} message(s) in thread</Text>
            </View>
            <Pressable
              onPress={() => router.push({ pathname: "/compose", params: { recipient: activeConversation.correspondent } })}
              style={styles.replyButton}
            >
              <Text style={styles.replyButtonText}>Reply</Text>
            </Pressable>
          </View>

          {activeConversation.messages.map((message) => {
            const decrypted = message.decryptedPayload || null;
            const messageState = message.readAt
              ? "acknowledged"
              : message.locallyReadAt
                ? "locally read"
                : "unread";
            return (
              <View key={message.messageId} style={styles.messageBubble}>
                <Text style={styles.messageFrom}>{message.from}</Text>
                <Text style={styles.messageMeta}>
                  {new Date(message.storedAt).toLocaleString()} · {messageState}
                </Text>
                {decrypted ? (
                  <>
                    <Text style={styles.messageSubject}>{decrypted.subject || "(no subject)"}</Text>
                    <Text style={styles.messageBody}>{decrypted.body || ""}</Text>
                    <Text style={styles.messageMeta}>Sender device: {decrypted.senderDeviceId || "unknown"}</Text>
                  </>
                ) : (
                  <>
                    <Text style={styles.messageCipherLabel}>Encrypted envelope</Text>
                    <Text style={styles.messageMeta}>Protocol: {message.envelope?.protocol || "unknown"}</Text>
                    <Pressable onPress={() => handleDecrypt(message).catch(() => {})} style={styles.decryptButton}>
                      <Text style={styles.decryptButtonText}>Decrypt and acknowledge</Text>
                    </Pressable>
                  </>
                )}
              </View>
            );
          })}
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
  sectionTitle: {
    color: "#f5f5f5",
    fontSize: 18,
    fontWeight: "700",
    fontFamily: "Courier"
  },
  meta: {
    color: "#9a9a9a",
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
  empty: {
    color: "#666666",
    fontSize: 15
  },
  threadList: {
    gap: 6
  },
  threadRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: 12,
    padding: 14,
    borderRadius: 14,
    backgroundColor: "#0e0e0e",
    borderWidth: 1,
    borderColor: "#2a0000"
  },
  threadRowActive: {
    borderColor: "#cc0000",
    backgroundColor: "#1a0000"
  },
  threadAvatar: {
    width: 42,
    height: 42,
    borderRadius: 21,
    backgroundColor: "#330000",
    borderWidth: 1,
    borderColor: "#4d0000",
    alignItems: "center",
    justifyContent: "center"
  },
  threadAvatarText: {
    color: "#ffffff",
    fontSize: 18,
    fontWeight: "700",
    fontFamily: "Courier"
  },
  threadBody: {
    flex: 1,
    gap: 2
  },
  threadName: {
    color: "#f5f5f5",
    fontSize: 16,
    fontWeight: "700"
  },
  threadTime: {
    color: "#666666",
    fontSize: 12,
    fontFamily: "Courier"
  },
  threadMeta: {
    color: "#9a9a9a",
    fontSize: 13
  },
  threadHeader: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    gap: 12
  },
  replyButton: {
    paddingVertical: 10,
    paddingHorizontal: 14,
    borderRadius: 999,
    borderWidth: 1,
    borderColor: "#cc0000",
    backgroundColor: "#1a0000"
  },
  replyButtonText: {
    color: "#ffffff",
    fontSize: 13,
    fontWeight: "700",
    fontFamily: "Courier"
  },
  messageBubble: {
    padding: 14,
    marginTop: 6,
    borderRadius: 14,
    backgroundColor: "#0e0e0e",
    borderWidth: 1,
    borderColor: "#2a0000",
    gap: 6
  },
  decryptButton: {
    marginTop: 8,
    paddingVertical: 10,
    paddingHorizontal: 12,
    borderRadius: 12,
    backgroundColor: "#1a0000",
    borderWidth: 1,
    borderColor: "#4d0000",
    alignItems: "center"
  },
  decryptButtonText: {
    color: "#ff2222",
    fontSize: 14,
    fontWeight: "700",
    fontFamily: "Courier"
  },
  messageFrom: {
    color: "#f5f5f5",
    fontSize: 15,
    fontWeight: "700"
  },
  messageSubject: {
    color: "#ffffff",
    fontSize: 16,
    fontWeight: "700"
  },
  messageBody: {
    color: "#d6d6d6",
    fontSize: 15,
    lineHeight: 22
  },
  messageCipherLabel: {
    color: "#cc0000",
    fontSize: 13,
    fontWeight: "700",
    fontFamily: "Courier"
  },
  messageMeta: {
    color: "#888888",
    fontSize: 13,
    lineHeight: 18
  }
});
