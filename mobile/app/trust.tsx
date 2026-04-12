import { useFocusEffect } from "expo-router";
import { useCallback, useState } from "react";
import { Pressable, ScrollView, StyleSheet, Text, View } from "react-native";

import { createMobileApi, loadStoredAuthState } from "../src/lib/session";
import {
  assessMobileDeviceTrust,
  loadMobileTrustRecords,
  removeMobileTrustRecord,
  trustCurrentMobileDevice,
  type StoredTrustRecord
} from "../src/lib/trust";

type BundleDevice = {
  deviceId: string;
  identityKey: JsonWebKey;
  signedPrekey: JsonWebKey;
  prekeySignature: string;
};

type BundlePayload = {
  username: string;
  devices: BundleDevice[];
};

export default function TrustScreen() {
  const [records, setRecords] = useState<StoredTrustRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);

  const loadRecords = useCallback(async () => {
    setLoading(true);
    try {
      const nextRecords = await loadMobileTrustRecords();
      setRecords(nextRecords);
      setStatus(
        nextRecords.length
          ? `Loaded ${nextRecords.length} saved trust record(s).`
          : "No saved trust records yet. Records appear after bundle checks and sends."
      );
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Unable to load trust records.");
    } finally {
      setLoading(false);
    }
  }, []);

  useFocusEffect(
    useCallback(() => {
      loadRecords().catch(() => {});
    }, [loadRecords])
  );

  async function fetchCurrentDevice(record: StoredTrustRecord) {
    const auth = await loadStoredAuthState();
    const api = createMobileApi(auth.apiBase, auth.session.accessToken);
    const payload = await api.getBundles(record.username) as BundlePayload;
    const device = Array.isArray(payload.devices)
      ? payload.devices.find((candidate) => candidate.deviceId === record.deviceId)
      : null;

    if (!device) {
      throw new Error(`No active backend bundle found for ${record.username} on device ${record.deviceId}.`);
    }

    return {
      username: payload.username,
      device
    };
  }

  async function handleRefresh(record: StoredTrustRecord) {
    const key = `${record.username}#${record.deviceId}:refresh`;
    setBusyKey(key);
    setStatus(`Refreshing trust state for ${record.username} on ${record.deviceId}...`);

    try {
      const current = await fetchCurrentDevice(record);
      const result = await assessMobileDeviceTrust(current.username, current.device);
      await loadRecords();
      setStatus(
        result.trusted
          ? `Trust check passed for ${record.username} on ${record.deviceId}. Safety number: ${result.safetyNumber}.`
          : `Keys changed for ${record.username} on ${record.deviceId}. Safety number: ${result.safetyNumber}.`
      );
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Unable to refresh the selected trust record.");
    } finally {
      setBusyKey(null);
    }
  }

  async function handleTrustLatest(record: StoredTrustRecord) {
    const key = `${record.username}#${record.deviceId}:trust`;
    setBusyKey(key);
    setStatus(`Trusting latest keys for ${record.username} on ${record.deviceId}...`);

    try {
      const current = await fetchCurrentDevice(record);
      const trusted = await trustCurrentMobileDevice(current.username, current.device);
      await loadRecords();
      setStatus(`Trusted latest keys for ${record.username}. Safety number: ${trusted.safetyNumber}.`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Unable to trust the latest device keys.");
    } finally {
      setBusyKey(null);
    }
  }

  async function handleForget(record: StoredTrustRecord) {
    const key = `${record.username}#${record.deviceId}:forget`;
    setBusyKey(key);
    setStatus(`Removing saved trust record for ${record.username} on ${record.deviceId}...`);

    try {
      await removeMobileTrustRecord(record.username, record.deviceId);
      await loadRecords();
      setStatus(`Removed trust record for ${record.username} on ${record.deviceId}.`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Unable to remove the saved trust record.");
    } finally {
      setBusyKey(null);
    }
  }

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <Text style={styles.eyebrow}>deadp0et mobile</Text>
      <Text style={styles.title}>Trusted devices</Text>
      <Text style={styles.description}>
        Review saved device fingerprints, re-check them against the live backend, trust changed keys explicitly, or
        forget stale records so they are re-evaluated on the next bundle lookup.
      </Text>

      <View style={styles.actions}>
        <Pressable onPress={() => loadRecords().catch(() => {})} disabled={loading || Boolean(busyKey)} style={styles.button}>
          <Text style={styles.buttonText}>{loading ? "Loading..." : "Refresh trust list"}</Text>
        </Pressable>
      </View>

      {status ? <Text style={styles.status}>{status}</Text> : null}

      <View style={styles.card}>
        <Text style={styles.sectionTitle}>Saved trust records</Text>
        {!records.length ? <Text style={styles.empty}>No saved trust records.</Text> : null}
        {records.map((record) => {
          const recordKey = `${record.username}#${record.deviceId}`;
          const changed = record.status === "changed";
          return (
            <View key={recordKey} style={styles.recordCard}>
              <Text style={styles.recordTitle}>{record.username}</Text>
              <Text style={styles.detail}>Device: {record.deviceId}</Text>
              <Text style={styles.detail}>Status: {record.status || "trusted"}</Text>
              <Text style={styles.detail}>Trusted safety #: {record.trustedSafetyNumber || "not stored"}</Text>
              <Text style={styles.detail}>Pending safety #: {record.pendingSafetyNumber || "none"}</Text>
              <Text style={styles.detail}>Last seen: {record.lastSeenAt || "unknown"}</Text>

              <View style={styles.recordActions}>
                <Pressable
                  onPress={() => handleRefresh(record).catch(() => {})}
                  disabled={busyKey === `${recordKey}:refresh`}
                  style={styles.inlineButton}
                >
                  <Text style={styles.inlineButtonText}>
                    {busyKey === `${recordKey}:refresh` ? "Checking..." : "Re-check backend"}
                  </Text>
                </Pressable>

                {changed ? (
                  <Pressable
                    onPress={() => handleTrustLatest(record).catch(() => {})}
                    disabled={busyKey === `${recordKey}:trust`}
                    style={styles.alertButton}
                  >
                    <Text style={styles.alertButtonText}>
                      {busyKey === `${recordKey}:trust` ? "Trusting..." : "Trust latest keys"}
                    </Text>
                  </Pressable>
                ) : null}

                <Pressable
                  onPress={() => handleForget(record).catch(() => {})}
                  disabled={busyKey === `${recordKey}:forget`}
                  style={styles.secondaryButton}
                >
                  <Text style={styles.secondaryButtonText}>
                    {busyKey === `${recordKey}:forget` ? "Removing..." : "Forget record"}
                  </Text>
                </Pressable>
              </View>
            </View>
          );
        })}
      </View>
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
  status: {
    color: "#8c3f2b",
    fontSize: 14,
    lineHeight: 20
  },
  card: {
    padding: 18,
    borderRadius: 18,
    backgroundColor: "#fffaf3",
    borderWidth: 1,
    borderColor: "#dbc8b8",
    gap: 10
  },
  sectionTitle: {
    color: "#1d1b19",
    fontSize: 18,
    fontWeight: "700"
  },
  empty: {
    color: "#6b6158",
    fontSize: 15
  },
  recordCard: {
    paddingTop: 12,
    marginTop: 4,
    borderTopWidth: 1,
    borderTopColor: "#e5d6ca",
    gap: 4
  },
  recordTitle: {
    color: "#1d1b19",
    fontSize: 16,
    fontWeight: "700"
  },
  detail: {
    color: "#453f39",
    fontSize: 13,
    lineHeight: 18
  },
  recordActions: {
    gap: 10,
    marginTop: 10
  },
  inlineButton: {
    paddingVertical: 10,
    paddingHorizontal: 12,
    borderRadius: 12,
    backgroundColor: "#1d1b19",
    alignItems: "center"
  },
  inlineButtonText: {
    color: "#f8f3ec",
    fontSize: 14,
    fontWeight: "700"
  },
  alertButton: {
    paddingVertical: 10,
    paddingHorizontal: 12,
    borderRadius: 12,
    backgroundColor: "#8c3f2b",
    alignItems: "center"
  },
  alertButtonText: {
    color: "#fff7f1",
    fontSize: 14,
    fontWeight: "700"
  },
  secondaryButton: {
    paddingVertical: 10,
    paddingHorizontal: 12,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: "#c89c86",
    backgroundColor: "#fff7f1",
    alignItems: "center"
  },
  secondaryButtonText: {
    color: "#8c3f2b",
    fontSize: 14,
    fontWeight: "700"
  }
});
