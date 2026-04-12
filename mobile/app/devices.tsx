import { useFocusEffect } from "expo-router";
import { useCallback, useState } from "react";
import { Pressable, ScrollView, StyleSheet, Text, View } from "react-native";

import {
  appendOneTimePrekeysToStoredRecord,
  generateDeviceBundle,
  generateOneTimePrekeySet,
  serializeMobileDeviceRecord
} from "../src/lib/crypto";
import { loadLocalDevice, saveLocalDevice, saveSession } from "../src/lib/secure-storage";
import { createMobileApi, loadStoredAuthState } from "../src/lib/session";

type DeviceRecord = {
  deviceId: string;
  signedPrekey: JsonWebKey;
  prekeySignature: string;
  oneTimePrekeys?: Array<{ keyId: string; key: JsonWebKey }>;
  availableOneTimePrekeys?: number;
  lowOneTimePrekeys?: boolean;
  prekeyWarning?: string | null;
  registeredAt?: string;
  revokedAt?: string | null;
};

type DeviceListPayload = {
  username: string;
  devices: DeviceRecord[];
  lowOneTimePrekeyThreshold?: number;
};

export default function DevicesScreen() {
  const [loading, setLoading] = useState(true);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [username, setUsername] = useState("");
  const [localDeviceId, setLocalDeviceId] = useState("");
  const [devices, setDevices] = useState<DeviceRecord[]>([]);
  const [lowThreshold, setLowThreshold] = useState<number | null>(null);

  const loadDevices = useCallback(async () => {
    setLoading(true);
    setStatus("Loading account devices...");

    try {
      const auth = await loadStoredAuthState();
      const api = createMobileApi(auth.apiBase, auth.session.accessToken);
      const payload = await api.listDevices() as DeviceListPayload;
      setUsername(payload.username || auth.localDeviceRecord.username || "");
      setLocalDeviceId(auth.localDeviceRecord.deviceId || auth.session.deviceId);
      setDevices(Array.isArray(payload.devices) ? payload.devices : []);
      setLowThreshold(typeof payload.lowOneTimePrekeyThreshold === "number" ? payload.lowOneTimePrekeyThreshold : null);
      setStatus(
        Array.isArray(payload.devices) && payload.devices.length
          ? `Loaded ${payload.devices.length} device record(s) for ${payload.username}.`
          : `No device records loaded for ${payload.username}.`
      );
    } catch (error) {
      setDevices([]);
      setStatus(error instanceof Error ? error.message : "Unable to load account devices.");
    } finally {
      setLoading(false);
    }
  }, []);

  useFocusEffect(
    useCallback(() => {
      loadDevices().catch(() => {});
    }, [loadDevices])
  );

  async function handleRegisterNewDevice() {
    const actionKey = "register-device";
    setBusyAction(actionKey);
    setStatus("Generating and registering a new device on this phone...");

    try {
      const auth = await loadStoredAuthState();
      const passwordVerifier = auth.localDeviceRecord.passwordVerifier;
      const accountId = auth.localDeviceRecord.accountId;

      if (!passwordVerifier || !accountId || !auth.localDeviceRecord.username) {
        throw new Error("Local device record is missing account credentials required to enroll a new device.");
      }

      const deviceBundle = await generateDeviceBundle();
      const api = createMobileApi(auth.apiBase, auth.session.accessToken);
      await api.registerDevice({
        device: deviceBundle.publicBundle
      });

      const nextSessionPayload = await api.createSession({
        username: auth.localDeviceRecord.username,
        passwordVerifier,
        deviceId: deviceBundle.publicBundle.deviceId
      });

      const localRecord = await serializeMobileDeviceRecord({
        username: auth.localDeviceRecord.username,
        passwordVerifier,
        accountId,
        deviceBundle
      });

      await saveLocalDevice(JSON.stringify(localRecord));
      await saveSession(JSON.stringify({
        apiBase: auth.apiBase,
        session: nextSessionPayload.session
      }));

      await loadDevices();
      setStatus(
        `Registered device ${deviceBundle.publicBundle.deviceId} and switched this phone to the new session. The previous device remains active on the account until revoked.`
      );
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Unable to register a new device on this phone.");
    } finally {
      setBusyAction(null);
    }
  }

  async function handleReplenish(device: DeviceRecord) {
    const actionKey = `${device.deviceId}:replenish`;
    setBusyAction(actionKey);
    setStatus(`Replenishing one-time prekeys for ${device.deviceId}...`);

    try {
      const auth = await loadStoredAuthState();
      if (!auth.hydratedDevice) {
        throw new Error("Saved local device keys could not be restored.");
      }
      if (device.deviceId !== auth.hydratedDevice.publicBundle.deviceId) {
        throw new Error("One-click replenish is only available for the local device on this phone.");
      }

      const oneTimePrekeySet = await generateOneTimePrekeySet();
      const api = createMobileApi(auth.apiBase, auth.session.accessToken);
      const existingOneTimePrekeys = Array.isArray(device.oneTimePrekeys) ? device.oneTimePrekeys : [];

      await api.rotatePrekeys({
        deviceId: device.deviceId,
        signedPrekey: device.signedPrekey,
        prekeySignature: device.prekeySignature,
        oneTimePrekeys: [...existingOneTimePrekeys, ...oneTimePrekeySet.publicOneTimePrekeys]
      });

      const rawLocalDevice = await loadLocalDevice();
      if (!rawLocalDevice) {
        throw new Error("Local device record is missing from secure storage.");
      }

      const parsedLocalDevice = JSON.parse(rawLocalDevice);
      const nextLocalDevice = await appendOneTimePrekeysToStoredRecord(
        parsedLocalDevice,
        oneTimePrekeySet.privateOneTimePrekeyKeys,
        oneTimePrekeySet.publicOneTimePrekeys
      );

      if (!nextLocalDevice) {
        throw new Error("Unable to update local one-time prekeys.");
      }

      await saveLocalDevice(JSON.stringify(nextLocalDevice));
      await loadDevices();
      setStatus(`Replenished local one-time prekeys for ${device.deviceId}.`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Unable to replenish one-time prekeys.");
    } finally {
      setBusyAction(null);
    }
  }

  async function handleRevoke(device: DeviceRecord) {
    const actionKey = `${device.deviceId}:revoke`;
    setBusyAction(actionKey);
    setStatus(`Revoking ${device.deviceId}...`);

    try {
      const auth = await loadStoredAuthState();
      if (device.deviceId === auth.session.deviceId) {
        throw new Error("Revoking the current device would invalidate this session. Use a different device to remove it.");
      }

      const api = createMobileApi(auth.apiBase, auth.session.accessToken);
      await api.revokeDevice(device.deviceId);
      await loadDevices();
      setStatus(`Revoked device ${device.deviceId}.`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Unable to revoke the selected device.");
    } finally {
      setBusyAction(null);
    }
  }

  const activeDevices = devices.filter((device) => !device.revokedAt);
  const revokedDevices = devices.filter((device) => Boolean(device.revokedAt));
  const lowPrekeyDevices = activeDevices.filter((device) => device.lowOneTimePrekeys);

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <Text style={styles.eyebrow}>deadp0et mobile</Text>
      <Text style={styles.title}>Devices</Text>
      <Text style={styles.description}>
        Inspect active and revoked devices, monitor one-time prekey depletion, replenish local prekeys for this phone,
        and revoke other devices from the account.
      </Text>

      <View style={styles.card}>
        <Text style={styles.sectionTitle}>Summary</Text>
        <Text style={styles.detail}>Username: {username || "unknown"}</Text>
        <Text style={styles.detail}>Local device: {localDeviceId || "unknown"}</Text>
        <Text style={styles.detail}>Active devices: {activeDevices.length}</Text>
        <Text style={styles.detail}>Revoked devices: {revokedDevices.length}</Text>
        <Text style={styles.detail}>
          Low-prekey devices: {lowPrekeyDevices.length}
          {lowThreshold ? ` (threshold ${lowThreshold})` : ""}
        </Text>
      </View>

      <View style={styles.actions}>
        <Pressable
          onPress={() => handleRegisterNewDevice().catch(() => {})}
          disabled={busyAction === "register-device" || loading}
          style={styles.button}
        >
          <Text style={styles.buttonText}>{busyAction === "register-device" ? "Registering..." : "Register this phone as a new device"}</Text>
        </Pressable>
        <Pressable onPress={() => loadDevices().catch(() => {})} disabled={loading || Boolean(busyAction)} style={styles.button}>
          <Text style={styles.buttonText}>{loading ? "Loading..." : "Refresh devices"}</Text>
        </Pressable>
      </View>

      {status ? <Text style={styles.status}>{status}</Text> : null}

      <View style={styles.card}>
        <Text style={styles.sectionTitle}>Active devices</Text>
        {!activeDevices.length ? <Text style={styles.empty}>No active devices.</Text> : null}
        {activeDevices.map((device) => {
          const isLocalDevice = device.deviceId === localDeviceId;
          const replenishKey = `${device.deviceId}:replenish`;
          const revokeKey = `${device.deviceId}:revoke`;
          return (
            <View key={device.deviceId} style={styles.deviceCard}>
              <Text style={styles.deviceTitle}>{device.deviceId}</Text>
              <Text style={styles.detail}>Registered: {device.registeredAt || "unknown"}</Text>
              <Text style={styles.detail}>Available one-time prekeys: {device.availableOneTimePrekeys ?? "unknown"}</Text>
              <Text style={styles.detail}>Low prekeys: {device.lowOneTimePrekeys ? "yes" : "no"}</Text>
              {device.prekeyWarning ? <Text style={styles.warning}>{device.prekeyWarning}</Text> : null}
              {isLocalDevice ? <Text style={styles.localBadge}>This phone holds the private keys for this device.</Text> : null}

              <View style={styles.recordActions}>
                {isLocalDevice ? (
                  <Pressable
                    onPress={() => handleReplenish(device).catch(() => {})}
                    disabled={busyAction === replenishKey}
                    style={styles.inlineButton}
                  >
                    <Text style={styles.inlineButtonText}>
                      {busyAction === replenishKey ? "Replenishing..." : "Replenish local prekeys"}
                    </Text>
                  </Pressable>
                ) : (
                  <Pressable
                    onPress={() => handleRevoke(device).catch(() => {})}
                    disabled={busyAction === revokeKey}
                    style={styles.alertButton}
                  >
                    <Text style={styles.alertButtonText}>
                      {busyAction === revokeKey ? "Revoking..." : "Revoke device"}
                    </Text>
                  </Pressable>
                )}
              </View>
            </View>
          );
        })}
      </View>

      <View style={styles.card}>
        <Text style={styles.sectionTitle}>Revoked devices</Text>
        {!revokedDevices.length ? <Text style={styles.empty}>No revoked devices.</Text> : null}
        {revokedDevices.map((device) => (
          <View key={device.deviceId} style={styles.deviceCard}>
            <Text style={styles.deviceTitle}>{device.deviceId}</Text>
            <Text style={styles.detail}>Registered: {device.registeredAt || "unknown"}</Text>
            <Text style={styles.detail}>Revoked: {device.revokedAt || "unknown"}</Text>
          </View>
        ))}
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
  empty: {
    color: "#6b6158",
    fontSize: 15
  },
  deviceCard: {
    paddingTop: 12,
    marginTop: 4,
    borderTopWidth: 1,
    borderTopColor: "#e5d6ca",
    gap: 4
  },
  deviceTitle: {
    color: "#1d1b19",
    fontSize: 16,
    fontWeight: "700"
  },
  detail: {
    color: "#453f39",
    fontSize: 13,
    lineHeight: 18
  },
  warning: {
    color: "#8c3f2b",
    fontSize: 13,
    lineHeight: 18
  },
  localBadge: {
    color: "#1d1b19",
    fontSize: 13,
    lineHeight: 18,
    fontWeight: "600"
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
  }
});
