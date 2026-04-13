import * as Notifications from "expo-notifications";
import { Platform } from "react-native";

export async function requestPushPermissions() {
  const existing = await Notifications.getPermissionsAsync();
  if (existing.granted) {
    return existing;
  }
  return Notifications.requestPermissionsAsync();
}

export async function getNativePushRegistration() {
  const permissions = await requestPushPermissions();
  if (!permissions.granted) {
    throw new Error("Push notification permission was not granted.");
  }

  const tokenResponse = await Notifications.getDevicePushTokenAsync();
  const token = typeof tokenResponse?.data === "string" ? tokenResponse.data.trim() : "";
  if (!token) {
    throw new Error("Device push token is unavailable on this device.");
  }

  return {
    token,
    provider: "native",
    platform: Platform.OS
  };
}
