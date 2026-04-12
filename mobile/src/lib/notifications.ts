import * as Notifications from "expo-notifications";

export async function requestPushPermissions() {
  const existing = await Notifications.getPermissionsAsync();
  if (existing.granted) {
    return existing;
  }
  return Notifications.requestPermissionsAsync();
}
