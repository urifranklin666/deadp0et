import * as SecureStore from "expo-secure-store";

const SESSION_KEY = "deadp0et.mobile.session";
const DEVICE_KEY = "deadp0et.mobile.device";
const CONTACT_TRUST_KEY = "deadp0et.mobile.contact-trust";

export async function saveSession(value: string) {
  await SecureStore.setItemAsync(SESSION_KEY, value);
}

export async function loadSession() {
  return SecureStore.getItemAsync(SESSION_KEY);
}

export async function clearSession() {
  await SecureStore.deleteItemAsync(SESSION_KEY);
}

export async function saveLocalDevice(value: string) {
  await SecureStore.setItemAsync(DEVICE_KEY, value);
}

export async function loadLocalDevice() {
  return SecureStore.getItemAsync(DEVICE_KEY);
}

export async function clearLocalDevice() {
  await SecureStore.deleteItemAsync(DEVICE_KEY);
}

export async function saveContactTrust(value: string) {
  await SecureStore.setItemAsync(CONTACT_TRUST_KEY, value);
}

export async function loadContactTrust() {
  return SecureStore.getItemAsync(CONTACT_TRUST_KEY);
}

export async function clearContactTrust() {
  await SecureStore.deleteItemAsync(CONTACT_TRUST_KEY);
}
