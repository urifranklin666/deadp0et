import * as SecureStore from "expo-secure-store";

const SESSION_KEY = "deadp0et.mobile.session";
const DEVICE_KEY = "deadp0et.mobile.device";
const CONTACT_TRUST_KEY = "deadp0et.mobile.contact-trust";
const API_BASE_KEY = "deadp0et.mobile.api-base";
const CONVERSATION_CACHE_KEY = "deadp0et.mobile.conversation-cache";
const COMPOSE_DRAFTS_KEY = "deadp0et.mobile.compose-drafts";

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

export async function savePreferredApiBase(value: string) {
  await SecureStore.setItemAsync(API_BASE_KEY, value);
}

export async function loadPreferredApiBase() {
  return SecureStore.getItemAsync(API_BASE_KEY);
}

export async function clearPreferredApiBase() {
  await SecureStore.deleteItemAsync(API_BASE_KEY);
}

export async function saveConversationCache(value: string) {
  await SecureStore.setItemAsync(CONVERSATION_CACHE_KEY, value);
}

export async function loadConversationCache() {
  return SecureStore.getItemAsync(CONVERSATION_CACHE_KEY);
}

export async function clearConversationCache() {
  await SecureStore.deleteItemAsync(CONVERSATION_CACHE_KEY);
}

export async function saveComposeDrafts(value: string) {
  await SecureStore.setItemAsync(COMPOSE_DRAFTS_KEY, value);
}

export async function loadComposeDrafts() {
  return SecureStore.getItemAsync(COMPOSE_DRAFTS_KEY);
}

export async function clearComposeDrafts() {
  await SecureStore.deleteItemAsync(COMPOSE_DRAFTS_KEY);
}
