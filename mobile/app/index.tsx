import { Link } from "expo-router";
import { StatusBar } from "expo-status-bar";
import { Pressable, ScrollView, StyleSheet, Text, View } from "react-native";

export default function HomeScreen() {
  return (
    <ScrollView contentContainerStyle={styles.container}>
      <StatusBar style="dark" />
      <Text style={styles.eyebrow}>deadp0et mobile</Text>
      <Text style={styles.title}>Secure messaging client scaffold</Text>
      <Text style={styles.copy}>
        The mobile client now generates a real local device record, persists it in secure storage, sends encrypted
        envelopes through the live backend, and decrypts inbox messages locally on the phone.
      </Text>

      <View style={styles.card}>
        <Text style={styles.cardTitle}>Initial scope</Text>
        <Text style={styles.cardItem}>Sign up and log in with a real backend session</Text>
        <Text style={styles.cardItem}>Store local device material in secure storage</Text>
        <Text style={styles.cardItem}>Fetch inbox state and compose encrypted envelopes</Text>
        <Text style={styles.cardItem}>Manage devices and prekeys from a phone UI</Text>
      </View>

      <View style={styles.links}>
        <NavLink href="/signup" label="Create account" />
        <NavLink href="/login" label="Log in" />
        <NavLink href="/inbox" label="Inbox" />
        <NavLink href="/compose" label="Compose" />
        <NavLink href="/devices" label="Devices shell" />
        <NavLink href="/settings" label="Settings shell" />
      </View>
    </ScrollView>
  );
}

function NavLink({
  href,
  label
}: {
  href: "/signup" | "/login" | "/inbox" | "/compose" | "/devices" | "/settings";
  label: string;
}) {
  return (
    <Link href={href} asChild>
      <Pressable style={styles.button}>
        <Text style={styles.buttonText}>{label}</Text>
      </Pressable>
    </Link>
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
    marginTop: 28,
    color: "#8c3f2b",
    fontSize: 14,
    fontWeight: "700",
    letterSpacing: 1.2,
    textTransform: "uppercase"
  },
  title: {
    color: "#1d1b19",
    fontSize: 34,
    fontWeight: "800",
    lineHeight: 40
  },
  copy: {
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
  cardTitle: {
    color: "#1d1b19",
    fontSize: 18,
    fontWeight: "700"
  },
  cardItem: {
    color: "#453f39",
    fontSize: 15,
    lineHeight: 22
  },
  links: {
    gap: 12
  },
  button: {
    paddingVertical: 14,
    paddingHorizontal: 16,
    borderRadius: 14,
    backgroundColor: "#1d1b19"
  },
  buttonText: {
    color: "#f8f3ec",
    fontSize: 16,
    fontWeight: "700"
  }
});
