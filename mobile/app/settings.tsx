import { Link } from "expo-router";
import { Pressable, StyleSheet, Text, View } from "react-native";

export default function SettingsScreen() {
  return (
    <View style={styles.container}>
      <Text style={styles.title}>Settings</Text>
      <Text style={styles.body}>
        This screen still needs backend configuration, logout, session diagnostics, app lock, and notification
        settings, but trust management is available now.
      </Text>
      <Link href="/trust" asChild>
        <Pressable style={styles.button}>
          <Text style={styles.buttonText}>Manage trusted devices</Text>
        </Pressable>
      </Link>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 24,
    backgroundColor: "#f5f0e8",
    gap: 16
  },
  title: {
    marginTop: 24,
    color: "#1d1b19",
    fontSize: 30,
    fontWeight: "800"
  },
  body: {
    color: "#453f39",
    fontSize: 16,
    lineHeight: 24
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
  }
});
