import { StyleSheet, Text, View } from "react-native";

type ScreenShellProps = {
  title: string;
  body: string;
};

export function ScreenShell({ title, body }: ScreenShellProps) {
  return (
    <View style={styles.container}>
      <Text style={styles.title}>{title}</Text>
      <Text style={styles.body}>{body}</Text>
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
  }
});
