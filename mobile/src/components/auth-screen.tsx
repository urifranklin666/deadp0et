import { ReactNode } from "react";
import { ScrollView, StyleSheet, Text, View } from "react-native";

type AuthScreenProps = {
  title: string;
  description: string;
  children: ReactNode;
  footer?: ReactNode;
};

export function AuthScreen({ title, description, children, footer = null }: AuthScreenProps) {
  return (
    <ScrollView contentContainerStyle={styles.container}>
      <Text style={styles.eyebrow}>deadp0et mobile</Text>
      <Text style={styles.title}>{title}</Text>
      <Text style={styles.description}>{description}</Text>
      <View style={styles.card}>{children}</View>
      {footer ? <View style={styles.footer}>{footer}</View> : null}
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
    gap: 14
  },
  footer: {
    gap: 10
  }
});
