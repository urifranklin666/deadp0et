import { Pressable, StyleSheet, Text, TextInput, View } from "react-native";

type AuthFormProps = {
  apiBase: string;
  busy: boolean;
  buttonLabel: string;
  helper: string;
  password: string;
  setApiBase: (value: string) => void;
  setPassword: (value: string) => void;
  setUsername: (value: string) => void;
  status: string | null;
  username: string;
  onSubmit: () => void;
};

export function AuthForm(props: AuthFormProps) {
  return (
    <>
      <Field label="Backend URL" value={props.apiBase} secure={false} onChangeText={props.setApiBase} autoCapitalize="none" />
      <Field label="Username" value={props.username} secure={false} onChangeText={props.setUsername} autoCapitalize="none" />
      <Field label="Password" value={props.password} secure onChangeText={props.setPassword} autoCapitalize="none" />

      <Text style={styles.helper}>{props.helper}</Text>

      {props.status ? <Text style={styles.status}>{props.status}</Text> : null}

      <Pressable onPress={props.onSubmit} disabled={props.busy} style={[styles.button, props.busy && styles.buttonDisabled]}>
        <Text style={styles.buttonText}>{props.busy ? "Working..." : props.buttonLabel}</Text>
      </Pressable>
    </>
  );
}

function Field({
  autoCapitalize,
  label,
  onChangeText,
  secure,
  value
}: {
  autoCapitalize: "none" | "sentences" | "words" | "characters";
  label: string;
  onChangeText: (value: string) => void;
  secure: boolean;
  value: string;
}) {
  return (
    <View style={styles.field}>
      <Text style={styles.label}>{label}</Text>
      <TextInput
        value={value}
        onChangeText={onChangeText}
        secureTextEntry={secure}
        autoCapitalize={autoCapitalize}
        autoCorrect={false}
        style={styles.input}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  field: {
    gap: 8
  },
  label: {
    color: "#453f39",
    fontSize: 14,
    fontWeight: "700"
  },
  input: {
    borderWidth: 1,
    borderColor: "#cdb8a4",
    borderRadius: 12,
    paddingVertical: 12,
    paddingHorizontal: 14,
    backgroundColor: "#fffdf8",
    color: "#1d1b19",
    fontSize: 16
  },
  helper: {
    color: "#6b6158",
    fontSize: 14,
    lineHeight: 20
  },
  status: {
    color: "#8c3f2b",
    fontSize: 14,
    lineHeight: 20
  },
  button: {
    marginTop: 4,
    paddingVertical: 14,
    paddingHorizontal: 16,
    borderRadius: 14,
    backgroundColor: "#1d1b19",
    alignItems: "center"
  },
  buttonDisabled: {
    opacity: 0.65
  },
  buttonText: {
    color: "#f8f3ec",
    fontSize: 16,
    fontWeight: "700"
  }
});
