import { Stack } from "expo-router";

export default function RootLayout() {
  return (
    <Stack
      screenOptions={{
        headerStyle: { backgroundColor: "#f5f0e8" },
        headerTintColor: "#1d1b19",
        contentStyle: { backgroundColor: "#f5f0e8" }
      }}
    />
  );
}
