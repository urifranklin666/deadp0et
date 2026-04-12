import { ScreenShell } from "../src/components/screen-shell";

export default function LoginScreen() {
  return (
    <ScreenShell
      title="Log in"
      body="This screen will authenticate against /v1/sessions, restore the device context, and persist the session securely."
    />
  );
}
