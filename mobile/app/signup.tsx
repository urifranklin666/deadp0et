import { ScreenShell } from "../src/components/screen-shell";

export default function SignupScreen() {
  return (
    <ScreenShell
      title="Create account"
      body="This screen will generate a device locally, create the first account/device bundle, and persist local device material in secure storage."
    />
  );
}
