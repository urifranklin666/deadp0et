import { ScreenShell } from "../src/components/screen-shell";

export default function SettingsScreen() {
  return (
    <ScreenShell
      title="Settings"
      body="This screen will manage backend configuration, logout, session diagnostics, app lock, and future notification settings."
    />
  );
}
