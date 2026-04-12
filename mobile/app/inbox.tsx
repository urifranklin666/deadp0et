import { ScreenShell } from "../src/components/screen-shell";

export default function InboxScreen() {
  return (
    <ScreenShell
      title="Inbox"
      body="This screen will fetch device-scoped inbox state, cache envelopes locally, and drive message decryption on demand."
    />
  );
}
