import { ScreenShell } from "../src/components/screen-shell";

export default function DevicesScreen() {
  return (
    <ScreenShell
      title="Devices"
      body="This screen will list active and revoked devices, support new device enrollment, and expose prekey rotation and device revocation flows."
    />
  );
}
