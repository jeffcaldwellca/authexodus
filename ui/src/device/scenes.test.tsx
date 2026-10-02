import { render, screen, within } from "@testing-library/react";
import type { Device } from "../api";
import { en } from "../strings/en";
import {
  AuthyAccounts, AuthyBackups, AuthyDevices, AuthyPrompt, DeviceManagement, DownloadPage, InstallProfile,
  NetworkDetail, ProfileDownloaded, ProxyForm, TrustSettings, WifiList,
} from "./scenes";

const DEVICES: Device[] = ["iphone", "ipad"];

describe("device illustrations", () => {
  it.each(DEVICES)("proxy_form_illustration_shows_live_ip_and_port (%s)", (device) => {
    const { rerender } = render(<ProxyForm device={device} ip="192.168.4.109" port={8080} mode="fields" />);
    const d = en.deviceName[device];
    const drawing = screen.getByRole("img", { name: en.device.alt.proxyForm(d, "192.168.4.109", 8080) });
    expect(drawing).toHaveAttribute("data-device", device);
    // The values are drawn into the picture, next to the fields they belong in.
    expect(within(drawing).getByText("192.168.4.109")).toBeInTheDocument();
    expect(within(drawing).getByText("8080")).toBeInTheDocument();
    expect(within(drawing).getByText(en.device.server)).toBeInTheDocument();
    expect(within(drawing).getByText(en.device.port)).toBeInTheDocument();
    // Both are marked as the thing to type.
    expect(drawing.querySelectorAll(".d-live")).toHaveLength(2);

    // They are live: a different address and port redraw.
    rerender(<ProxyForm device={device} ip="10.0.0.12" port={49152} mode="fields" />);
    const redrawn = screen.getByRole("img", { name: en.device.alt.proxyForm(d, "10.0.0.12", 49152) });
    expect(within(redrawn).getByText("10.0.0.12")).toBeInTheDocument();
    expect(within(redrawn).getByText("49152")).toBeInTheDocument();
    expect(within(redrawn).queryByText("192.168.4.109")).not.toBeInTheDocument();
  });

  it("the iPad frame shows the Settings sidebar and the iPhone frame does not", () => {
    const { container, rerender } = render(<WifiList device="ipad" step="info" />);
    expect(container.querySelector('[data-part="sidebar"]')).not.toBeNull();
    rerender(<WifiList device="iphone" step="info" />);
    expect(container.querySelector('[data-part="sidebar"]')).toBeNull();
  });

  it.each(DEVICES)("every drawing has a text equivalent and marks what to tap (%s)", (device) => {
    const scenes = [
      <WifiList device={device} step="open" />, <WifiList device={device} step="info" />, <NetworkDetail device={device} />,
      <ProxyForm device={device} ip="1.2.3.4" port={1} mode="save" />, <ProxyForm device={device} ip="" port={0} mode="off" />,
      <DownloadPage device={device} ip="1.2.3.4" port={1} highlight="download" />, <DownloadPage device={device} ip="1.2.3.4" port={1} highlight="test" />,
      <ProfileDownloaded device={device} />, <InstallProfile device={device} />, <TrustSettings device={device} />,
      <DeviceManagement device={device} />, <AuthyPrompt device={device} stop />, <AuthyPrompt device={device} stop={false} />,
      <AuthyBackups device={device} />, <AuthyDevices device={device} />,
    ];
    for (const scene of scenes) {
      const { container, unmount } = render(scene);
      const drawing = screen.getByRole("img");
      expect(drawing.getAttribute("aria-label")).toMatch(/\S{3,}/);
      expect(container.querySelectorAll(".d-hl, .d-stop").length).toBeGreaterThan(0);
      unmount();
    }
    const { unmount } = render(<AuthyAccounts device={device} />);
    expect(screen.getByRole("img", { name: en.device.alt.authyAccounts(en.deviceName[device]) })).toBeInTheDocument();
    unmount();
  });

  it("the trust drawing names the certificate exactly as the phone shows it", () => {
    render(<TrustSettings device="iphone" />);
    expect(screen.getByText(en.certName)).toBeInTheDocument();
  });
});
