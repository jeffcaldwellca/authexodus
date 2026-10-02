// Screen 3: download the certificate, install the profile, and (the step people miss) switch
// on full trust. Advances by itself when an intercepted connection to Authy succeeds.
import type { Device } from "../api";
import { Callout, Guide, QrImage, Screen, Waiting, type GuideStep } from "../components/ui";
import { DownloadPage, InstallProfile, ProfileDownloaded, TrustSettings } from "../device/scenes";
import { MethodBroken } from "../failures/MethodBroken";
import { Trouble } from "../failures/Trouble";
import { Trust } from "../failures/Trust";
import { Vpn } from "../failures/Vpn";
import { Wifi } from "../failures/Wifi";
import { en } from "../strings/en";
import { troubleFor } from "../wizard/machine";
import { deviceLabel, type ScreenProps } from "./types";

const t = en.certificate;

export function Certificate({ state, dispatch, proxy }: ScreenProps) {
  const device: Device = state.device ?? "iphone";
  const d = deviceLabel(state.device);
  const help = { d, ip: proxy?.ip, port: proxy?.port };
  const trouble = troubleFor(state);
  const abandon = () => dispatch({ type: "abandon" });

  const steps: GuideStep[] = proxy ? [
    {
      id: "scan",
      text: t.steps.scan(d),
      art: (
        <div className="qr-block">
          <QrImage svg={proxy.certQrSvg} alt={t.qrAlt} size={240} />
          <p className="quiet-text">{t.orType}</p>
          <p className="live">{proxy.certUrl}</p>
        </div>
      ),
    },
    { id: "download", text: t.steps.download, art: <DownloadPage device={device} ip={proxy.ip} port={proxy.port} highlight="download" /> },
    { id: "profile", text: t.steps.profile, art: <ProfileDownloaded device={device} /> },
    { id: "install", text: t.steps.install, art: <InstallProfile device={device} /> },
    { id: "trust", text: t.steps.trust, art: <TrustSettings device={device} />, important: true },
    { id: "test", text: t.steps.test, art: <DownloadPage device={device} ip={proxy.ip} port={proxy.port} highlight="test" /> },
  ] : [];

  return (
    <Screen
      title={t.title}
      lede={t.lede}
      status={<Callout tone="ok"><p>{t.connected(d)}</p></Callout>}
      footer={
        <>
          <Trouble onAbandon={abandon}>
            <Trust {...help} collapsible />
            <Wifi {...help} collapsible />
            <Vpn {...help} collapsible />
          </Trouble>
          <Waiting>{t.waiting}</Waiting>
        </>
      }
    >
      {trouble === "trust" && <Trust {...help} />}
      {trouble === "methodBroken" && (
        <MethodBroken {...help}>
          <button type="button" className="secondary" onClick={abandon}>{en.common.stopAndCleanUp}</button>
        </MethodBroken>
      )}
      {/* Remounting on `trouble` puts the trust picture in view the moment trust is the problem. */}
      <Guide key={trouble ?? "none"} steps={steps} initial={trouble === "trust" ? "trust" : "scan"} />
    </Screen>
  );
}
