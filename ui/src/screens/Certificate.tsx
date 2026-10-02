// Screen 3: download the certificate, install the profile, and (the step people miss) switch
// on full trust. Advances by itself when an intercepted connection to Authy succeeds.
// A refused connection here is expected until the last step, so it only adds a calm reminder
// under the guide; it never moves the picture the person is looking at.
import type { Device } from "../api";
import { Callout, Guide, QrImage, Screen, Waiting, type GuideStep } from "../components/ui";
import { DownloadPage, InstallProfile, ProfileDownloaded, TrustSettings } from "../device/scenes";
import { ConnectionNotices } from "../failures/ConnectionNotices";
import { Trouble } from "../failures/Trouble";
import { Trust } from "../failures/Trust";
import { Vpn } from "../failures/Vpn";
import { Wifi } from "../failures/Wifi";
import { en } from "../strings/en";
import { troubleFor } from "../wizard/machine";
import { deviceLabel, type ScreenProps } from "./types";

const t = en.certificate;

/** The 32 pairs of a SHA-256 fingerprint in four short rows, which is easier to compare by eye. */
export function fingerprintLines(fingerprint: string): string[] {
  const pairs = fingerprint.split(":").filter(Boolean);
  const lines: string[] = [];
  for (let i = 0; i < pairs.length; i += 8) lines.push(pairs.slice(i, i + 8).join(":"));
  return lines;
}

export function Certificate({ state, dispatch, proxy, onRestart, restart }: ScreenProps) {
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
    { id: "trust", text: t.steps.trust(d), art: <TrustSettings device={device} />, important: true },
    { id: "test", text: t.steps.test, art: <DownloadPage device={device} ip={proxy.ip} port={proxy.port} highlight="test" /> },
  ] : [];

  return (
    <Screen
      title={t.title}
      lede={t.lede}
      status={<Callout tone="ok"><p>{t.connected(d)}</p></Callout>}
      footer={
        <>
          <Trouble d={d} mentionAuthy={state.reachedAuthy} onAbandon={abandon} onRestart={() => onRestart()}>
            <Trust {...help} collapsible />
            <Wifi {...help} collapsible />
            <Vpn {...help} collapsible />
          </Trouble>
          <Waiting>{t.waiting}</Waiting>
        </>
      }
    >
      <ConnectionNotices d={d} state={state} restart={restart} onRestart={() => onRestart()} />
      {proxy && (
        <div className="fingerprint-box">
          <p className="values-caption">{t.fingerprintLabel}</p>
          <p className="fingerprint" data-testid="fingerprint">
            {fingerprintLines(proxy.certFingerprint).map((line) => <span key={line}>{line}</span>)}
          </p>
          <p className="quiet-text">{t.fingerprintHow(d)}</p>
        </div>
      )}
      {/* The guide never moves on an event: the person may still be scanning the code. */}
      <Guide steps={steps} />
      {trouble === "trust" && <Trust {...help} reminder />}
    </Screen>
  );
}
