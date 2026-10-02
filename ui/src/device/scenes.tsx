// The drawn screens. Each takes the chosen device and draws the same content in an iPhone
// frame or an iPad frame (the iPad shows the Settings sidebar). The row to tap is marked,
// and live values (server address, port) are drawn in. Every drawing carries a text
// equivalent as its accessible name.
import type { Device } from "../api";
import { en } from "../strings/en";
import { Frame, Group, NAV, NavBar, SettingsRoot, Stack, Toggle } from "./parts";

const t = en.device;
const alt = en.device.alt;
const name = (device: Device) => en.deviceName[device];

type P = { device: Device };

/**
 * Settings → Wi-Fi. `open` marks the Wi-Fi row that gets you there (the first screen of
 * Settings on an iPhone, the sidebar on an iPad); `info` marks the ⓘ beside the network.
 */
export function WifiList({ device, step }: P & { step: "open" | "info" }) {
  const open = step === "open";
  const label = open ? alt.wifiOpen(name(device)) : alt.wifiList(name(device));
  return (
    <Frame device={device} label={label} sidebar={{ active: "wifi", tapWifi: open }}>
      {(w) => open && device === "iphone" ? <SettingsRoot w={w} tapWifi /> : (
        <>
          <NavBar w={w} title={t.wifi} back={device === "iphone" ? t.settings : undefined} />
          <Stack y={NAV} w={w} groups={[
            { rows: [{ label: t.wifi, accessory: "toggleOn" }] },
            { header: t.myNetworks, rows: [{ label: t.homeNetwork, leadingCheck: true, accessory: "info", highlight: open ? undefined : "accessory" }] },
            { header: t.otherNetworks, rows: [{ label: t.neighbour, accessory: "info" }, { label: t.cafe, accessory: "info" }] },
          ]} />
        </>
      )}
    </Frame>
  );
}

export function NetworkDetail({ device }: P) {
  return (
    <Frame device={device} label={alt.networkDetail(name(device))} sidebar={{ active: "wifi" }}>
      {(w) => (
        <>
          <NavBar w={w} title={t.homeNetwork} back={t.wifi} />
          <Stack y={NAV} w={w} groups={[
            { rows: [{ label: t.forget, tone: "link" }] },
            { rows: [{ label: t.autoJoin, accessory: "toggleOn" }] },
            { rows: [{ label: t.ipAddress, value: t.ipAddressValue }] },
            { header: t.httpProxy, rows: [{ label: t.configureProxy, value: t.off, accessory: "chevron", highlight: "row" }] },
          ]} />
        </>
      )}
    </Frame>
  );
}

/**
 * Configure Proxy. `fields` marks the Server and Port to type, `save` marks the Save button,
 * and `off` shows the cleanup state: Off selected, then Save.
 */
export function ProxyForm({ device, ip, port, mode }: P & { ip: string; port: number; mode: "fields" | "save" | "off" }) {
  const d = name(device);
  const label = mode === "off" ? alt.proxyOff(d) : mode === "save" ? `${alt.proxyForm(d, ip, port)} ${alt.proxySave(d)}` : alt.proxyForm(d, ip, port);
  const off = mode === "off";
  return (
    <Frame device={device} label={label} sidebar={{ active: "wifi" }}>
      {(w) => (
        <>
          <NavBar w={w} title={t.configureProxy} back action={t.save} actionHighlight={mode !== "fields"} />
          <Stack y={NAV} w={w} groups={[
            { rows: [
              { label: t.off, accessory: off ? "check" : undefined, highlight: off ? "row" : undefined },
              { label: t.manual, accessory: off ? undefined : "check" },
              { label: t.automatic },
            ] },
            ...(off ? [] : [{ rows: [
              { label: t.server, value: ip, live: true },
              { label: t.port, value: String(port), live: true },
              { label: t.authentication, accessory: "toggleOff" as const },
            ] }]),
          ]} />
        </>
      )}
    </Frame>
  );
}

export function ProfileDownloaded({ device }: P) {
  return (
    <Frame device={device} label={alt.profileDownloaded(name(device))} sidebar={{ active: "general", profileRow: true }}>
      {(w) => device === "iphone" ? <SettingsRoot w={w} profileRow /> : (
        <>
          <NavBar w={w} title={t.general} />
          <Stack y={NAV} w={w} groups={[
            { rows: [{ label: t.about, accessory: "chevron" }] },
            { rows: [{ label: t.deviceManagement, accessory: "chevron" }] },
          ]} />
        </>
      )}
    </Frame>
  );
}

export function InstallProfile({ device }: P) {
  return (
    <Frame device={device} label={alt.installProfile(name(device))} sidebar={{ active: "general" }}>
      {(w) => (
        <>
          <NavBar w={w} title={t.installProfile} leading={t.cancel} action={t.install} actionHighlight />
          <rect x={10} y={NAV} width={w - 20} height={58} rx={9} className="d-card" />
          <rect x={22} y={NAV + 12} width={34} height={34} rx={8} className="d-chip" />
          <text x={64} y={NAV + 26} className="d-text d-small">{en.certName}</text>
          <text x={64} y={NAV + 42} className="d-text d-dim d-small">{t.certificate}</text>
          <Stack y={NAV + 72} w={w} groups={[
            { rows: [{ label: t.signedBy, value: t.notSigned }, { label: t.contains, value: t.certificate }] },
          ]} />
        </>
      )}
    </Frame>
  );
}

export function TrustSettings({ device }: P) {
  return (
    <Frame device={device} label={alt.trustSettings(name(device))} sidebar={{ active: "general" }}>
      {(w) => (
        <>
          <NavBar w={w} title={t.trustTitle} back />
          <text x={22} y={NAV + 12} className="d-text d-dim d-tiny">{t.trustGroup}</text>
          <rect x={10} y={NAV + 20} width={w - 20} height={44} rx={9} className="d-card" />
          <rect x={12} y={NAV + 22} width={w - 24} height={40} rx={7} className="d-hl" />
          <text x={22} y={NAV + 46} className="d-text d-small">{en.certName}</text>
          <Toggle x={w - 56} y={NAV + 32} on />
        </>
      )}
    </Frame>
  );
}

export function DeviceManagement({ device }: P) {
  return (
    <Frame device={device} label={alt.deviceManagement(name(device))} sidebar={{ active: "general" }}>
      {(w) => (
        <>
          <NavBar w={w} title={t.deviceManagement} back />
          <Group y={NAV} w={w} rows={[{ label: t.vpn, value: t.notConnected, accessory: "chevron" }]} />
          <text x={22} y={NAV + 66} className="d-text d-dim d-small">{t.configProfile}</text>
          <rect x={10} y={NAV + 74} width={w - 20} height={44} rx={9} className="d-card" />
          <rect x={12} y={NAV + 76} width={w - 24} height={40} rx={7} className="d-hl" />
          <text x={22} y={NAV + 100} className="d-text d-small">{en.certName}</text>
          <text x={w - 22} y={NAV + 101} textAnchor="end" className="d-text d-dim d-chev">›</text>
          <Group y={NAV + 134} w={w} rows={[{ label: t.removeProfile, tone: "danger", highlight: "row" }]} />
        </>
      )}
    </Frame>
  );
}

/** The page the app serves to the phone, drawn inside Safari. */
export function DownloadPage({ device, ip, port, highlight }: P & { ip: string; port: number; highlight: "download" | "test" }) {
  const d = name(device);
  return (
    <Frame device={device} label={highlight === "download" ? alt.downloadPage(d) : alt.testPage(d)}>
      {(w) => {
        const cx = w / 2;
        return (
          <>
            <rect x={cx - 100} y={2} width={200} height={26} rx={9} className="d-card" />
            <text x={cx} y={19} textAnchor="middle" className="d-text d-small d-mono">{t.safariHost(ip, port)}</text>
            <text x={cx} y={84} textAnchor="middle" className="d-text d-bold d-large">{en.appName}</text>
            <rect x={cx - 88} y={108} width={176} height={40} rx={10} className="d-button" />
            <text x={cx} y={133} textAnchor="middle" className="d-text d-on-button d-bold">{t.downloadCertificate}</text>
            {highlight === "download" && <rect x={cx - 94} y={102} width={188} height={52} rx={14} className="d-hl d-ring" />}
            <text x={cx} y={186} textAnchor="middle" className="d-text d-link d-underline">{t.test}</text>
            {highlight === "test" && <rect x={cx - 34} y={166} width={68} height={32} rx={9} className="d-hl d-ring" />}
          </>
        );
      }}
    </Frame>
  );
}

/** Authy asking for the backups password. With `stop`, the drawing says to stop here. */
export function AuthyPrompt({ device, stop }: P & { stop: boolean }) {
  const d = name(device);
  return (
    <Frame device={device} label={stop ? alt.authyPrompt(d) : alt.authyPassword(d)}>
      {(w) => {
        const cx = w / 2;
        return (
          <>
            <circle cx={cx} cy={44} r={22} className="d-authy" />
            <text x={cx} y={96} textAnchor="middle" className="d-text d-bold d-large">{t.authyBackupsTitle}</text>
            <text x={cx} y={118} textAnchor="middle" className="d-text d-dim d-small">{t.authyBackupsBody1}</text>
            <text x={cx} y={133} textAnchor="middle" className="d-text d-dim d-small">{t.authyBackupsBody2}</text>
            <rect x={cx - 96} y={152} width={192} height={38} rx={9} className="d-card" />
            <text x={cx - 84} y={176} className="d-text d-dim">{t.authyPasswordField}</text>
            {!stop && <rect x={cx - 100} y={148} width={200} height={46} rx={11} className="d-hl" />}
            {stop && (
              <g>
                <rect x={cx - 96} y={214} width={192} height={46} rx={10} className="d-stop" />
                <text x={cx} y={243} textAnchor="middle" className="d-text d-bold d-large d-on-stop">{t.stopHere}</text>
              </g>
            )}
          </>
        );
      }}
    </Frame>
  );
}

function AuthyHeader({ w, title }: { w: number; title: string }) {
  return (
    <>
      <circle cx={24} cy={16} r={9} className="d-authy" />
      <text x={w / 2} y={21} textAnchor="middle" className="d-text d-bold">{title}</text>
    </>
  );
}

export function AuthyAccounts({ device }: P) {
  return (
    <Frame device={device} label={alt.authyAccounts(name(device))}>
      {(w) => (
        <>
          <AuthyHeader w={w} title={t.authy} />
          <Group y={NAV} w={w} rows={t.sampleAccounts.map((label) => ({ label, value: t.sampleCode }))} />
        </>
      )}
    </Frame>
  );
}

export function AuthyBackups({ device }: P) {
  return (
    <Frame device={device} label={alt.authyBackups(name(device))}>
      {(w) => (
        <>
          <AuthyHeader w={w} title={t.authyAccounts} />
          <Group y={NAV} w={w} rows={[{ label: t.authyBackupsToggle, accessory: "toggleOn", highlight: "row" }]} />
        </>
      )}
    </Frame>
  );
}

export function AuthyDevices({ device }: P) {
  return (
    <Frame device={device} label={alt.authyDevices(name(device))}>
      {(w) => (
        <>
          <AuthyHeader w={w} title={t.authyDevices} />
          <Stack y={NAV} w={w} groups={[
            { rows: [{ label: t.authyMultiDevice, accessory: "toggleOn", highlight: "row" }] },
            { rows: [{ label: t.authyThisDevice, value: name(device) }] },
          ]} />
        </>
      )}
    </Frame>
  );
}

/** Not a phone screen: the saved file going into the Trash on this computer. */
export function TrashFile() {
  return (
    <svg className="device device-plain" role="img" aria-label={alt.trashFile} viewBox="0 0 260 200">
      <path d="M40 40h44l18 18v62H40z" className="d-card d-outline" />
      <path d="M84 40v18h18" className="d-outline d-nofill" />
      <text x={71} y={140} textAnchor="middle" className="d-text d-small d-ui">{t.fileName}</text>
      <path d="M120 84h44m-10-9 10 9-10 9" className="d-outline d-nofill d-arrow" />
      <path d="M186 62h44l-5 60h-34z" className="d-card d-outline" />
      <path d="M180 56h56M200 56v-8h16v8" className="d-outline d-nofill" />
      <text x={208} y={140} textAnchor="middle" className="d-text d-small d-ui">{t.trash}</text>
    </svg>
  );
}
