// Screen 2: point the phone's Wi-Fi proxy at this computer. Advances by itself when a device
// connects.
import type { Device } from "../api";
import type { ApiError } from "../api.errors";
import { DeviceSwitch } from "../components/DeviceSwitch";
import { Callout, Guide, Screen, Waiting, type GuideStep } from "../components/ui";
import { NetworkDetail, ProxyForm, WifiList } from "../device/scenes";
import { ConnectionNotices } from "../failures/ConnectionNotices";
import { Firewall } from "../failures/Firewall";
import { Problem } from "../failures/Problem";
import { Trouble } from "../failures/Trouble";
import { Vpn } from "../failures/Vpn";
import { Wifi } from "../failures/Wifi";
import { en } from "../strings/en";
import { deviceLabel, type ScreenProps } from "./types";

const t = en.connect;

export type ConnectProps = ScreenProps & {
  /** Why the connection could not be started, in the shell's terms. */
  proxyError: ApiError | null;
  /** An address the shell refused to switch to without a restart. */
  addressRejected: string | null;
  /** An address the shell could not switch to at all, and why. */
  addressError: { ip: string; error: ApiError } | null;
  /** A restart landed on a different address or port than the device was set to. */
  addressChanged: boolean;
  onPickAddress: (ip: string) => void;
  onRetry: () => void;
};

export function Connect({ api, state, dispatch, proxy, proxyError, addressRejected, addressError, addressChanged, onPickAddress, onRetry, onRestart, restart, restartError }: ConnectProps) {
  const device: Device = state.device ?? "iphone";
  const d = deviceLabel(state.device);
  const help = { d, ip: proxy?.ip, port: proxy?.port };

  const restartButton = (
    <button type="button" className="secondary" disabled={restart === "busy"} onClick={() => onRestart()}>
      {restart === "busy" ? en.common.restarting : en.common.restart}
    </button>
  );

  const steps: GuideStep[] = proxy ? [
    { id: "wifi", text: t.steps.wifi[device], art: <WifiList device={device} step="open" /> },
    { id: "info", text: t.steps.info, art: <WifiList device={device} step="info" /> },
    { id: "configure", text: t.steps.configure, art: <NetworkDetail device={device} /> },
    { id: "manual", text: t.steps.manual(proxy.ip, proxy.port), art: <ProxyForm device={device} ip={proxy.ip} port={proxy.port} mode="fields" /> },
    { id: "save", text: t.steps.save, art: <ProxyForm device={device} ip={proxy.ip} port={proxy.port} mode="save" /> },
  ] : [];

  return (
    <Screen
      title={t.title(d)}
      lede={t.lede(d)}
      footer={
        <>
          <Trouble d={d} mentionAuthy={state.reachedAuthy} onAbandon={() => dispatch({ type: "abandon" })} onRestart={() => onRestart()}>
            <Firewall {...help} collapsible />
            <Wifi {...help} collapsible />
            <Vpn {...help} collapsible />
          </Trouble>
          {proxy && <Waiting>{t.waiting(d)}</Waiting>}
        </>
      }
    >
      <DeviceSwitch api={api} state={state} dispatch={dispatch} />
      <ConnectionNotices d={d} state={state} restart={restart} restartError={restartError} onRestart={() => onRestart()} />
      {addressChanged && <Callout tone="warn" title={t.addressChanged(d)} alert />}
      {addressRejected && (
        <Callout tone="warn" title={t.addressRejected(addressRejected)} alert>
          <button type="button" className="secondary" disabled={restart === "busy"} onClick={() => onRestart(addressRejected)}>
            {t.restartOn(addressRejected)}
          </button>
        </Callout>
      )}
      {addressError && (
        <Problem error={addressError.error} d={d} title={t.addressFailed(addressError.ip)}>
          {addressError.error.code === "address_changed" && restartButton}
        </Problem>
      )}
      {proxyError && (
        <Problem error={proxyError} d={d} title={t.startFailed(d)}>
          {/* An address that is gone will not come back by asking again: only a restart moves on. */}
          {proxyError.code === "address_changed" ? restartButton
            : <button type="button" className="secondary" onClick={onRetry}>{en.common.tryAgain}</button>}
        </Problem>
      )}
      {!proxy && !proxyError && <Waiting>{t.starting}</Waiting>}
      {proxy && (
        <>
          <div className={addressChanged ? "values values-changed" : "values"} role="group" aria-label={t.valuesLabel(d)}>
            <div>
              <p className="values-caption">{t.valuesLabel(d)}</p>
              <dl>
                <div><dt>{t.server}</dt><dd className="live">{proxy.ip}</dd></div>
                <div><dt>{t.port}</dt><dd className="live">{proxy.port}</dd></div>
              </dl>
            </div>
            {proxy.addresses.length > 1 && (
              <label className="address">
                <span>{t.addressLabel}</span>
                <select value={proxy.ip} disabled={restart === "busy"} onChange={(e) => onPickAddress(e.target.value)}>
                  {proxy.addresses.map((a) => <option key={a.ip} value={a.ip}>{t.addressOption(a.ip, a.label)}</option>)}
                </select>
                <span className="quiet-text">{t.addressHint(d)}</span>
              </label>
            )}
          </div>
          <Callout tone="info"><p>{t.firewall}</p></Callout>
          <Guide steps={steps} />
        </>
      )}
    </Screen>
  );
}
