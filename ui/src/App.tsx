// The wizard: one reducer, eight screens, and the wiring between the core's events and the
// reducer. The app holds no secrets here; screens that show one ask the core for it.
import { useCallback, useEffect, useReducer, useRef, useState, type ReactNode } from "react";
import type { Api, ProxyInfo, Step } from "./api";
import { Callout } from "./components/ui";
import type { RestartState } from "./failures/ConnectionNotices";
import { Authy } from "./screens/Authy";
import { Certificate } from "./screens/Certificate";
import { Cleanup } from "./screens/Cleanup";
import { Connect } from "./screens/Connect";
import { Destination } from "./screens/Destination";
import { Done } from "./screens/Done";
import { Unlock } from "./screens/Unlock";
import { Verify } from "./screens/Verify";
import { Welcome } from "./screens/Welcome";
import { en } from "./strings/en";
import { initialState, reduce } from "./wizard/machine";

const RAIL: readonly Exclude<Step, "done">[] = [
  "welcome", "connect", "certificate", "authy", "unlock", "destination", "verify", "cleanup",
];

export function App({ api, devTools }: { api: Api; devTools?: ReactNode }) {
  const [state, dispatch] = useReducer(reduce, undefined, initialState);
  const [loaded, setLoaded] = useState<"loading" | "ready" | "failed">("loading");
  const [proxy, setProxy] = useState<ProxyInfo | null>(null);
  const [proxyError, setProxyError] = useState(false);
  const [addressRejected, setAddressRejected] = useState<string | null>(null);
  const [restart, setRestart] = useState<RestartState>("idle");
  const [addressChanged, setAddressChanged] = useState(false);
  const proxyAsked = useRef(false);
  const proxyNow = useRef<ProxyInfo | null>(null);
  proxyNow.current = proxy;

  useEffect(() => {
    let live = true;
    api.getState()
      .then((app) => { if (live) { dispatch({ type: "loaded", app }); setLoaded("ready"); } })
      .catch(() => { if (live) setLoaded("failed"); });
    const off = api.onProxyEvent((event) => dispatch({ type: "proxy", event }));
    return () => { live = false; off(); };
  }, [api]);

  const startProxy = useCallback(() => {
    setProxyError(false);
    api.startProxy().then(setProxy).catch(() => setProxyError(true));
  }, [api]);

  // The shell refuses a new address once a backup is captured; the way through is a restart.
  const pickAddress = useCallback((ip: string) => {
    setAddressRejected(null);
    setAddressChanged(false);
    api.startProxy(ip).then(setProxy).catch(() => setAddressRejected(ip));
  }, [api]);

  const restartProxy = useCallback((ip?: string) => {
    const before = proxyNow.current;
    // Unless a new address was asked for, stay on the one the device is already set to.
    const keep = ip ?? before?.ip;
    setRestart("busy");
    // Reset progress now, not when the shell answers: events from the new proxy can arrive
    // first, and they must land on the reset state instead of being wiped by it.
    dispatch({ type: "restarting" });
    api.restartProxy(keep)
      .catch((err: unknown) => {
        // The address the device was using is gone (this computer's address changed):
        // fall back once to whatever address the shell picks.
        if (ip !== undefined || keep === undefined) throw err;
        return api.restartProxy();
      })
      .then((info) => {
        setProxy(info);
        setProxyError(false);
        setAddressRejected(null);
        setAddressChanged(before !== null && ip === undefined && (info.ip !== before.ip || info.port !== before.port));
        setRestart("idle");
      })
      .catch(() => setRestart("failed"));
  }, [api]);

  // The proxy starts when the person reaches the connect step, and only once.
  useEffect(() => {
    if (state.step !== "connect" || proxyAsked.current) return;
    proxyAsked.current = true;
    startProxy();
  }, [state.step, startProxy]);

  // Once cleanup begins the proxy is gone, and so is everything it told us.
  useEffect(() => {
    if (state.step === "cleanup") setProxy(null);
  }, [state.step]);

  const position = state.step === "done" ? RAIL.length : RAIL.indexOf(state.step);
  const props = { api, state, dispatch, proxy, onRestart: restartProxy, restart };

  return (
    <div className="app">
      <nav className="rail" aria-label={en.rail.label}>
        <p className="brand">{en.appName}</p>
        <ol>
          {RAIL.map((step, i) => {
            const status = i < position ? "done" : i === position ? "current" : "todo";
            return (
              <li key={step} className={status} aria-current={status === "current" ? "step" : undefined}>
                <span className="marker" aria-hidden="true">{status === "done" ? "✓" : i + 1}</span>
                <span>{en.rail.steps[step]}</span>
                {status === "done" && <span className="sr-only">{en.rail.finished}</span>}
              </li>
            );
          })}
        </ol>
        <div className="version">
          {state.version && <p>{en.rail.version(state.version)}</p>}
          {state.releasesUrl && (
            <p>
              {en.rail.releases}
              <span className="selectable">{state.releasesUrl}</span>
            </p>
          )}
        </div>
      </nav>
      {/* `key` remounts the screen on each step, which moves focus to its heading. */}
      <main className="main" key={state.step}>
        {loaded === "ready" && state.step !== "done" && (
          <p className="step-of">{en.common.stepOf(position + 1, RAIL.length, en.rail.steps[state.step])}</p>
        )}
        {loaded === "loading" && <p className="loading" role="status">{en.common.loading}</p>}
        {loaded === "failed" && <div className="screen-body"><Callout tone="error" title={en.common.loadFailed} alert /></div>}
        {loaded === "ready" && state.step === "welcome" && <Welcome {...props} />}
        {loaded === "ready" && state.step === "connect" && (
          <Connect {...props} proxyError={proxyError} addressRejected={addressRejected} addressChanged={addressChanged} onPickAddress={pickAddress} onRetry={startProxy} />
        )}
        {loaded === "ready" && state.step === "certificate" && <Certificate {...props} />}
        {loaded === "ready" && state.step === "authy" && <Authy {...props} />}
        {loaded === "ready" && state.step === "unlock" && <Unlock {...props} />}
        {loaded === "ready" && state.step === "destination" && <Destination {...props} />}
        {loaded === "ready" && state.step === "verify" && <Verify {...props} />}
        {loaded === "ready" && state.step === "cleanup" && <Cleanup {...props} />}
        {loaded === "ready" && state.step === "done" && <Done {...props} />}
      </main>
      {devTools}
    </div>
  );
}
