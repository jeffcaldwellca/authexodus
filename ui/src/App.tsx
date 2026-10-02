// The wizard: one reducer, eight screens, and the wiring between the core's events and the
// reducer. The app holds no secrets here; screens that show one ask the core for it.
import { useCallback, useEffect, useReducer, useRef, useState, type ReactNode } from "react";
import type { Api, ProxyInfo, Step } from "./api";
import { asApiError, type ApiError } from "./api.errors";
import type { RestartState } from "./failures/ConnectionNotices";
import { Problem } from "./failures/Problem";
import { Authy } from "./screens/Authy";
import { Certificate } from "./screens/Certificate";
import { Cleanup } from "./screens/Cleanup";
import { Connect } from "./screens/Connect";
import { Destination } from "./screens/Destination";
import { Done } from "./screens/Done";
import { deviceLabel } from "./screens/types";
import { Unlock } from "./screens/Unlock";
import { Verify } from "./screens/Verify";
import { Welcome } from "./screens/Welcome";
import { en } from "./strings/en";
import { initialState, reduce } from "./wizard/machine";

const RAIL: readonly Exclude<Step, "done">[] = [
  "welcome", "connect", "certificate", "authy", "unlock", "destination", "verify", "cleanup",
];
/** While the connection is up, the person is reminded to keep the window and the Mac awake. */
const CONNECTED: readonly Step[] = ["connect", "certificate", "authy", "unlock", "destination", "verify"];
/** After one of these, asking again with no address lets the shell pick a new one. */
const ADDRESS_GONE = ["address_changed", "address_not_private", "internal"];

export function App({ api, devTools }: { api: Api; devTools?: ReactNode }) {
  const [state, dispatch] = useReducer(reduce, undefined, initialState);
  const [loaded, setLoaded] = useState<"loading" | "ready" | "failed">("loading");
  const [loadError, setLoadError] = useState<ApiError | null>(null);
  const [proxy, setProxy] = useState<ProxyInfo | null>(null);
  const [proxyError, setProxyError] = useState<ApiError | null>(null);
  const [addressRejected, setAddressRejected] = useState<string | null>(null);
  const [addressError, setAddressError] = useState<{ ip: string; error: ApiError } | null>(null);
  const [restart, setRestart] = useState<RestartState>("idle");
  const [restartError, setRestartError] = useState<ApiError | null>(null);
  const [addressChanged, setAddressChanged] = useState(false);
  /** Whether this run's certificate is limited to Authy. Outlives the proxy, for cleanup. */
  const [certConstrained, setCertConstrained] = useState<boolean | null>(null);
  const proxyAsked = useRef(false);
  const proxyNow = useRef<ProxyInfo | null>(null);
  proxyNow.current = proxy;
  const addressGone = useRef(false);
  addressGone.current = state.addressChanged;

  const gotProxy = useCallback((info: ProxyInfo) => {
    setProxy(info);
    setCertConstrained(info.certConstrained);
  }, []);

  const load = useCallback(() => {
    let live = true;
    setLoaded("loading");
    api.getState()
      .then((app) => {
        if (!live) return;
        // A reloaded window finds the run still going in the shell: pick it up, do not restart it.
        const running = app.session?.proxy ?? null;
        if (running) { proxyAsked.current = true; gotProxy(running); }
        dispatch({ type: "loaded", app });
        setLoaded("ready");
      })
      .catch((err: unknown) => { if (live) { setLoadError(asApiError(err)); setLoaded("failed"); } });
    return () => { live = false; };
  }, [api, gotProxy]);

  useEffect(() => {
    const stop = load();
    const off = api.onProxyEvent((event) => dispatch({ type: "proxy", event }));
    return () => { stop(); off(); };
  }, [api, load]);

  const startProxy = useCallback(() => {
    setProxyError(null);
    api.startProxy().then(gotProxy).catch((err: unknown) => setProxyError(asApiError(err)));
  }, [api, gotProxy]);

  // The shell refuses a new address once a backup is captured; the way through is a restart.
  const pickAddress = useCallback((ip: string) => {
    setAddressRejected(null);
    setAddressError(null);
    setAddressChanged(false);
    api.startProxy(ip).then(gotProxy).catch((err: unknown) => {
      const error = asApiError(err);
      if (error.code === "capture_would_be_lost") setAddressRejected(ip);
      else setAddressError({ ip, error });
    });
  }, [api, gotProxy]);

  const restartProxy = useCallback((ip?: string) => {
    const before = proxyNow.current;
    // Unless a new address was asked for, stay on the one the device is already set to. When
    // the shell has said that address is gone, let it choose.
    const keep = ip ?? (addressGone.current ? undefined : before?.ip);
    setRestart("busy");
    setRestartError(null);
    // Reset progress now, not when the shell answers: events from the new proxy can arrive
    // first, and they must land on the reset state instead of being wiped by it.
    dispatch({ type: "restarting" });
    api.restartProxy(keep)
      .catch((err: unknown) => {
        // The address the device was using is gone (this computer's address changed):
        // fall back once to whatever address the shell picks.
        if (ip !== undefined || keep === undefined || !ADDRESS_GONE.includes(asApiError(err).code)) throw err;
        return api.restartProxy();
      })
      .then((info) => {
        gotProxy(info);
        setProxyError(null);
        setAddressRejected(null);
        setAddressError(null);
        setAddressChanged(before !== null && ip === undefined && (info.ip !== before.ip || info.port !== before.port));
        setRestart("idle");
      })
      .catch((err: unknown) => { setRestartError(asApiError(err)); setRestart("failed"); });
  }, [api, gotProxy]);

  // The proxy starts when the person reaches the connect step, and only once per run.
  useEffect(() => {
    if (state.step !== "connect" || proxyAsked.current) return;
    proxyAsked.current = true;
    startProxy();
  }, [state.step, startProxy]);

  // Once cleanup begins the proxy is gone, and so is everything it told us.
  useEffect(() => {
    if (state.step === "cleanup") setProxy(null);
  }, [state.step]);

  // Back on the welcome screen (a new run after Done): nothing of the last run carries over.
  useEffect(() => {
    if (state.step !== "welcome") return;
    proxyAsked.current = false;
    setProxy(null);
    setProxyError(null);
    setAddressRejected(null);
    setAddressError(null);
    setAddressChanged(false);
    setRestart("idle");
    setRestartError(null);
    setCertConstrained(null);
  }, [state.step]);

  const position = state.step === "done" ? RAIL.length : RAIL.indexOf(state.step);
  const props = { api, state, dispatch, proxy, onRestart: restartProxy, restart, restartError, certConstrained };

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
      </nav>
      {/* Outside the step list, which is hidden in a narrow window: this is shown at every size. */}
      <div className="version">
        {state.version && <p>{en.rail.version(state.version)}</p>}
        {state.releasesUrl && (
          <p>
            {en.rail.releases}
            <span className="selectable">{state.releasesUrl}</span>
          </p>
        )}
      </div>
      {/* `key` remounts the screen on each step, which moves focus to its heading. */}
      <main className="main" key={state.step}>
        {loaded === "ready" && state.step !== "done" && (
          <p className="step-of">{en.common.stepOf(position + 1, RAIL.length, en.rail.steps[state.step])}</p>
        )}
        {loaded === "ready" && CONNECTED.includes(state.step) && (
          <p className="keep-open" role="note">{en.common.keepOpen(deviceLabel(state.device))}</p>
        )}
        {loaded === "loading" && <p className="loading" role="status">{en.common.loading}</p>}
        {loaded === "failed" && loadError && (
          <div className="screen-body">
            <Problem error={loadError} d={en.deviceName.either} title={en.common.loadFailed}>
              <p>{en.common.loadFailedHelp}</p>
              <button type="button" className="secondary" onClick={load}>{en.common.tryAgain}</button>
            </Problem>
          </div>
        )}
        {loaded === "ready" && state.step === "welcome" && <Welcome {...props} />}
        {loaded === "ready" && state.step === "connect" && (
          <Connect
            {...props}
            proxyError={proxyError}
            addressRejected={addressRejected}
            addressError={addressError}
            addressChanged={addressChanged}
            onPickAddress={pickAddress}
            onRetry={startProxy}
          />
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
