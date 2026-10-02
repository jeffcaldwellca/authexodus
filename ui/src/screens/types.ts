import type { Dispatch } from "react";
import type { Api, Device, ProxyInfo } from "../api";
import { en } from "../strings/en";
import type { WizardEvent, WizardState } from "../wizard/machine";

/** What every screen is given. Screens hold no state of their own that outlives them. */
export type ScreenProps = {
  api: Api;
  state: WizardState;
  dispatch: Dispatch<WizardEvent>;
  proxy: ProxyInfo | null;
};

/** The device's name for sentences: the chosen one, or "iPhone or iPad" before the choice. */
export function deviceLabel(device: Device | null): string {
  return device ? en.deviceName[device] : en.deviceName.either;
}
