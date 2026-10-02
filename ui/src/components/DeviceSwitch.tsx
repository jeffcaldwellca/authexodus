// A small way to put a wrong device choice right. Offered only on the first two steps, before
// anything is deleted: the drawings and the wording follow the choice at once.
import type { Device } from "../api";
import { en } from "../strings/en";
import type { ScreenProps } from "../screens/types";

export function DeviceSwitch({ api, state, dispatch }: Pick<ScreenProps, "api" | "state" | "dispatch">) {
  const other: Device = state.device === "ipad" ? "iphone" : "ipad";
  const change = () => {
    dispatch({ type: "chooseDevice", device: other });
    void api.setDevice(other).catch(() => undefined);
  };
  return (
    <p className="device-switch">
      <button type="button" className="quiet small" onClick={change}>{en.common.switchDevice(en.deviceName[other])}</button>
    </p>
  );
}
