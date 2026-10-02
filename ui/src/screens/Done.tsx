// The end of the wizard. Nothing left to do but keep Authy around for a while.
import { Screen } from "../components/ui";
import { en } from "../strings/en";
import { deviceLabel, type ScreenProps } from "./types";

const t = en.done;

export function Done({ state }: ScreenProps) {
  return (
    <Screen title={t.title} lede={t.body(deviceLabel(state.device))}>
      <p>{t.keepAuthy}</p>
      <p className="quiet-text">{t.close}</p>
    </Screen>
  );
}
