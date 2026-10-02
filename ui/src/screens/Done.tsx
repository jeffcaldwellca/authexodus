// The end of the wizard. After a run that moved codes: keep Authy around for a while, and
// set up again whatever could not move. After giving up: say so, and show the manual route.
import { Screen } from "../components/ui";
import { ManualGuide } from "../failures/ManualGuide";
import { en } from "../strings/en";
import { deviceLabel, type ScreenProps } from "./types";

const t = en.done;

export function Done({ state }: ScreenProps) {
  if (!state.moved) {
    return (
      <Screen title={t.titleNothingMoved} lede={t.bodyNothingMoved}>
        <ManualGuide />
        <p className="quiet-text">{t.close}</p>
      </Screen>
    );
  }
  return (
    <Screen title={t.title} lede={t.body(deviceLabel(state.device))}>
      {state.cantMove > 0 && <p className="strong">{t.notMoved(state.cantMove)}</p>}
      <p>{t.keepAuthy}</p>
      <p>{t.again}</p>
      <p className="quiet-text">{t.close}</p>
    </Screen>
  );
}
