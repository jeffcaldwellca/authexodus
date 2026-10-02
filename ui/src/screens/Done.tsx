// The end of the wizard. After a run that moved codes: keep Authy around for a while, and
// set up again whatever could not move, by name. After giving up: say so, and show the
// manual route. By now the app has forgotten the codes and destroyed its key, so the only
// way to move them anywhere else is a new run from the beginning, and the screen says so.
import { Screen } from "../components/ui";
import { ManualGuide } from "../failures/ManualGuide";
import { en } from "../strings/en";
import { cantMoveCount } from "../wizard/machine";
import { deviceLabel, type ScreenProps } from "./types";

const t = en.done;

export function Done({ state, dispatch }: ScreenProps) {
  const d = deviceLabel(state.device);
  const cantMove = cantMoveCount(state);
  const names = [...state.cantMove.native, ...state.cantMove.invalid];
  const footer = (
    <>
      <p className="footer-hint">{t.close}</p>
      <button type="button" className="secondary" onClick={() => dispatch({ type: "startOver" })}>{t.startAgain}</button>
    </>
  );
  const notMoved = cantMove > 0 && (
    <>
      <p className="strong">{t.notMoved(cantMove)}</p>
      <ul className="plain-list" aria-label={t.notMovedLabel}>{names.map((name, i) => <li key={`${i}:${name}`}>{name}</li>)}</ul>
    </>
  );
  if (!state.moved) {
    return (
      <Screen title={t.titleNothingMoved} lede={t.bodyNothingMoved} footer={footer}>
        {notMoved}
        <ManualGuide />
        <p className="quiet-text">{t.again(d)}</p>
      </Screen>
    );
  }
  return (
    <Screen title={t.title} lede={t.body(d)} footer={footer}>
      {notMoved}
      <p>{t.keepAuthy}</p>
      <p>{t.again(d)}</p>
    </Screen>
  );
}
