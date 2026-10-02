// The confirmation before "Stop and clean up". Stopping destroys the capture and the
// certificate key, so the person is told what is lost and what they would have to redo.
import { Dialog } from "../components/Dialog";
import { en } from "../strings/en";

const t = en.failures.stop;

export function StopConfirm({ mentionAuthy, onCancel, onConfirm }: {
  /** The person may have deleted Authy already, so they must be told to finish signing in. */
  mentionAuthy: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  return (
    <Dialog title={t.title} variant="box" urgent onClose={onCancel}>
      <p>{t.lost}</p>
      <p>{t.redo}</p>
      {mentionAuthy && <p className="strong">{en.common.authyFinish}</p>}
      <div className="dialog-actions">
        <button type="button" className="primary" onClick={onCancel}>{en.common.keepGoing}</button>
        <button type="button" className="secondary danger" onClick={onConfirm}>{en.common.stopAndCleanUp}</button>
      </div>
    </Dialog>
  );
}
