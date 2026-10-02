// Wording for the dev-only "pretend phone" panel. Kept out of `en.ts` so that none of it is
// bundled into the real app: only `dev/DevPanel.tsx` imports this file.
export const dev = {
  title: "Pretend phone",
  note: (password: string) => `Not the real app. Backup password: ${password}`,
  deviceConnected: "Device connects",
  trustWorking: "Trust works",
  tlsRejected: "Certificate refused",
  authyError: "Authy error",
  deviceRefused: "Other device refused",
  backupCaptured: "Backup captured",
  bwFail: "Next apply fails",
  bwFailMessage: "503 Service Unavailable",
  hide: "Hide",
  show: "Pretend phone",
} as const;
