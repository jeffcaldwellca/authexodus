// The shape of a failed command. The shell rejects with "<code>: <plain sentence>"; the Tauri
// binding turns that into an `ApiError` (in one place, `api.tauri.ts`), and the in-memory fake
// throws the same thing. Screens choose what to show and offer from `code`, and show
// `message`, the shell's own sentence, as the detail.

/** Every code the shell can reject with. Anything else is `internal`. */
export const ERROR_CODES = [
  "address_changed", "address_not_private", "no_private_address", "listen_failed", "keychain_failed",
  "capture_would_be_lost", "bad_email", "bad_server_url", "bw_download_failed", "bw_checksum_mismatch",
  "bw_unreachable", "bw_session_expired", "bw_vault_read_failed", "bw_failed", "not_unlocked", "no_backup",
  "export_failed", "cleanup_keychain_failed", "cleanup_failed", "internal",
] as const;

export type ErrorCode = (typeof ERROR_CODES)[number];

export function isErrorCode(text: string): text is ErrorCode {
  return (ERROR_CODES as readonly string[]).includes(text);
}

export class ApiError extends Error {
  readonly code: ErrorCode;
  constructor(code: ErrorCode, message: string) {
    super(message);
    this.name = "ApiError";
    this.code = code;
  }
}

/** Whatever was thrown, as an `ApiError`. Anything that is not one already is `internal`. */
export function asApiError(err: unknown): ApiError {
  if (err instanceof ApiError) return err;
  return new ApiError("internal", err instanceof Error ? err.message : String(err));
}
