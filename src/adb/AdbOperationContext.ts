/** Shared per-request state and result helpers for ADB operation handlers. */

import type {
  AdbOperation,
  AdbRequest,
} from "../domain/adb/adbDeviceAnalysis.js";
import type {
  AdbBinarySelection,
  AdbClientIdentity,
} from "./AdbConfiguration.js";
import { adbArguments, runAdb, type AdbRunLimits } from "./AdbCommand.js";
import type { PendingOutputDirectoryCleanup } from "./AdbOutputFiles.js";

/** Stable identity for the ADB device-acquisition provider. */
export const ADB_PROVIDER_IDENTITY = {
  id: "adb",
  name: "Android Debug Bridge",
  version: null,
} as const;

const UNPARSED_LINES_REPORTED = 10;

export const clientIdentityResult = (
  selection: AdbBinarySelection,
  identity: AdbClientIdentity,
) => ({
  binary_path: selection.binary,
  path_source: selection.pathSource,
  version: identity.version,
  installed_path: identity.installedPath,
});

type ClientIdentity = ReturnType<typeof clientIdentityResult>;
export type ProviderIdentity = {
  id: string;
  name: string;
  version: string | null;
};

/** Validated input for one ADB operation. */
export type AdbInput<Name extends AdbOperation> = Extract<
  AdbRequest,
  { operation: Name }
>["input"];

/** Everything an operation handler needs after the adb client was probed. */
export interface AdbOperationContext<Name extends AdbOperation = AdbOperation> {
  readonly operation: Name;
  readonly binary: string;
  readonly client: ClientIdentity;
  readonly provider: ProviderIdentity;
  readonly signal: AbortSignal | undefined;
  /** Hand an output directory whose removal failed to the provider for retry. */
  readonly retainOutputCleanup: (owner: PendingOutputDirectoryCleanup) => void;
}

export const reported = (
  unparsedLines: readonly string[],
  coverage: "complete" | "partial",
) => ({
  unparsed_lines: unparsedLines.slice(0, UNPARSED_LINES_REPORTED),
  coverage:
    coverage === "partial" || unparsedLines.length > 0 ? "partial" : "complete",
});

export const unparsedOverflowLimitation = (
  unparsedLines: readonly string[],
): string[] =>
  unparsedLines.length > UNPARSED_LINES_REPORTED
    ? [
        `unparsed_lines reports the first ${String(UNPARSED_LINES_REPORTED)} of ${String(unparsedLines.length)} unrecognized lines`,
      ]
    : [];

/** Run a device shell command against the operation's selected serial. */
export const runShell = (
  context: AdbOperationContext,
  serial: string,
  arguments_: readonly string[],
  limits: AdbRunLimits,
) =>
  runAdb(
    context.operation,
    serial,
    context.binary,
    adbArguments(serial, ["shell", ...arguments_]),
    limits,
    context.signal,
  );
