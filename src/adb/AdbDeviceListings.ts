/** Read-only ADB device listings: processes, directory entries, features, and services. */

import {
  createAnalysisExecution,
  type AnalysisExecution,
} from "../application/AnalysisProvider.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { ok, type Result } from "../domain/result.js";
import {
  LISTING_MAX_OUTPUT_BYTES,
  LISTING_TIMEOUT_MS,
  adbArguments,
  runAdbCapture,
} from "./AdbCommand.js";
import {
  ADB_DIRECTORY_BATCH_SCRIPT,
  parseAdbDirectoryListing,
} from "./AdbDirectoryListing.js";
import {
  reported,
  runShell,
  unparsedOverflowLimitation,
  type AdbInput,
  type AdbOperationContext,
} from "./AdbOperationContext.js";
import {
  parseFeatureListOutput,
  parseProcessListOutput,
  parseServiceListOutput,
} from "./AdbShellOutput.js";

/** List device processes with `ps -A`. */
export const listProcesses = async (
  context: AdbOperationContext<"list_adb_processes">,
  input: AdbInput<"list_adb_processes">,
): Promise<Result<AnalysisExecution, AnalysisError>> => {
  const ran = await runShell(context, input.serial, ["ps", "-A"], {
    timeoutMs: LISTING_TIMEOUT_MS,
    maxOutputBytes: LISTING_MAX_OUTPUT_BYTES,
  });
  if (!ran.ok) return ran;
  const { columns, processes, unparsedLines } = parseProcessListOutput(
    ran.value.stdout,
  );
  return ok(
    createAnalysisExecution(
      {
        client: context.client,
        serial: input.serial,
        columns,
        processes,
        ...reported(unparsedLines, "complete"),
      },
      context.provider,
      { limitations: unparsedOverflowLimitation(unparsedLines) },
    ),
  );
};

/** List one device directory without following entries. */
export const listDirectory = async (
  context: AdbOperationContext<"list_adb_directory">,
  input: AdbInput<"list_adb_directory">,
): Promise<Result<AnalysisExecution, AnalysisError>> => {
  const ran = await runAdbCapture(
    context.operation,
    input.serial,
    context.binary,
    adbArguments(input.serial, [
      "shell",
      "sh",
      "-c",
      'cd "$1" || exit\nexec find . -mindepth 1 -maxdepth 1 -exec sh -c "$2" rea-list-directory {} +',
      "rea-list-directory",
      input.device_path,
      ADB_DIRECTORY_BATCH_SCRIPT,
    ]),
    {
      timeoutMs: LISTING_TIMEOUT_MS,
      maxOutputBytes: LISTING_MAX_OUTPUT_BYTES,
    },
    context.signal,
  );
  if (!ran.ok) return ran;
  const { entries, unparsedLines } = parseAdbDirectoryListing(ran.value.stdout);
  return ok(
    createAnalysisExecution(
      {
        client: context.client,
        serial: input.serial,
        device_path: input.device_path,
        entries,
        ...reported(unparsedLines, "complete"),
      },
      context.provider,
      {
        limitations: [
          "Entry kinds derive from stat permission mode; directory contents and link targets may change during capture",
          ...unparsedOverflowLimitation(unparsedLines),
        ],
      },
    ),
  );
};

/** List declared device features. */
export const listFeatures = async (
  context: AdbOperationContext<"list_adb_features">,
  input: AdbInput<"list_adb_features">,
): Promise<Result<AnalysisExecution, AnalysisError>> => {
  const ran = await runShell(
    context,
    input.serial,
    ["pm", "list", "features"],
    {
      timeoutMs: LISTING_TIMEOUT_MS,
      maxOutputBytes: LISTING_MAX_OUTPUT_BYTES,
    },
  );
  if (!ran.ok) return ran;
  const { features, unparsedLines } = parseFeatureListOutput(ran.value.stdout);
  return ok(
    createAnalysisExecution(
      {
        client: context.client,
        serial: input.serial,
        features,
        ...reported(unparsedLines, "complete"),
      },
      context.provider,
      { limitations: unparsedOverflowLimitation(unparsedLines) },
    ),
  );
};

/** List registered system services. */
export const listServices = async (
  context: AdbOperationContext<"list_adb_services">,
  input: AdbInput<"list_adb_services">,
): Promise<Result<AnalysisExecution, AnalysisError>> => {
  const ran = await runShell(context, input.serial, ["service", "list"], {
    timeoutMs: LISTING_TIMEOUT_MS,
    maxOutputBytes: LISTING_MAX_OUTPUT_BYTES,
  });
  if (!ran.ok) return ran;
  const { services, unparsedLines } = parseServiceListOutput(ran.value.stdout);
  return ok(
    createAnalysisExecution(
      {
        client: context.client,
        serial: input.serial,
        services,
        ...reported(unparsedLines, "complete"),
      },
      context.provider,
      { limitations: unparsedOverflowLimitation(unparsedLines) },
    ),
  );
};
