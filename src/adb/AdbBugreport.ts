/** ADB bugreport collection through an owned staging directory. */

import { lstat, mkdtemp } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";

import {
  createAnalysisExecution,
  type AnalysisExecution,
} from "../application/AnalysisProvider.js";
import type { AdbAcquiredFilePartialObservation } from "../domain/adb/adbDeviceAnalysis.js";
import {
  AnalysisCancelledError,
  AnalysisOutputError,
  AnalysisProtocolError,
} from "../domain/analysisErrorCore.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { analysisErrorWithCleanupFailure } from "../domain/analysisErrorCleanup.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  BUGREPORT_MAX_OUTPUT_BYTES,
  BUGREPORT_TIMEOUT_MS,
  adbArguments,
  hashAdbFile,
  runAdb,
} from "./AdbCommand.js";
import {
  ADB_PROVIDER_IDENTITY,
  type AdbInput,
  type AdbOperationContext,
} from "./AdbOperationContext.js";
import {
  ownedDirectoryIdentity,
  prepareOutputDirectory,
  publishBugreport,
  removeOwnedOutputDirectory,
  type OutputDirectoryIdentity,
} from "./AdbOutputFiles.js";
import { parseBugreportCopiedPath } from "./AdbShellOutput.js";

/** Collect a device bugreport archive through a staging directory. */
export const collectBugreport = async (
  context: AdbOperationContext<"collect_adb_bugreport">,
  input: AdbInput<"collect_adb_bugreport">,
): Promise<Result<AnalysisExecution, AnalysisError>> => {
  const { operation, binary, client, provider, signal } = context;
  const directory = await prepareOutputDirectory(
    operation,
    input.output_directory,
  );
  if (!directory.ok) return directory;
  let stagingDirectory: string;
  let stagingIdentity: OutputDirectoryIdentity | undefined;
  let retainedObservation: AdbAcquiredFilePartialObservation | undefined;
  let publishedPath: string | undefined;
  try {
    stagingDirectory = await mkdtemp(join(directory.value, ".rea-bugreport-"));
  } catch (cause) {
    return err(
      new AnalysisOutputError(
        operation,
        "The bugreport staging directory could not be created",
        { cause },
      ),
    );
  }
  const collectedResult = await (async (): Promise<
    Result<AnalysisExecution, AnalysisError>
  > => {
    let reportedPath: string | null = null;
    try {
      stagingIdentity = ownedDirectoryIdentity(await lstat(stagingDirectory));
      if (stagingIdentity === undefined)
        throw new Error(
          `The created bugreport staging output is not a regular directory: ${stagingDirectory}`,
        );
      const collected = await runAdb(
        operation,
        input.serial,
        binary,
        adbArguments(input.serial, ["bugreport", stagingDirectory]),
        {
          timeoutMs: BUGREPORT_TIMEOUT_MS,
          maxOutputBytes: BUGREPORT_MAX_OUTPUT_BYTES,
        },
        signal,
      );
      if (!collected.ok) return collected;
      reportedPath = parseBugreportCopiedPath(collected.value.stdout);
      if (reportedPath === null)
        return err(
          new AnalysisProtocolError(
            "adb bugreport did not report an archive path; the build may use an unsupported format",
          ),
        );
      if (dirname(resolve(reportedPath)) !== stagingDirectory)
        return err(
          new AnalysisProtocolError(
            `adb bugreport reported an archive outside its staging directory: ${reportedPath}`,
          ),
        );
      const archive = await lstat(reportedPath);
      if (!archive.isFile() || archive.isSymbolicLink())
        return err(
          new AnalysisProtocolError(
            `adb bugreport did not report a regular archive file: ${reportedPath}`,
          ),
        );
      retainedObservation = {
        provider_id: "adb",
        operation,
        result: {
          client,
          serial: input.serial,
          local_path: reportedPath,
          adb_reported_path: reportedPath,
          digest_status: "unknown",
        },
      };
      try {
        publishedPath = await publishBugreport(reportedPath, directory.value);
      } catch (cause) {
        return err(
          new AnalysisOutputError(
            operation,
            `The reported bugreport archive could not be published: ${reportedPath}`,
            { cause, partialObservation: retainedObservation },
          ),
        );
      }
      retainedObservation = {
        ...retainedObservation,
        result: { ...retainedObservation.result, local_path: publishedPath },
      };
      const digest = await hashAdbFile(publishedPath, operation, signal);
      const report = {
        client,
        serial: input.serial,
        local_path: publishedPath,
        bytes: digest.bytes,
        sha256: digest.sha256,
        adb_reported_path: reportedPath,
      };
      retainedObservation = {
        provider_id: "adb",
        operation,
        result: report,
      };
      return ok(
        createAnalysisExecution(report, provider, {
          limitations: [
            "The archive is device-generated: dumpstate, dumpsys, and logcat content is the device's own report",
          ],
        }),
      );
    } catch (cause) {
      if (cause instanceof AnalysisCancelledError) {
        if (retainedObservation !== undefined)
          cause.retainPartialObservation(retainedObservation);
        return err(cause);
      }
      return err(
        new AnalysisOutputError(
          operation,
          `The reported bugreport archive could not be read back: ${reportedPath ?? stagingDirectory}`,
          { cause, partialObservation: retainedObservation },
        ),
      );
    }
  })();
  // A completed acquisition becomes caller evidence even if publication fails.
  // Its staging directory must not enter automatic cleanup or cleanup retries.
  if (retainedObservation !== undefined && publishedPath === undefined)
    return collectedResult;
  try {
    await removeOwnedOutputDirectory(stagingDirectory, stagingIdentity);
  } catch (cause) {
    const primary = collectedResult.ok
      ? new AnalysisOutputError(
          operation,
          "The archive was published, but its staging directory could not be removed",
        )
      : collectedResult.error;
    if (retainedObservation !== undefined)
      primary.retainPartialObservation(retainedObservation);
    context.retainOutputCleanup({
      operation,
      path: stagingDirectory,
      identity: stagingIdentity,
      primary,
      remove: () =>
        removeOwnedOutputDirectory(stagingDirectory, stagingIdentity),
    });
    return err(
      analysisErrorWithCleanupFailure(
        primary,
        new ProviderCleanupError(
          ADB_PROVIDER_IDENTITY.id,
          [stagingDirectory],
          { reason: cause instanceof Error ? cause.message : String(cause) },
          { operation, cause },
        ),
        operation,
      ),
    );
  }
  return collectedResult;
};
