/** ADB package acquisition: pull every APK of one package into an owned directory. */

import { lstat, mkdir } from "node:fs/promises";
import { join } from "node:path";

import {
  createAnalysisExecution,
  type AnalysisExecution,
} from "../application/AnalysisProvider.js";
import {
  AnalysisCancelledError,
  AnalysisOutputError,
  AnalysisProtocolError,
  AnalysisUnsupportedTargetError,
} from "../domain/analysisErrorCore.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { analysisErrorWithCleanupFailure } from "../domain/analysisErrorCleanup.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  PM_PATH_MAX_OUTPUT_BYTES,
  PM_PATH_TIMEOUT_MS,
  PULL_MAX_OUTPUT_BYTES,
  PULL_TIMEOUT_MS,
  adbArguments,
  hashAdbFile,
  runAdb,
} from "./AdbCommand.js";
import { parsePmPathOutput } from "./AdbDeviceOutput.js";
import {
  ADB_PROVIDER_IDENTITY,
  type AdbInput,
  type AdbOperationContext,
} from "./AdbOperationContext.js";
import {
  ownedDirectoryIdentity,
  prepareOutputDirectory,
  removeOwnedOutputDirectory,
  reservePackageDestinations,
  type OutputDirectoryIdentity,
  type PendingOutputDirectoryCleanup,
} from "./AdbOutputFiles.js";

/** Resolve the package's APK paths, refusing any that cannot be pulled to unique host files. */
const resolvePackageApkPaths = async (
  context: AdbOperationContext<"pull_adb_package">,
  input: AdbInput<"pull_adb_package">,
) => {
  const { operation, binary, signal } = context;
  const { serial, package: packageName } = input;
  const paths = await runAdb(
    operation,
    serial,
    binary,
    adbArguments(serial, ["shell", "pm", "path", packageName]),
    {
      timeoutMs: PM_PATH_TIMEOUT_MS,
      maxOutputBytes: PM_PATH_MAX_OUTPUT_BYTES,
    },
    signal,
  );
  if (!paths.ok) return paths;
  const parsed = parsePmPathOutput(paths.value.stdout);
  const capturedOutput = {
    stdout: paths.value.stdout,
    stderr: paths.value.stderr,
    truncated: false,
  };
  if (parsed.rejectedPaths.length > 0)
    return err(
      new AnalysisOutputError(
        operation,
        `Package Manager reported paths that cannot be represented as host files: ${parsed.rejectedPaths.map((entry) => `${JSON.stringify(entry.device_path)} (${entry.reason})`).join(", ")}`,
        { capturedOutput },
      ),
    );
  if (parsed.paths.length === 0 && parsed.unparsedLines.length === 0)
    return err(
      new AnalysisUnsupportedTargetError(
        operation,
        serial,
        `Package Manager reported no APK paths for ${packageName}; it may not be installed for user 0`,
      ),
    );
  if (parsed.unparsedLines.length > 0)
    return err(
      new AnalysisProtocolError(
        `pm path reported an unrecognized line: ${parsed.unparsedLines[0]}`,
        { capturedOutput },
      ),
    );
  const destinationNames = new Set<string>();
  for (const entry of parsed.paths) {
    if (destinationNames.has(entry.file_name))
      return err(
        new AnalysisOutputError(
          operation,
          `Package Manager reported multiple paths with the same local destination ${JSON.stringify(entry.file_name)}; refusing before pulling any files`,
          { capturedOutput },
        ),
      );
    destinationNames.add(entry.file_name);
  }
  return ok({ paths: parsed.paths, capturedOutput });
};

/** Pull every APK Package Manager reports for one package into an owned directory. */
export const pullPackage = async (
  context: AdbOperationContext<"pull_adb_package">,
  input: AdbInput<"pull_adb_package">,
): Promise<Result<AnalysisExecution, AnalysisError>> => {
  const { operation, binary, client, provider, signal } = context;
  const { serial, package: packageName } = input;
  const resolved = await resolvePackageApkPaths(context, input);
  if (!resolved.ok) return resolved;
  const { paths, capturedOutput } = resolved.value;
  const directory = await prepareOutputDirectory(
    operation,
    input.output_directory,
  );
  if (!directory.ok) return directory;
  const packageDirectory = join(directory.value, packageName);
  let packageDirectoryCreated = false;
  let packageDirectoryIdentity: OutputDirectoryIdentity | undefined;
  const packageOwner = (
    primary: AnalysisError,
  ): PendingOutputDirectoryCleanup => ({
    operation,
    path: packageDirectory,
    identity: packageDirectoryIdentity,
    primary,
    remove: () =>
      removeOwnedOutputDirectory(packageDirectory, packageDirectoryIdentity),
  });
  try {
    if (
      await lstat(packageDirectory).then(
        () => true,
        () => false,
      )
    )
      throw new Error(
        `The package output directory already exists: ${packageDirectory}`,
      );
    await mkdir(packageDirectory);
    packageDirectoryCreated = true;
    packageDirectoryIdentity = ownedDirectoryIdentity(
      await lstat(packageDirectory),
    );
    if (packageDirectoryIdentity === undefined)
      throw new Error(
        `The created package output is not a regular directory: ${packageDirectory}`,
      );
  } catch (cause) {
    const primary = new AnalysisOutputError(
      operation,
      cause instanceof Error ? cause.message : String(cause),
      { cause },
    );
    if (!packageDirectoryCreated) return err(primary);
    context.retainOutputCleanup(packageOwner(primary));
    const cleanup = new ProviderCleanupError(
      ADB_PROVIDER_IDENTITY.id,
      [packageDirectory],
      {
        reason: "Could not establish an owned package directory identity",
      },
      { operation, cause },
    );
    return err(analysisErrorWithCleanupFailure(primary, cleanup, operation));
  }
  const failOwnedPackage = async (
    primary: AnalysisError,
  ): Promise<Result<AnalysisExecution, AnalysisError>> => {
    const owner = packageOwner(primary);
    try {
      await owner.remove();
    } catch (cause: unknown) {
      context.retainOutputCleanup(owner);
      const cleanup = new ProviderCleanupError(
        ADB_PROVIDER_IDENTITY.id,
        [packageDirectory],
        { reason: cause instanceof Error ? cause.message : String(cause) },
        { operation, cause },
      );
      return err(analysisErrorWithCleanupFailure(primary, cleanup, operation));
    }
    return err(primary);
  };
  const destinationError = await reservePackageDestinations(
    operation,
    packageDirectory,
    paths,
    capturedOutput,
  );
  if (destinationError !== undefined) return failOwnedPackage(destinationError);
  const artifacts: {
    device_path: string;
    file_name: string;
    local_path: string;
    bytes: number;
    sha256: string;
    role: "base" | "split" | "unknown";
    role_basis: "file_name";
  }[] = [];
  const failures: {
    device_path: string | null;
    stage: "resolve_paths" | "pull" | "digest";
    message: string;
  }[] = [];
  const cancelledPackagePull = (
    error: AnalysisCancelledError,
    localPath: string,
    devicePath: string,
    stage: "pull" | "digest",
  ) => {
    error.retainPartialObservation({
      provider_id: "adb",
      operation,
      result: {
        client,
        serial,
        package_name: packageName,
        output_directory: directory.value,
        artifacts,
        failures: [
          ...failures,
          {
            device_path: devicePath,
            stage,
            message:
              stage === "pull"
                ? `Pull cancelled; any incomplete file is retained at ${localPath}. Remaining APKs were not attempted.`
                : `Digesting the pulled file was cancelled; the file is retained at ${localPath}. Remaining APKs were not attempted.`,
          },
        ],
        coverage: "partial",
      },
    });
    return err(error);
  };
  for (const entry of paths) {
    const localPath = join(packageDirectory, entry.file_name);
    const pulled = await runAdb(
      operation,
      serial,
      binary,
      adbArguments(serial, ["pull", entry.device_path, localPath]),
      { timeoutMs: PULL_TIMEOUT_MS, maxOutputBytes: PULL_MAX_OUTPUT_BYTES },
      signal,
    );
    if (!pulled.ok) {
      if (pulled.error instanceof AnalysisCancelledError)
        return cancelledPackagePull(
          pulled.error,
          localPath,
          entry.device_path,
          "pull",
        );
      failures.push({
        device_path: entry.device_path,
        stage: "pull",
        message: pulled.error.message,
      });
      continue;
    }
    try {
      const digest = await hashAdbFile(localPath, operation, signal);
      artifacts.push({
        device_path: entry.device_path,
        file_name: entry.file_name,
        local_path: localPath,
        bytes: digest.bytes,
        sha256: digest.sha256,
        role: entry.role,
        role_basis: "file_name",
      });
    } catch (cause: unknown) {
      if (cause instanceof AnalysisCancelledError)
        return cancelledPackagePull(
          cause,
          localPath,
          entry.device_path,
          "digest",
        );
      failures.push({
        device_path: entry.device_path,
        stage: "digest",
        message: `The pulled file could not be read back after pulling: ${localPath}`,
      });
    }
  }
  if (artifacts.length === 0 && failures.length > 0) {
    const primary = new AnalysisProtocolError(
      `Every APK pull failed for ${packageName} on ${serial}: ${failures[0]!.message}`,
    );
    return failOwnedPackage(primary);
  }
  return ok(
    createAnalysisExecution(
      {
        client,
        serial,
        package_name: packageName,
        output_directory: directory.value,
        artifacts,
        failures,
        coverage: failures.length === 0 ? "complete" : "partial",
      },
      provider,
      {
        limitations: [
          "APK role names derive from the pulled file names (base.apk, split_*.apk)",
          "Pulled artifacts are host-local copies; the device retains the originals",
        ],
      },
    ),
  );
};
