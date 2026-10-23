/** Single-file ADB transfers: pull, push, and screen capture. */

import { createHash } from "node:crypto";
import { stat, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";

import {
  createAnalysisExecution,
  type AnalysisExecution,
} from "../application/AnalysisProvider.js";
import {
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisProtocolError,
  AnalysisResourceConstraintError,
  AnalysisTimeoutError,
} from "../domain/analysisErrorCore.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  PULL_MAX_OUTPUT_BYTES,
  PULL_TIMEOUT_MS,
  SCREEN_MAX_OUTPUT_BYTES,
  SCREEN_TIMEOUT_MS,
  SETTINGS_TIMEOUT_MS,
  SHELL_TIMEOUT_MS,
  adbArguments,
  hashAdbFile,
  runAdb,
  runAdbCapture,
} from "./AdbCommand.js";
import { adbHostFileName } from "./AdbHostFileName.js";
import type { AdbInput, AdbOperationContext } from "./AdbOperationContext.js";
import {
  prepareOutputDirectory,
  refuseExistingTarget,
} from "./AdbOutputFiles.js";
import { parsePngDimensions } from "./AdbShellOutput.js";

/** Pull one device file to a new host file and digest it. */
export const pullFile = async (
  context: AdbOperationContext<"pull_adb_file">,
  input: AdbInput<"pull_adb_file">,
): Promise<Result<AnalysisExecution, AnalysisError>> => {
  const { operation, binary, client, provider, signal } = context;
  const derived = adbHostFileName(input.device_path);
  if (!derived.ok)
    return err(
      new AnalysisInputError(operation, undefined, [
        {
          path: ["device_path"],
          reason: "invalid_value",
          message: `The device path ${JSON.stringify(input.device_path)} does not name a file that can be written on this host (${derived.reason}); REA never renames a device-reported file.`,
        },
      ]),
    );
  const directory = await prepareOutputDirectory(
    operation,
    input.output_directory,
  );
  if (!directory.ok) return directory;
  const localPath = join(directory.value, derived.fileName);
  const existing = await refuseExistingTarget(operation, localPath);
  if (existing !== undefined) return err(existing);
  const pulled = await runAdb(
    operation,
    input.serial,
    binary,
    adbArguments(input.serial, ["pull", input.device_path, localPath]),
    { timeoutMs: PULL_TIMEOUT_MS, maxOutputBytes: PULL_MAX_OUTPUT_BYTES },
    signal,
  );
  if (!pulled.ok) return pulled;
  try {
    const digest = await hashAdbFile(localPath, operation, signal);
    return ok(
      createAnalysisExecution(
        {
          client,
          serial: input.serial,
          device_path: input.device_path,
          local_path: localPath,
          bytes: digest.bytes,
          sha256: digest.sha256,
        },
        provider,
        {
          limitations: [
            "The pulled file is a host-local copy; the device retains the original",
          ],
        },
      ),
    );
  } catch (cause) {
    if (cause instanceof AnalysisCancelledError) {
      cause.retainPartialObservation({
        provider_id: "adb",
        operation,
        result: {
          client,
          serial: input.serial,
          local_path: localPath,
          device_path: input.device_path,
          digest_status: "unknown",
        },
      });
      return err(cause);
    }
    return err(
      new AnalysisOutputError(
        operation,
        `The pulled file could not be read back after pulling: ${localPath}`,
        { cause },
      ),
    );
  }
};

/** Push a host file to the device and verify the device-side digest when available. */
export const pushFile = async (
  context: AdbOperationContext<"push_adb_file">,
  input: AdbInput<"push_adb_file">,
): Promise<Result<AnalysisExecution, AnalysisError>> => {
  const { operation, binary, client, provider, signal } = context;
  const localPath = resolve(input.local_path);
  const info = await stat(localPath).then(
    (value) => value,
    () => null,
  );
  if (info === null || !info.isFile())
    return err(
      new AnalysisInputError(operation, {
        cause: new Error(`The local file does not exist: ${localPath}`),
      }),
    );
  let digest: Awaited<ReturnType<typeof hashAdbFile>>;
  try {
    digest = await hashAdbFile(localPath, operation, signal);
  } catch (cause: unknown) {
    if (cause instanceof AnalysisCancelledError) return err(cause);
    throw cause;
  }
  const existsProbe = await runAdb(
    operation,
    input.device_path,
    binary,
    adbArguments(input.serial, ["shell", "test", "-e", input.device_path]),
    { timeoutMs: SETTINGS_TIMEOUT_MS, maxOutputBytes: 1024 },
    signal,
  );
  let deviceExists: boolean;
  if (existsProbe.ok) deviceExists = true;
  else if (existsProbe.error instanceof AnalysisProtocolError)
    deviceExists = false;
  else if (existsProbe.error instanceof AnalysisTimeoutError)
    return existsProbe;
  else if (existsProbe.error instanceof AnalysisCancelledError)
    return existsProbe;
  else if (existsProbe.error instanceof AnalysisResourceConstraintError)
    return existsProbe;
  else deviceExists = true; // authorization/refusal states surface on push instead
  if (deviceExists && !input.overwrite)
    return err(
      new AnalysisOutputError(
        operation,
        `The device path already exists and overwrite was not requested: ${input.device_path}`,
      ),
    );
  const pushed = await runAdb(
    operation,
    input.device_path,
    binary,
    adbArguments(input.serial, ["push", localPath, input.device_path]),
    { timeoutMs: PULL_TIMEOUT_MS, maxOutputBytes: PULL_MAX_OUTPUT_BYTES },
    signal,
  );
  if (!pushed.ok) return pushed;
  const deviceDigest = await runAdb(
    operation,
    input.device_path,
    binary,
    adbArguments(input.serial, ["shell", "sha256sum", input.device_path]),
    { timeoutMs: SHELL_TIMEOUT_MS, maxOutputBytes: 1024 },
    signal,
  );
  if (deviceDigest.ok) {
    const digestMatch = /^([a-f0-9]{64})\s/u.exec(deviceDigest.value.stdout);
    if (digestMatch !== null && digestMatch[1] !== digest.sha256)
      return err(
        new AnalysisArtifactChangedError(
          operation,
          input.device_path,
          `The device-reported digest does not match the pushed local file: ${localPath}`,
        ),
      );
    return ok(
      createAnalysisExecution(
        {
          client,
          serial: input.serial,
          local_path: localPath,
          device_path: input.device_path,
          bytes: digest.bytes,
          sha256: digest.sha256,
          device_sha256: digestMatch?.[1] ?? null,
          overwritten: deviceExists,
          device_digest_source: "device_sha256sum",
        },
        provider,
        {
          limitations: [
            "Push writes the caller's file to the device; this is the only device-mutating ADB tool",
          ],
        },
      ),
    );
  }
  return ok(
    createAnalysisExecution(
      {
        client,
        serial: input.serial,
        local_path: localPath,
        device_path: input.device_path,
        bytes: digest.bytes,
        sha256: digest.sha256,
        device_sha256: null,
        overwritten: deviceExists,
        device_digest_source: "unavailable",
      },
      provider,
      {
        limitations: [
          "The device did not answer sha256sum, so the transfer is not device-side verified",
          "Push writes the caller's file to the device; this is the only device-mutating ADB tool",
        ],
      },
    ),
  );
};

/** Capture one PNG frame of the device screen. */
export const captureScreen = async (
  context: AdbOperationContext<"capture_adb_screen">,
  input: AdbInput<"capture_adb_screen">,
): Promise<Result<AnalysisExecution, AnalysisError>> => {
  const { operation, binary, client, provider, signal } = context;
  const directory = await prepareOutputDirectory(
    operation,
    input.output_directory,
  );
  if (!directory.ok) return directory;
  const localPath = join(directory.value, "screen.png");
  const existing = await refuseExistingTarget(operation, localPath);
  if (existing !== undefined) return err(existing);
  const captured = await runAdbCapture(
    operation,
    input.serial,
    binary,
    adbArguments(input.serial, ["exec-out", "screencap", "-p"]),
    { timeoutMs: SCREEN_TIMEOUT_MS, maxOutputBytes: SCREEN_MAX_OUTPUT_BYTES },
    signal,
  );
  if (!captured.ok) return captured;
  const dimensions = parsePngDimensions(captured.value.stdout);
  if (dimensions.width === null)
    return err(
      new AnalysisProtocolError(
        "screencap did not return a PNG payload; the device may not expose a display",
      ),
    );
  try {
    await writeFile(localPath, captured.value.stdout, { flag: "wx" });
  } catch (cause) {
    return err(
      new AnalysisOutputError(
        operation,
        `The screen output could not be created exclusively: ${localPath}`,
        { cause },
      ),
    );
  }
  const sha256 = createHash("sha256")
    .update(captured.value.stdout)
    .digest("hex");
  return ok(
    createAnalysisExecution(
      {
        client,
        serial: input.serial,
        local_path: localPath,
        bytes: captured.value.stdout.byteLength,
        sha256,
        width: dimensions.width,
        height: dimensions.height,
      },
      provider,
      {
        limitations: [
          "The capture is one frame at read time; no recording or interaction occurred",
        ],
      },
    ),
  );
};
