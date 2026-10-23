/** Device-mutating ADB app control: install, uninstall, start, and force-stop. */

import { stat } from "node:fs/promises";
import { resolve } from "node:path";

import {
  createAnalysisExecution,
  type AnalysisExecution,
} from "../application/AnalysisProvider.js";
import {
  adbResultSchemas,
  type AdbActivityStartPartialObservation,
} from "../domain/adb/adbDeviceAnalysis.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisUnsupportedTargetError,
} from "../domain/analysisErrorCore.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  PACKAGE_LIST_TIMEOUT_MS,
  PM_PATH_MAX_OUTPUT_BYTES,
  PULL_MAX_OUTPUT_BYTES,
  PULL_TIMEOUT_MS,
  SHELL_TIMEOUT_MS,
  adbArguments,
  hashAdbFile,
  runAdb,
} from "./AdbCommand.js";
import type { AdbInput, AdbOperationContext } from "./AdbOperationContext.js";
import {
  parseAmStartOutput,
  parsePackageChangeOutput,
  parseResolveActivityOutput,
} from "./AdbShellOutput.js";

/** Install a host APK on the device. */
export const installPackage = async (
  context: AdbOperationContext<"install_adb_package">,
  input: AdbInput<"install_adb_package">,
): Promise<Result<AnalysisExecution, AnalysisError>> => {
  const { operation, binary, client, provider, signal } = context;
  const apkPath = resolve(input.apk_path);
  const info = await stat(apkPath).then(
    (value) => value,
    () => null,
  );
  if (info === null || !info.isFile())
    return err(
      new AnalysisInputError(operation, {
        cause: new Error(`The local APK does not exist: ${apkPath}`),
      }),
    );
  let digest: Awaited<ReturnType<typeof hashAdbFile>>;
  try {
    digest = await hashAdbFile(apkPath, operation, signal);
  } catch (cause: unknown) {
    if (cause instanceof AnalysisCancelledError) return err(cause);
    throw cause;
  }
  const installed = await runAdb(
    operation,
    input.serial,
    binary,
    adbArguments(input.serial, [
      "install",
      ...(input.replace ? ["-r"] : []),
      apkPath,
    ]),
    { timeoutMs: PULL_TIMEOUT_MS, maxOutputBytes: PULL_MAX_OUTPUT_BYTES },
    signal,
  );
  if (!installed.ok) return installed;
  const verdict = parsePackageChangeOutput(installed.value.stdout);
  if (verdict.status === "failure")
    return err(
      new AnalysisUnsupportedTargetError(
        operation,
        input.serial,
        verdict.reason ?? "the device refused the installation",
      ),
    );
  return ok(
    createAnalysisExecution(
      {
        client,
        serial: input.serial,
        apk_path: apkPath,
        bytes: digest.bytes,
        sha256: digest.sha256,
        replaced: input.replace,
      },
      provider,
      {
        limitations: [
          "Install changes device state; the installed APK's digest is the host file's digest",
        ],
      },
    ),
  );
};

/** Uninstall a package for user 0. */
export const uninstallPackage = async (
  context: AdbOperationContext<"uninstall_adb_package">,
  input: AdbInput<"uninstall_adb_package">,
): Promise<Result<AnalysisExecution, AnalysisError>> => {
  const { operation, binary, client, provider, signal } = context;
  const uninstalled = await runAdb(
    operation,
    input.serial,
    binary,
    adbArguments(input.serial, ["uninstall", input.package]),
    {
      timeoutMs: PACKAGE_LIST_TIMEOUT_MS,
      maxOutputBytes: PULL_MAX_OUTPUT_BYTES,
    },
    signal,
  );
  if (!uninstalled.ok) return uninstalled;
  const verdict = parsePackageChangeOutput(uninstalled.value.stdout);
  if (verdict.status === "failure")
    return err(
      new AnalysisUnsupportedTargetError(
        operation,
        input.serial,
        verdict.reason ?? "the device refused the removal",
      ),
    );
  return ok(
    createAnalysisExecution(
      {
        client,
        serial: input.serial,
        package_name: input.package,
      },
      provider,
      {
        limitations: [
          "Uninstall removes the package and its data for user 0; keeping data (-k) is not exposed",
        ],
      },
    ),
  );
};

const runAmStart = async (
  context: AdbOperationContext<"start_adb_app" | "start_adb_activity">,
  serial: string,
  arguments_: readonly string[],
  resultFields: Record<string, unknown>,
): Promise<Result<AnalysisExecution, AnalysisError>> => {
  const { operation, binary, provider, signal } = context;
  const started = await runAdb(
    operation,
    serial,
    binary,
    adbArguments(serial, ["shell", "am", "start", "-W", ...arguments_]),
    { timeoutMs: SHELL_TIMEOUT_MS, maxOutputBytes: PM_PATH_MAX_OUTPUT_BYTES },
    signal,
  );
  if (!started.ok) return started;
  const verdict = parseAmStartOutput(
    started.value.stdout,
    started.value.stderr,
  );
  const result = {
    ...resultFields,
    started_activity: verdict.startedActivity,
    reported_activity: verdict.activity,
    reported_status: verdict.reportedStatus,
  };
  if (verdict.status === "refused") {
    const partialObservation: AdbActivityStartPartialObservation =
      operation === "start_adb_app"
        ? {
            provider_id: "adb",
            operation,
            result: adbResultSchemas.start_adb_app.parse(result),
          }
        : {
            provider_id: "adb",
            operation,
            result: adbResultSchemas.start_adb_activity.parse(result),
          };
    return err(
      new AnalysisUnsupportedTargetError(
        operation,
        serial,
        verdict.reason ?? "am start refused the intent",
        {
          capturedOutput: {
            stdout: started.value.stdout,
            stderr: started.value.stderr,
            truncated: false,
          },
          partialObservation,
        },
      ),
    );
  }
  return ok(
    createAnalysisExecution(result, provider, {
      rawResult: {
        stdout: started.value.stdout,
        stderr: started.value.stderr,
      },
      limitations: [
        "Starting an activity changes device state; am start -W waits for launch completion but no lifecycle observation is captured",
      ],
    }) as AnalysisExecution,
  );
};

/** Start a package's launcher activity. */
export const startApp = async (
  context: AdbOperationContext<"start_adb_app">,
  input: AdbInput<"start_adb_app">,
): Promise<Result<AnalysisExecution, AnalysisError>> => {
  const { operation, binary, client, signal } = context;
  const resolved = await runAdb(
    operation,
    input.serial,
    binary,
    adbArguments(input.serial, [
      "shell",
      "cmd",
      "package",
      "resolve-activity",
      "--brief",
      "-c",
      "android.intent.category.LAUNCHER",
      input.package,
    ]),
    { timeoutMs: SHELL_TIMEOUT_MS, maxOutputBytes: PM_PATH_MAX_OUTPUT_BYTES },
    signal,
  );
  if (!resolved.ok) return resolved;
  const component = parseResolveActivityOutput(resolved.value.stdout);
  if (component === null)
    return err(
      new AnalysisUnsupportedTargetError(
        operation,
        input.serial,
        `No launcher activity is declared for ${input.package}`,
      ),
    );
  return runAmStart(context, input.serial, ["-n", component], {
    client,
    serial: input.serial,
    package_name: input.package,
    component,
  });
};

/** Start an activity from a caller-described intent. */
export const startActivity = async (
  context: AdbOperationContext<"start_adb_activity">,
  input: AdbInput<"start_adb_activity">,
): Promise<Result<AnalysisExecution, AnalysisError>> => {
  const { operation, client } = context;
  const extraFlags: Record<
    "string" | "boolean" | "int" | "long" | "float",
    string
  > = {
    string: "--es",
    boolean: "--ez",
    int: "--ei",
    long: "--el",
    float: "--ef",
  };
  for (const extra of input.extras)
    if (extra.type === "boolean" && !/^(true|false)$/u.test(extra.value))
      return err(
        new AnalysisInputError(operation, {
          cause: new Error(`Boolean extra ${extra.key} must be true or false`),
        }),
      );
    else if (
      (extra.type === "int" || extra.type === "long") &&
      !/^-?\d+$/u.test(extra.value)
    )
      return err(
        new AnalysisInputError(operation, {
          cause: new Error(
            `${extra.type === "int" ? "Integer" : "Long"} extra ${extra.key} must be an integer`,
          ),
        }),
      );
    else if (extra.type === "float" && !/^-?\d+(\.\d+)?$/u.test(extra.value))
      return err(
        new AnalysisInputError(operation, {
          cause: new Error(`Float extra ${extra.key} must be a number`),
        }),
      );
  const arguments_ = [
    "-a",
    input.action,
    ...(input.data_uri === undefined ? [] : ["-d", input.data_uri]),
    ...(input.component === undefined ? [] : ["-n", input.component]),
    ...input.extras.flatMap((extra) => [
      extraFlags[extra.type],
      extra.key,
      extra.value,
    ]),
  ];
  return runAmStart(context, input.serial, arguments_, {
    client,
    serial: input.serial,
    action: input.action,
    data_uri: input.data_uri ?? null,
    component: input.component ?? null,
    extras: input.extras.map((extra) => ({ ...extra })),
  });
};

/** Force-stop a package. */
export const stopApp = async (
  context: AdbOperationContext<"stop_adb_app">,
  input: AdbInput<"stop_adb_app">,
): Promise<Result<AnalysisExecution, AnalysisError>> => {
  const { operation, binary, client, provider, signal } = context;
  const stopped = await runAdb(
    operation,
    input.serial,
    binary,
    adbArguments(input.serial, ["shell", "am", "force-stop", input.package]),
    { timeoutMs: SHELL_TIMEOUT_MS, maxOutputBytes: PM_PATH_MAX_OUTPUT_BYTES },
    signal,
  );
  if (!stopped.ok) return stopped;
  return ok(
    createAnalysisExecution(
      {
        client,
        serial: input.serial,
        package_name: input.package,
      },
      provider,
      {
        limitations: [
          "Force-stop succeeds even for packages with no running process; it reports completion, not prior state",
        ],
      },
    ),
  );
};
