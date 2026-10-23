/** Read-only ADB device queries: each runs bounded adb commands and parses their output. */

import {
  createAnalysisExecution,
  type AnalysisExecution,
} from "../application/AnalysisProvider.js";
import {
  AnalysisProtocolError,
  AnalysisUnsupportedTargetError,
} from "../domain/analysisErrorCore.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  DEVICES_MAX_OUTPUT_BYTES,
  DEVICES_TIMEOUT_MS,
  DUMPSYS_PACKAGE_MAX_OUTPUT_BYTES,
  DUMPSYS_PACKAGE_TIMEOUT_MS,
  DUMPSYS_WINDOW_MAX_OUTPUT_BYTES,
  GETPROP_MAX_OUTPUT_BYTES,
  LOGCAT_MAX_OUTPUT_BYTES,
  LOGCAT_TIMEOUT_MS,
  PACKAGE_LIST_MAX_OUTPUT_BYTES,
  PACKAGE_LIST_TIMEOUT_MS,
  SETTINGS_MAX_OUTPUT_BYTES,
  SETTINGS_TIMEOUT_MS,
  SHELL_TIMEOUT_MS,
  runAdb,
} from "./AdbCommand.js";
import {
  parseAdbDevicesOutput,
  parseGetpropOutput,
  parsePackageListOutput,
} from "./AdbDeviceOutput.js";
import {
  reported,
  runShell,
  unparsedOverflowLimitation,
  type AdbInput,
  type AdbOperationContext,
} from "./AdbOperationContext.js";
import {
  parseDumpsysPackageOutput,
  parseSettingsGetOutput,
  parseWindowFocusOutput,
  parseWmDensityOutput,
  parseWmSizeOutput,
} from "./AdbShellOutput.js";

/** Enumerate attached devices with `adb devices -l`. */
export const listDevices = async (
  context: AdbOperationContext<"list_adb_devices">,
): Promise<Result<AnalysisExecution, AnalysisError>> => {
  const ran = await runAdb(
    context.operation,
    "adb-devices",
    context.binary,
    ["devices", "-l"],
    {
      timeoutMs: DEVICES_TIMEOUT_MS,
      maxOutputBytes: DEVICES_MAX_OUTPUT_BYTES,
    },
    context.signal,
  );
  if (!ran.ok) return ran;
  const { devices, unparsedLines, daemonStarted } = parseAdbDevicesOutput(
    ran.value.stdout,
  );
  if (unparsedLines.length > 0)
    return err(
      new AnalysisProtocolError(
        `adb devices reported an unrecognized line: ${unparsedLines[0]}`,
      ),
    );
  return ok(
    createAnalysisExecution(
      {
        client: context.client,
        devices,
        may_have_started_adb_server: daemonStarted,
      },
      context.provider,
      {
        limitations: [
          "Device kind is inferred from the emulator serial prefix and USB transport metadata, not from device attestation",
          "Kind stays unknown for TCP transports unless the serial is an emulator port",
        ],
      },
    ),
  );
};

/** Read whitelisted build identity properties. */
export const inspectDevice = async (
  context: AdbOperationContext<"inspect_adb_device">,
  input: AdbInput<"inspect_adb_device">,
): Promise<Result<AnalysisExecution, AnalysisError>> => {
  const ran = await runShell(context, input.serial, ["getprop"], {
    timeoutMs: SHELL_TIMEOUT_MS,
    maxOutputBytes: GETPROP_MAX_OUTPUT_BYTES,
  });
  if (!ran.ok) return ran;
  const { properties, emulatorObserved } = parseGetpropOutput(ran.value.stdout);
  return ok(
    createAnalysisExecution(
      {
        client: context.client,
        serial: input.serial,
        properties,
        property_count: properties.length,
        emulator_observed: emulatorObserved,
      },
      context.provider,
      {
        limitations: [
          "Properties are a fixed whitelist of build identity facts, not the full getprop dump",
          "emulator_observed is null when the build does not report ro.kernel.qemu",
        ],
      },
    ),
  );
};

/** List installed packages with their base APK paths. */
export const listPackages = async (
  context: AdbOperationContext<"list_adb_packages">,
  input: AdbInput<"list_adb_packages">,
): Promise<Result<AnalysisExecution, AnalysisError>> => {
  const scopeFlag =
    input.scope === "third_party"
      ? "-3"
      : input.scope === "system"
        ? "-s"
        : null;
  const ran = await runShell(
    context,
    input.serial,
    [
      "pm",
      "list",
      "packages",
      "-f",
      ...(scopeFlag === null ? [] : [scopeFlag]),
    ],
    {
      timeoutMs: PACKAGE_LIST_TIMEOUT_MS,
      maxOutputBytes: PACKAGE_LIST_MAX_OUTPUT_BYTES,
    },
  );
  if (!ran.ok) return ran;
  const { packages, unparsedLines } = parsePackageListOutput(ran.value.stdout);
  return ok(
    createAnalysisExecution(
      {
        client: context.client,
        serial: input.serial,
        scope: input.scope,
        packages,
        ...reported(unparsedLines, "complete"),
      },
      context.provider,
      {
        limitations: [
          "base_apk_device_path is a device filesystem path, not a host-local path",
          ...unparsedOverflowLimitation(unparsedLines),
        ],
      },
    ),
  );
};

/** Read a bounded logcat dump. */
export const readLogcat = async (
  context: AdbOperationContext<"read_adb_logcat">,
  input: AdbInput<"read_adb_logcat">,
): Promise<Result<AnalysisExecution, AnalysisError>> => {
  const ran = await runShell(
    context,
    input.serial,
    [
      "logcat",
      "-d",
      "-b",
      input.buffer,
      "-t",
      String(input.count),
      ...(input.pid === undefined ? [] : ["--pid", String(input.pid)]),
    ],
    {
      timeoutMs: LOGCAT_TIMEOUT_MS,
      maxOutputBytes: LOGCAT_MAX_OUTPUT_BYTES,
    },
  );
  if (!ran.ok) return ran;
  const lines = ran.value.stdout.split(/\r?\n/u);
  if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  const bounded = lines.slice(-input.count);
  return ok(
    createAnalysisExecution(
      {
        client: context.client,
        serial: input.serial,
        count: input.count,
        buffer: input.buffer,
        pid: input.pid ?? null,
        lines: bounded,
        total_bytes: ran.value.stdoutBytes,
        coverage:
          bounded.length !== lines.length || bounded.length === input.count
            ? "partial"
            : "complete",
      },
      context.provider,
      {
        limitations: [
          "Reads a bounded dump (logcat -d); the newest lines are kept when the count cap trims",
          "coverage is partial when the requested count or capture budget truncated the dump",
        ],
      },
    ),
  );
};

/** Project `dumpsys package` facts for one package. */
export const inspectPackage = async (
  context: AdbOperationContext<"inspect_adb_package">,
  input: AdbInput<"inspect_adb_package">,
): Promise<Result<AnalysisExecution, AnalysisError>> => {
  const ran = await runShell(
    context,
    input.serial,
    ["dumpsys", "package", input.package],
    {
      timeoutMs: DUMPSYS_PACKAGE_TIMEOUT_MS,
      maxOutputBytes: DUMPSYS_PACKAGE_MAX_OUTPUT_BYTES,
    },
  );
  if (!ran.ok) return ran;
  const stdout = ran.value.stdout;
  if (/Unable to find package:/u.test(stdout) || stdout.trim() === "")
    return err(
      new AnalysisUnsupportedTargetError(
        context.operation,
        input.serial,
        `Package Manager did not report details for ${input.package}; it may not be installed for user 0`,
      ),
    );
  const details = parseDumpsysPackageOutput(stdout);
  return ok(
    createAnalysisExecution(
      {
        client: context.client,
        serial: input.serial,
        package_name: input.package,
        version_name: details.versionName,
        version_code: details.versionCode,
        first_install_time: details.firstInstallTime,
        last_update_time: details.lastUpdateTime,
        installer_package_name: details.installerPackageName,
        user_id: details.userId,
        pkg_flags: details.pkgFlags,
        requested_permissions_count: details.requestedPermissions,
        coverage:
          details.versionCode === null && details.versionName === null
            ? "partial"
            : "complete",
      },
      context.provider,
      {
        limitations: [
          "Fields are a fixed projection of dumpsys package output; version-dependent sections are ignored rather than guessed",
          "requested_permissions_count counts the listed requested permissions section only",
        ],
      },
    ),
  );
};

/** Read physical and override display size and density. */
export const inspectDisplay = async (
  context: AdbOperationContext<"inspect_adb_display">,
  input: AdbInput<"inspect_adb_display">,
): Promise<Result<AnalysisExecution, AnalysisError>> => {
  const size = await runShell(context, input.serial, ["wm", "size"], {
    timeoutMs: SETTINGS_TIMEOUT_MS,
    maxOutputBytes: SETTINGS_MAX_OUTPUT_BYTES,
  });
  if (!size.ok) return size;
  const density = await runShell(context, input.serial, ["wm", "density"], {
    timeoutMs: SETTINGS_TIMEOUT_MS,
    maxOutputBytes: SETTINGS_MAX_OUTPUT_BYTES,
  });
  if (!density.ok) return density;
  const parsedSize = parseWmSizeOutput(size.value.stdout);
  if (parsedSize.physical === null)
    return err(
      new AnalysisProtocolError(
        "wm size did not report a physical size; the build may use an unsupported format",
      ),
    );
  const parsedDensity = parseWmDensityOutput(density.value.stdout);
  return ok(
    createAnalysisExecution(
      {
        client: context.client,
        serial: input.serial,
        physical_size: parsedSize.physical,
        override_size: parsedSize.override,
        physical_density: parsedDensity.physical,
        override_density: parsedDensity.override,
      },
      context.provider,
      {
        limitations: [
          "Override values are present only when a build has overridden the physical values",
        ],
      },
    ),
  );
};

/** Read the focused window and app declarations. */
export const inspectWindow = async (
  context: AdbOperationContext<"inspect_adb_window">,
  input: AdbInput<"inspect_adb_window">,
): Promise<Result<AnalysisExecution, AnalysisError>> => {
  const ran = await runShell(
    context,
    input.serial,
    ["dumpsys", "window", "windows"],
    {
      timeoutMs: SHELL_TIMEOUT_MS,
      maxOutputBytes: DUMPSYS_WINDOW_MAX_OUTPUT_BYTES,
    },
  );
  if (!ran.ok) return ran;
  const { focusedWindow, focusedApp } = parseWindowFocusOutput(
    ran.value.stdout,
  );
  return ok(
    createAnalysisExecution(
      {
        client: context.client,
        serial: input.serial,
        focused_window: focusedWindow,
        focused_app: focusedApp,
        observed_lines: [
          ...(focusedWindow === null ? [] : [focusedWindow]),
          ...(focusedApp === null ? [] : [focusedApp]),
        ],
      },
      context.provider,
      {
        limitations: [
          "Focus values are the window manager's declarations at read time; no interaction occurred",
        ],
      },
    ),
  );
};

/** Read one Android setting. */
export const readSetting = async (
  context: AdbOperationContext<"read_adb_setting">,
  input: AdbInput<"read_adb_setting">,
): Promise<Result<AnalysisExecution, AnalysisError>> => {
  const ran = await runShell(
    context,
    input.serial,
    ["settings", "get", input.namespace, input.key],
    {
      timeoutMs: SETTINGS_TIMEOUT_MS,
      maxOutputBytes: SETTINGS_MAX_OUTPUT_BYTES,
    },
  );
  if (!ran.ok) return ran;
  const { value, deviceReportedNull } = parseSettingsGetOutput(
    ran.value.stdout,
  );
  return ok(
    createAnalysisExecution(
      {
        client: context.client,
        serial: input.serial,
        namespace: input.namespace,
        key: input.key,
        value,
        device_reported_null: deviceReportedNull,
      },
      context.provider,
      {
        limitations: [
          "Android prints the literal string null for absent keys; that is reported as a device-side null observation",
        ],
      },
    ),
  );
};

/** Match package names against a caller query. */
export const resolvePackages = async (
  context: AdbOperationContext<"resolve_adb_packages">,
  input: AdbInput<"resolve_adb_packages">,
): Promise<Result<AnalysisExecution, AnalysisError>> => {
  const ran = await runShell(
    context,
    input.serial,
    ["pm", "list", "packages", "-f"],
    {
      timeoutMs: PACKAGE_LIST_TIMEOUT_MS,
      maxOutputBytes: PACKAGE_LIST_MAX_OUTPUT_BYTES,
    },
  );
  if (!ran.ok) return ran;
  const { packages, unparsedLines } = parsePackageListOutput(ran.value.stdout);
  const needle = input.query.toLowerCase();
  const matches = packages.filter((entry) =>
    entry.package_name.toLowerCase().includes(needle),
  );
  return ok(
    createAnalysisExecution(
      {
        client: context.client,
        serial: input.serial,
        query: input.query,
        matches,
        exact_match:
          matches.length === 1 &&
          matches[0]!.package_name.toLowerCase() === needle,
        coverage: unparsedLines.length > 0 ? "partial" : "complete",
      },
      context.provider,
      {
        limitations: [
          "Matching is a case-insensitive substring over package names; application display labels are not part of pm output",
          ...unparsedOverflowLimitation(unparsedLines),
        ],
      },
    ),
  );
};
