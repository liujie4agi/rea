import type {
  ExecutionOptions,
  ProviderAvailability,
} from "../application/AnalysisProvider.js";
import { providerConfigurationRefusal } from "../domain/providerConfigurationRefusal.js";
import {
  createAnalysisExecution,
  type AnalysisExecution,
} from "../application/AnalysisProvider.js";
import type { AdbRequest } from "../domain/adb/adbDeviceAnalysis.js";
import {
  AnalysisCancelledError,
  AnalysisProtocolError,
} from "../domain/analysisErrorCore.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import { analysisErrorWithCleanupFailure } from "../domain/analysisErrorCleanup.js";
import { err, ok, type Result } from "../domain/result.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import {
  installPackage,
  startActivity,
  startApp,
  stopApp,
  uninstallPackage,
} from "./AdbAppControl.js";
import { collectBugreport } from "./AdbBugreport.js";
import {
  AdbConfigurationFailure,
  adbConfigurationAvailability,
  inspectAdbClient,
  resolveAdbBinary,
  type AdbBinarySelection,
  type AdbClientIdentity,
} from "./AdbConfiguration.js";
import {
  inspectDevice,
  inspectDisplay,
  inspectPackage,
  inspectWindow,
  listDevices,
  listPackages,
  readLogcat,
  readSetting,
  resolvePackages,
} from "./AdbDeviceQueries.js";
import {
  listDirectory,
  listFeatures,
  listProcesses,
  listServices,
} from "./AdbDeviceListings.js";
import { captureScreen, pullFile, pushFile } from "./AdbFileTransfer.js";
import {
  ADB_PROVIDER_IDENTITY,
  clientIdentityResult,
  type AdbOperationContext,
} from "./AdbOperationContext.js";
import type { PendingOutputDirectoryCleanup } from "./AdbOutputFiles.js";
import { pullPackage } from "./AdbPackagePull.js";

export interface AdbProviderOptions {
  readonly environment?: Readonly<Record<string, string | undefined>>;
}

/**
 * ADB device inspection and acquisition over a caller-selected adb binary.
 *
 * Every operation composes fixed adb argument vectors: caller values occupy
 * positional arguments, escaped when adb forwards them to the device shell. The provider never
 * starts an emulator, installs platform tools, or drives the device UI; the
 * only device mutation is the caller-requested file push, which requires an
 * explicit overwrite choice and verifies its transfer digest.
 */
export class AdbProvider {
  private readonly environment: Readonly<Record<string, string | undefined>>;
  readonly #pendingOutputDirectoryCleanup =
    new Set<PendingOutputDirectoryCleanup>();
  readonly #activeOperations = new Set<Promise<void>>();
  #closing = false;
  #closePromise: Promise<void> | undefined;
  #outputCleanupPromise: Promise<void> | undefined;

  constructor(options: AdbProviderOptions = {}) {
    this.environment = options.environment ?? process.env;
  }

  private selection(): AdbBinarySelection {
    return resolveAdbBinary(this.environment);
  }

  /** Probe the selected adb binary; never contacts devices or the server. */
  async inspectAvailability(
    signal?: AbortSignal,
  ): Promise<ProviderAvailability> {
    try {
      const selection = this.selection();
      await inspectAdbClient(selection, signal);
      return {
        status: "available",
        code: null,
        reason: null,
        diagnostics: {
          selected_binary: selection.binary,
          path_source: selection.pathSource,
        },
      };
    } catch (cause) {
      if (cause instanceof AdbConfigurationFailure)
        return adbConfigurationAvailability(cause);
      throw cause;
    }
  }

  /** Retry removal of owned output directories retained after failed cleanup. */
  close(): Promise<void> {
    this.#closing = true;
    if (this.#closePromise !== undefined) return this.#closePromise;
    const closing = (async () => {
      await Promise.all(this.#activeOperations);
      await this.#retryOutputDirectoryCleanup();
    })().finally(() => {
      if (this.#closePromise === closing) this.#closePromise = undefined;
    });
    this.#closePromise = closing;
    return this.#closePromise;
  }

  #retryOutputDirectoryCleanup(): Promise<void> {
    if (this.#outputCleanupPromise !== undefined)
      return this.#outputCleanupPromise;
    const cleanup = this.#performOutputDirectoryCleanup().finally(() => {
      if (this.#outputCleanupPromise === cleanup)
        this.#outputCleanupPromise = undefined;
    });
    this.#outputCleanupPromise = cleanup;
    return cleanup;
  }

  async #performOutputDirectoryCleanup(): Promise<void> {
    const failures: AnalysisError[] = [];
    for (const owner of this.#pendingOutputDirectoryCleanup) {
      try {
        await owner.remove();
        this.#pendingOutputDirectoryCleanup.delete(owner);
      } catch (cause: unknown) {
        const cleanup = new ProviderCleanupError(
          ADB_PROVIDER_IDENTITY.id,
          [owner.path],
          {
            reason: cause instanceof Error ? cause.message : String(cause),
          },
          { operation: owner.operation, cause },
        );
        failures.push(
          analysisErrorWithCleanupFailure(
            owner.primary,
            cleanup,
            owner.operation,
          ),
        );
      }
    }
    if (failures.length === 1) throw failures[0];
    if (failures.length > 1)
      throw new ProviderCleanupError(
        ADB_PROVIDER_IDENTITY.id,
        [...this.#pendingOutputDirectoryCleanup].map(({ path }) => path),
        {
          reason: "Failed ADB output directories remain after cleanup retry",
          operations: [...this.#pendingOutputDirectoryCleanup].map(
            ({ operation }) => operation,
          ),
          failures: failures.map(({ message, cleanupResources }) => ({
            message,
            resources: [...cleanupResources],
          })),
        },
        {
          operation: "close_binary",
          cause: new AggregateError(
            failures,
            "Multiple ADB output directory cleanups failed",
          ),
        },
      );
  }

  async execute(
    request: AdbRequest,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    if (this.#closing)
      return err(new AnalysisCancelledError(request.operation));
    let release!: () => void;
    const active = new Promise<void>((resolve) => {
      release = resolve;
    });
    this.#activeOperations.add(active);
    try {
      if (this.#pendingOutputDirectoryCleanup.size > 0) {
        try {
          await this.#retryOutputDirectoryCleanup();
        } catch (cause: unknown) {
          return err(
            cause instanceof AnalysisError
              ? cause
              : new ProviderCleanupError(
                  ADB_PROVIDER_IDENTITY.id,
                  [...this.#pendingOutputDirectoryCleanup].map(
                    ({ path }) => path,
                  ),
                  {
                    reason:
                      cause instanceof Error ? cause.message : String(cause),
                  },
                  { operation: request.operation, cause },
                ),
          );
        }
      }
      return await this.#executeOperation(request, options);
    } finally {
      this.#activeOperations.delete(active);
      release();
    }
  }

  async #executeOperation(
    request: AdbRequest,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const signal = options?.signal;
    if (signal?.aborted === true)
      return err(new AnalysisCancelledError(request.operation));
    let selection: AdbBinarySelection;
    let identity: AdbClientIdentity;
    try {
      selection = this.selection();
      identity = await inspectAdbClient(selection, signal);
    } catch (cause) {
      if (cause instanceof AnalysisCancelledError) return err(cause);
      if (cause instanceof AdbConfigurationFailure)
        return err(
          providerConfigurationRefusal(
            ADB_PROVIDER_IDENTITY.id,
            request.operation,
            cause,
          ),
        );
      return err(
        new AnalysisProtocolError(
          `adb version probe failed for ${request.operation}`,
          { cause },
        ),
      );
    }
    const shared: Omit<AdbOperationContext, "operation"> = {
      binary: selection.binary,
      client: clientIdentityResult(selection, identity),
      provider: { ...ADB_PROVIDER_IDENTITY, version: identity.version },
      signal,
      retainOutputCleanup: (owner) => {
        this.#pendingOutputDirectoryCleanup.add(owner);
      },
    };
    switch (request.operation) {
      case "inspect_adb_client":
        return ok(
          createAnalysisExecution(
            { client: shared.client, contacted_adb_server: false },
            shared.provider,
          ),
        );
      case "list_adb_devices":
        return listDevices({ ...shared, operation: request.operation });
      case "inspect_adb_device":
        return inspectDevice(
          { ...shared, operation: request.operation },
          request.input,
        );
      case "list_adb_packages":
        return listPackages(
          { ...shared, operation: request.operation },
          request.input,
        );
      case "pull_adb_package":
        return pullPackage(
          { ...shared, operation: request.operation },
          request.input,
        );
      case "read_adb_logcat":
        return readLogcat(
          { ...shared, operation: request.operation },
          request.input,
        );
      case "inspect_adb_package":
        return inspectPackage(
          { ...shared, operation: request.operation },
          request.input,
        );
      case "pull_adb_file":
        return pullFile(
          { ...shared, operation: request.operation },
          request.input,
        );
      case "push_adb_file":
        return pushFile(
          { ...shared, operation: request.operation },
          request.input,
        );
      case "capture_adb_screen":
        return captureScreen(
          { ...shared, operation: request.operation },
          request.input,
        );
      case "collect_adb_bugreport":
        return collectBugreport(
          { ...shared, operation: request.operation },
          request.input,
        );
      case "list_adb_processes":
        return listProcesses(
          { ...shared, operation: request.operation },
          request.input,
        );
      case "list_adb_directory":
        return listDirectory(
          { ...shared, operation: request.operation },
          request.input,
        );
      case "list_adb_features":
        return listFeatures(
          { ...shared, operation: request.operation },
          request.input,
        );
      case "list_adb_services":
        return listServices(
          { ...shared, operation: request.operation },
          request.input,
        );
      case "inspect_adb_display":
        return inspectDisplay(
          { ...shared, operation: request.operation },
          request.input,
        );
      case "inspect_adb_window":
        return inspectWindow(
          { ...shared, operation: request.operation },
          request.input,
        );
      case "read_adb_setting":
        return readSetting(
          { ...shared, operation: request.operation },
          request.input,
        );
      case "resolve_adb_packages":
        return resolvePackages(
          { ...shared, operation: request.operation },
          request.input,
        );
      case "install_adb_package":
        return installPackage(
          { ...shared, operation: request.operation },
          request.input,
        );
      case "uninstall_adb_package":
        return uninstallPackage(
          { ...shared, operation: request.operation },
          request.input,
        );
      case "start_adb_app":
        return startApp(
          { ...shared, operation: request.operation },
          request.input,
        );
      case "start_adb_activity":
        return startActivity(
          { ...shared, operation: request.operation },
          request.input,
        );
      case "stop_adb_app":
        return stopApp(
          { ...shared, operation: request.operation },
          request.input,
        );
    }
  }
}
