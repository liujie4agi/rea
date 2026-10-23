/** Host output ownership for ADB acquisitions: creation, identity, and removal. */

import type { Stats } from "node:fs";
import { constants as fsConstants } from "node:fs";
import { access, copyFile, lstat, mkdir, rm, rmdir } from "node:fs/promises";
import { basename, extname, join, resolve } from "node:path";

import { AnalysisOutputError } from "../domain/analysisErrorCore.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { err, ok, type Result } from "../domain/result.js";

/** Materialize the caller's output directory, refusing existing files inside. */
export const prepareOutputDirectory = async (
  operation: string,
  directory: string,
): Promise<Result<string, AnalysisError>> => {
  const root = resolve(directory);
  try {
    await mkdir(root, { recursive: true });
    await access(root, fsConstants.W_OK);
  } catch (cause) {
    return err(
      new AnalysisOutputError(
        operation,
        `The output directory is not writable or could not be created: ${root}`,
        { cause },
      ),
    );
  }
  return ok(root);
};

export const refuseExistingTarget = async (
  operation: string,
  path: string,
): Promise<AnalysisError | undefined> => {
  if (
    await lstat(path).then(
      () => true,
      () => false,
    )
  )
    return new AnalysisOutputError(
      operation,
      `The output file already exists: ${path}`,
    );
  return undefined;
};

/** Publish an ADB-produced archive without replacing an existing caller file. */
export const publishBugreport = async (
  source: string,
  directory: string,
): Promise<string> => {
  const fileName = basename(source);
  const extension = extname(fileName);
  const stem =
    extension === "" ? fileName : fileName.slice(0, -extension.length);
  for (let suffix = 0; ; suffix += 1) {
    const destination = join(
      directory,
      suffix === 0 ? fileName : `${stem} (${String(suffix)})${extension}`,
    );
    try {
      await copyFile(source, destination, fsConstants.COPYFILE_EXCL);
      return destination;
    } catch (cause: unknown) {
      if (cause instanceof Error && "code" in cause && cause.code === "EEXIST")
        continue;
      throw cause;
    }
  }
};

export interface PendingOutputDirectoryCleanup {
  readonly operation: "pull_adb_package" | "collect_adb_bugreport";
  readonly path: string;
  readonly identity: OutputDirectoryIdentity | undefined;
  readonly primary: AnalysisError;
  readonly remove: () => Promise<void>;
}

export interface OutputDirectoryIdentity {
  readonly dev: number;
  readonly ino: number;
  readonly mode: number;
}

/** Identity of a directory REA created, or undefined when it is not a plain directory. */
export const ownedDirectoryIdentity = (
  stats: Stats,
): OutputDirectoryIdentity | undefined =>
  !stats.isDirectory() || stats.isSymbolicLink()
    ? undefined
    : { dev: stats.dev, ino: stats.ino, mode: stats.mode };

const isSameDirectory = (
  current: Stats,
  identity: OutputDirectoryIdentity,
): boolean => {
  const observed = ownedDirectoryIdentity(current);
  return (
    observed !== undefined &&
    observed.dev === identity.dev &&
    observed.ino === identity.ino &&
    observed.mode === identity.mode
  );
};

export const removeOwnedOutputDirectory = async (
  path: string,
  identity: OutputDirectoryIdentity | undefined,
): Promise<void> => {
  if (identity === undefined)
    throw new Error(
      `Cannot verify the created output directory identity; refusing to remove ${path}`,
    );
  let current: Stats;
  try {
    current = await lstat(path);
  } catch (cause: unknown) {
    if (cause instanceof Error && Reflect.get(cause, "code") === "ENOENT")
      return;
    throw cause;
  }
  if (!isSameDirectory(current, identity))
    throw new Error(
      `The created output directory was replaced or changed; refusing to remove ${path}`,
    );
  await rm(path, { recursive: true, force: true });
};

export const reservePackageDestinations = async (
  operation: string,
  packageDirectory: string,
  entries: readonly { readonly file_name: string }[],
  capturedOutput: {
    readonly stdout: string;
    readonly stderr: string;
    readonly truncated: boolean;
  },
): Promise<AnalysisOutputError | undefined> => {
  const reservations: {
    readonly path: string;
    readonly identity: OutputDirectoryIdentity;
  }[] = [];
  for (const entry of entries) {
    const path = join(packageDirectory, entry.file_name);
    try {
      await mkdir(path);
      const identity = ownedDirectoryIdentity(await lstat(path));
      if (identity === undefined)
        throw new Error(`Could not reserve local filename ${entry.file_name}`);
      reservations.push({ path, identity });
    } catch (cause: unknown) {
      return new AnalysisOutputError(
        operation,
        `Package Manager paths cannot be written to unique local destinations at ${JSON.stringify(entry.file_name)}; refusing before pulling any files`,
        { cause, capturedOutput },
      );
    }
  }
  for (const reservation of reservations) {
    try {
      if (!isSameDirectory(await lstat(reservation.path), reservation.identity))
        throw new Error(
          `The local filename reservation changed before release: ${reservation.path}`,
        );
      await rmdir(reservation.path);
    } catch (cause: unknown) {
      return new AnalysisOutputError(
        operation,
        `Could not release a local filename reservation before pulling: ${reservation.path}`,
        { cause, capturedOutput },
      );
    }
  }
  return undefined;
};
