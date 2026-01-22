/**
 * Resolves relative segments in the path.
 *
 * @param path - Path to check (POSIX or Windows).
 *
 * @returns The potentially changed path (POSIX).
 */
export declare function normalizeFilePath(path: string): string;
/**
 * Adds the paths to the base path.
 *
 * @param basePath - The base path (POSIX or Windows).
 * @param paths - Subpaths to attach (POSIX).
 *
 * @returns The potentially changed path (POSIX).
 */
export declare function joinFilePath(basePath: string, ...paths: string[]): string;
/**
 * Returns the directory name of a path.
 *
 * @param path - Path to find directory of.
 *
 * @returns The directory path.
 */
export declare function filePathDirName(path: string): string;
