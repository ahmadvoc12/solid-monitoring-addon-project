import type { ClassIndex, ClassReference } from './ClassIndex';
import type { ClassLoader } from './ClassLoader';
/**
 * Load the names and locations of all available classes that are exported by a package.
 * This will not load classes, but it will merely provide references to classes.
 */
export declare class ClassFinder {
    private readonly classLoader;
    constructor(args: ClassFinderArgs);
    /**
     * From a given types index, find all named exports.
     * @param packageName Package we are checking.
     * @param typesPath The path to the index typings file.
     */
    getPackageExports(packageName: string, typesPath: string): Promise<ClassIndex<ClassReference>>;
    /**
     * Get all named and unnamed exports from the given file.
     * @param packageName Package we are checking.
     * @param fileName The path to a typescript file.
     */
    getFileExports(packageName: string, fileName: string): Promise<{
        named: ClassIndex<ClassReference>;
        unnamed: {
            packageName: string;
            fileName: string;
        }[];
    }>;
}
export interface ClassFinderArgs {
    classLoader: ClassLoader;
}
