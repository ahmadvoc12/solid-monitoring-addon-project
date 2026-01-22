"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ClassFinder = void 0;
/**
 * Load the names and locations of all available classes that are exported by a package.
 * This will not load classes, but it will merely provide references to classes.
 */
class ClassFinder {
    constructor(args) {
        this.classLoader = args.classLoader;
    }
    /**
     * From a given types index, find all named exports.
     * @param packageName Package we are checking.
     * @param typesPath The path to the index typings file.
     */
    async getPackageExports(packageName, typesPath) {
        let exports = {};
        // Start from the package index, and collect all named exports.
        const paths = [typesPath];
        for (const path of paths) {
            const { named, unnamed } = await this.getFileExports(packageName, path);
            exports = { ...exports, ...named };
            for (const additionalPath of unnamed) {
                paths.push(additionalPath.fileName);
            }
        }
        return exports;
    }
    /**
     * Get all named and unnamed exports from the given file.
     * @param packageName Package we are checking.
     * @param fileName The path to a typescript file.
     */
    async getFileExports(packageName, fileName) {
        // Load the elements of the class
        const { resolvedPath, exportedClasses, exportedInterfaces, exportedImportedElements, exportedImportedAll, exportedUnknowns, declaredClasses, declaredInterfaces, importedElements, } = await this.classLoader.loadClassElements(packageName, fileName);
        const exportDefinitions = { named: {}, unnamed: [] };
        // Get all named exports
        for (const localName in exportedClasses) {
            exportDefinitions.named[localName] = {
                packageName,
                localName,
                qualifiedPath: undefined,
                fileName: resolvedPath,
                fileNameReferenced: resolvedPath,
            };
        }
        for (const localName in exportedInterfaces) {
            exportDefinitions.named[localName] = {
                packageName,
                localName,
                qualifiedPath: undefined,
                fileName: resolvedPath,
                fileNameReferenced: resolvedPath,
            };
        }
        // Get all named exports from other files
        for (const [exportedName, { localName, fileName: importedFileName }] of Object.entries(exportedImportedElements)) {
            exportDefinitions.named[exportedName] = {
                packageName,
                localName,
                qualifiedPath: undefined,
                fileName: importedFileName,
                fileNameReferenced: resolvedPath,
            };
        }
        // Iterate over all named export that had an unknown target,
        // and attempt to link them to classes available in the file
        if (Object.keys(exportedUnknowns).length > 0) {
            for (const [exportedName, localName] of Object.entries(exportedUnknowns)) {
                // First check declared classes
                if (localName in declaredClasses) {
                    exportDefinitions.named[exportedName] = {
                        packageName,
                        localName,
                        qualifiedPath: undefined,
                        fileName: resolvedPath,
                        fileNameReferenced: resolvedPath,
                    };
                    break;
                }
                // First check declared interfaces
                if (localName in declaredInterfaces) {
                    exportDefinitions.named[exportedName] = {
                        packageName,
                        localName,
                        qualifiedPath: undefined,
                        fileName: resolvedPath,
                        fileNameReferenced: resolvedPath,
                    };
                    break;
                }
                // Next, check imports
                if (localName in importedElements) {
                    exportDefinitions.named[exportedName] = importedElements[localName];
                }
            }
        }
        // Handle export *
        exportDefinitions.unnamed = exportedImportedAll;
        return exportDefinitions;
    }
}
exports.ClassFinder = ClassFinder;
//# sourceMappingURL=ClassFinder.js.map