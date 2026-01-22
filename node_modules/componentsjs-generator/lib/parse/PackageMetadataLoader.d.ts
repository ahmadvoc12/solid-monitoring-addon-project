import type { ResolutionContext } from '../resolution/ResolutionContext';
/**
 * Load metadata from a package.
 */
export declare class PackageMetadataLoader {
    private readonly resolutionContext;
    private readonly prefixes?;
    constructor(args: PackageMetadataLoaderArgs);
    /**
     * Load the metadata from the given package.
     * @param packageRootDirectory The path to a package that should contain a package.json.
     */
    load(packageRootDirectory: string): Promise<PackageMetadata>;
}
export interface PackageMetadataLoaderArgs {
    resolutionContext: ResolutionContext;
    prefixes?: string | Record<string, string>;
}
export interface PackageMetadata {
    name: string;
    version: string;
    moduleIri: string;
    componentsPath: string;
    contexts: Record<string, string>;
    importPaths: Record<string, string>;
    typesPath: string;
    prefix?: string;
}
