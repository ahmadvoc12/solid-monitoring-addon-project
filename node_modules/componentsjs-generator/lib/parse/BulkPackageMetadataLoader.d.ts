import type { Logger } from 'winston';
import type { PackageMetadataScope } from '../resolution/ExternalModulesLoader';
import type { PathDestinationDefinition } from '../serialize/ComponentConstructor';
import type { PackageMetadata, PackageMetadataLoader } from './PackageMetadataLoader';
/**
 * Load metadata from multiple packages in bulk.
 */
export declare class BulkPackageMetadataLoader {
    private readonly packageMetadataLoader;
    private readonly logger;
    constructor(args: BulkPackageMetadataLoaderArgs);
    /**
     * Load the metadata from the given packages.
     * @param pathDestinations Package paths.
     */
    load(pathDestinations: PathDestinationDefinition[]): Promise<BulkPackageMetadataOutput>;
}
export interface BulkPackageMetadataLoaderArgs {
    packageMetadataLoader: PackageMetadataLoader;
    logger: Logger;
}
export interface BulkPackageMetadataOutput {
    /**
     * Maps package name to scoped package metadata.
     */
    packageMetadatas: Record<string, PackageMetadataScope>;
    /**
     * Maps package root path to package metadata.
     */
    pathMetadatas: Record<string, PackageMetadata>;
}
