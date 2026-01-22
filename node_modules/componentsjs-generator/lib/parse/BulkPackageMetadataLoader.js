"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BulkPackageMetadataLoader = void 0;
const componentsjs_1 = require("componentsjs");
const jsonld_context_parser_1 = require("jsonld-context-parser");
const ContextConstructor_1 = require("../serialize/ContextConstructor");
/**
 * Load metadata from multiple packages in bulk.
 */
class BulkPackageMetadataLoader {
    constructor(args) {
        this.packageMetadataLoader = args.packageMetadataLoader;
        this.logger = args.logger;
    }
    /**
     * Load the metadata from the given packages.
     * @param pathDestinations Package paths.
     */
    async load(pathDestinations) {
        const packageMetadatas = {};
        const pathMetadatas = {};
        const minimalContextParser = new jsonld_context_parser_1.ContextParser({
            documentLoader: new componentsjs_1.PrefetchedDocumentLoader({
                contexts: {},
                logger: this.logger,
            }),
            skipValidation: true,
        });
        for (const pathDestination of pathDestinations) {
            let packageMetadata;
            try {
                // Load package metadata
                packageMetadata = await this.packageMetadataLoader.load(pathDestination.packageRootDirectory);
                const contextConstructor = new ContextConstructor_1.ContextConstructor({ packageMetadata });
                // Save the metadata for later use
                packageMetadatas[packageMetadata.name] = {
                    packageMetadata,
                    pathDestination,
                    minimalContext: await minimalContextParser.parse(contextConstructor.constructContext()),
                };
                pathMetadatas[pathDestination.packageRootDirectory] = packageMetadata;
            }
            catch (error) {
                // Skip invalid packages
                this.logger.warn(`Skipped generating invalid package at "${pathDestination.packageRootDirectory}": ${error.message}`);
            }
        }
        return { packageMetadatas, pathMetadatas };
    }
}
exports.BulkPackageMetadataLoader = BulkPackageMetadataLoader;
//# sourceMappingURL=BulkPackageMetadataLoader.js.map