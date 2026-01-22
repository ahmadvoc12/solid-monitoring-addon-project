"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Generator = void 0;
const ComponentsManagerBuilder_1 = require("componentsjs/lib/loading/ComponentsManagerBuilder");
const PrefetchedDocumentLoader_1 = require("componentsjs/lib/rdf/PrefetchedDocumentLoader");
const jsonld_context_parser_1 = require("jsonld-context-parser");
const BulkPackageMetadataLoader_1 = require("../parse/BulkPackageMetadataLoader");
const ClassFinder_1 = require("../parse/ClassFinder");
const ClassIndexer_1 = require("../parse/ClassIndexer");
const ClassLoader_1 = require("../parse/ClassLoader");
const CommentLoader_1 = require("../parse/CommentLoader");
const ConstructorLoader_1 = require("../parse/ConstructorLoader");
const GenericsLoader_1 = require("../parse/GenericsLoader");
const MemberLoader_1 = require("../parse/MemberLoader");
const PackageMetadataLoader_1 = require("../parse/PackageMetadataLoader");
const ParameterLoader_1 = require("../parse/ParameterLoader");
const ParameterResolver_1 = require("../parse/ParameterResolver");
const ExternalModulesLoader_1 = require("../resolution/ExternalModulesLoader");
const ComponentConstructor_1 = require("../serialize/ComponentConstructor");
const ComponentSerializer_1 = require("../serialize/ComponentSerializer");
const ContextConstructor_1 = require("../serialize/ContextConstructor");
/**
 * Generates a components file by parsing a typescript file.
 */
class Generator {
    constructor(args) {
        this.resolutionContext = args.resolutionContext;
        this.pathDestinations = args.pathDestinations;
        this.fileExtension = args.fileExtension;
        this.ignoreClasses = args.ignoreClasses;
        this.logLevel = args.logLevel;
        this.debugState = args.debugState;
        this.prefixes = args.prefixes;
        this.hardErrorUnsupported = args.hardErrorUnsupported;
    }
    async generateComponents() {
        const logger = ComponentsManagerBuilder_1.ComponentsManagerBuilder.createLogger(this.logLevel);
        const commentLoader = new CommentLoader_1.CommentLoader();
        const classLoader = new ClassLoader_1.ClassLoader({ resolutionContext: this.resolutionContext, logger, commentLoader });
        const classFinder = new ClassFinder_1.ClassFinder({ classLoader });
        const classIndexer = new ClassIndexer_1.ClassIndexer({ classLoader, classFinder, ignoreClasses: this.ignoreClasses, logger });
        const parameterLoader = new ParameterLoader_1.ParameterLoader({
            commentLoader,
            hardErrorUnsupported: this.hardErrorUnsupported,
            logger,
        });
        const parameterResolver = new ParameterResolver_1.ParameterResolver({
            classLoader,
            parameterLoader,
            ignoreClasses: this.ignoreClasses,
        });
        // Preload package metadata for all provided paths
        const { packageMetadatas, pathMetadatas } = await new BulkPackageMetadataLoader_1.BulkPackageMetadataLoader({
            packageMetadataLoader: new PackageMetadataLoader_1.PackageMetadataLoader({
                resolutionContext: this.resolutionContext,
                prefixes: this.prefixes,
            }),
            logger,
        }).load(this.pathDestinations);
        logger.info(`Generating components for ${Object.keys(packageMetadatas).length} package${Object.keys(packageMetadatas).length > 1 ? 's' : ''}`);
        // Generate components for all provided paths
        for (const pathDestination of this.pathDestinations) {
            // Load package metadata
            const packageMetadata = pathMetadatas[pathDestination.packageRootDirectory];
            if (!packageMetadata) {
                continue;
            }
            // Find all relevant classes
            const packageExports = await classFinder.getPackageExports(packageMetadata.name, packageMetadata.typesPath);
            const classAndInterfaceIndex = await classIndexer.createIndex(packageExports);
            // Load constructor data
            const constructorsUnresolved = new ConstructorLoader_1.ConstructorLoader({ parameterLoader }).getConstructors(classAndInterfaceIndex);
            const constructors = await parameterResolver.resolveAllConstructorParameters(constructorsUnresolved);
            // Load generics data
            const genericsUnresolved = new GenericsLoader_1.GenericsLoader({ parameterLoader }).getGenerics(classAndInterfaceIndex);
            const generics = await parameterResolver.resolveAllGenericTypeParameterData(genericsUnresolved);
            // Load extensions data
            const extensionsUnresolved = parameterLoader.loadAllExtensionData(classAndInterfaceIndex);
            const extensions = await parameterResolver.resolveAllExtensionData(extensionsUnresolved, classAndInterfaceIndex);
            // Load members data
            const membersUnresolved = new MemberLoader_1.MemberLoader({ parameterLoader }).getMembers(classAndInterfaceIndex);
            const members = await parameterResolver.resolveAllMemberParameterData(membersUnresolved);
            // Load external components
            const externalModulesLoader = new ExternalModulesLoader_1.ExternalModulesLoader({
                pathDestination,
                packageMetadata,
                packagesBeingGenerated: packageMetadatas,
                resolutionContext: this.resolutionContext,
                debugState: this.debugState,
                logger,
            });
            const externalPackages = externalModulesLoader.findExternalPackages(classAndInterfaceIndex, constructors);
            const externalComponents = await externalModulesLoader.loadExternalComponents(require, externalPackages);
            // Create components
            const contextConstructor = new ContextConstructor_1.ContextConstructor({ packageMetadata });
            const componentConstructor = new ComponentConstructor_1.ComponentConstructor({
                packageMetadata,
                fileExtension: this.fileExtension,
                contextConstructor,
                pathDestination,
                classAndInterfaceIndex,
                classConstructors: constructors,
                classGenerics: generics,
                classExtensions: extensions,
                classMembers: members,
                externalComponents,
                contextParser: new jsonld_context_parser_1.ContextParser({
                    documentLoader: new PrefetchedDocumentLoader_1.PrefetchedDocumentLoader({
                        contexts: externalComponents.moduleState.contexts,
                        logger,
                    }),
                    skipValidation: true,
                }),
            });
            const components = await componentConstructor.constructComponents();
            const componentsIndex = await componentConstructor.constructComponentsIndex(components);
            // Serialize components
            const componentSerializer = new ComponentSerializer_1.ComponentSerializer({
                resolutionContext: this.resolutionContext,
                pathDestination,
                fileExtension: this.fileExtension,
                indentation: '  ',
            });
            await componentSerializer.serializeComponents(components);
            await componentSerializer.serializeComponentsIndex(componentsIndex);
            // Serialize context
            const context = contextConstructor.constructContext(components);
            await componentSerializer.serializeContext(context);
        }
    }
}
exports.Generator = Generator;
//# sourceMappingURL=Generator.js.map