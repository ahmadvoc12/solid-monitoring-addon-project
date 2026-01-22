"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.GeneratorFactory = void 0;
const Generator_1 = require("../generate/Generator");
const PathUtil_1 = require("../util/PathUtil");
const FileConfigLoader_1 = require("./FileConfigLoader");
/**
 * Constructs a {@link Generator} with the proper configs.
 *
 * It will consider the following configs in order of priority:
 * * CLI arguments
 * * .componentsjs-generator-config.json
 * * Default values
 */
class GeneratorFactory {
    constructor(args) {
        this.resolutionContext = args.resolutionContext;
    }
    async createGenerator(cwd, cliArgs, packageRootDirectories) {
        const config = await this.getConfig(cwd, cliArgs);
        return new Generator_1.Generator({
            resolutionContext: this.resolutionContext,
            pathDestinations: packageRootDirectories
                .filter(packageRootDirectory => !config.ignorePackagePaths
                .some(ignorePackagePath => packageRootDirectory.startsWith((0, PathUtil_1.joinFilePath)(cwd, ignorePackagePath))))
                .map(packageRootDirectory => ({
                packageRootDirectory,
                originalPath: (0, PathUtil_1.joinFilePath)(packageRootDirectory, config.source),
                replacementPath: (0, PathUtil_1.joinFilePath)(packageRootDirectory, config.destination),
            })),
            fileExtension: config.extension,
            logLevel: config.logLevel,
            debugState: config.debugState,
            prefixes: config.modulePrefix,
            ignoreClasses: config.ignoreComponents.reduce((acc, entry) => {
                acc[entry] = true;
                return acc;
            }, {}),
            hardErrorUnsupported: config.hardErrorUnsupported,
        });
    }
    async getConfig(cwd, cliArgs) {
        const defaultConfig = this.getDefaultConfig();
        const fileConfig = await new FileConfigLoader_1.FileConfigLoader({ resolutionContext: this.resolutionContext })
            .getClosestConfigFile(cwd);
        const cliConfig = await this.getCliConfig(cliArgs);
        return {
            ...defaultConfig,
            ...fileConfig,
            ...cliConfig,
        };
    }
    getDefaultConfig() {
        return {
            source: 'lib',
            destination: 'components',
            extension: 'jsonld',
            ignorePackagePaths: [],
            ignoreComponents: [],
            logLevel: 'info',
            modulePrefix: undefined,
            debugState: false,
            hardErrorUnsupported: true,
        };
    }
    async getCliConfig(cliArgs) {
        const config = {};
        if (cliArgs.s) {
            config.source = cliArgs.s;
        }
        if (cliArgs.c) {
            config.destination = cliArgs.c;
        }
        if (cliArgs.e) {
            config.extension = cliArgs.e;
        }
        if (cliArgs.i) {
            config.ignoreComponents = JSON.parse(await this.resolutionContext.getFileContent(cliArgs.i));
        }
        if (cliArgs.l) {
            config.logLevel = cliArgs.l;
        }
        if (cliArgs.r) {
            config.modulePrefix = cliArgs.r;
        }
        if (cliArgs.debugState) {
            config.debugState = cliArgs.debugState;
        }
        if (cliArgs.lenient) {
            config.hardErrorUnsupported = false;
        }
        return config;
    }
}
exports.GeneratorFactory = GeneratorFactory;
//# sourceMappingURL=GeneratorFactory.js.map