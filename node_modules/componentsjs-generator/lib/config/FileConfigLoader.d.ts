import type { ResolutionContext } from '../resolution/ResolutionContext';
import type { GeneratorConfig } from './GeneratorConfig';
/**
 * Loads the `.componentsjs-generator-config.json` config file from the file system.
 */
export declare class FileConfigLoader {
    static readonly DEFAULT_CONFIG_NAME = ".componentsjs-generator-config.json";
    private readonly resolutionContext;
    constructor(args: FileConfigLoaderArgs);
    /**
     * Get the closest config file, starting from the current working directory and following parent directory links.
     * @param cwd The current working directory
     */
    getClosestConfigFile(cwd: string): Promise<Partial<GeneratorConfig> | undefined>;
    /**
     * All directories that need to be considered when looking for the config file.
     * @param cwd The current working directory
     */
    getConsideredDirectories(cwd: string): string[];
}
export interface FileConfigLoaderArgs {
    resolutionContext: ResolutionContext;
}
