import { Generator } from '../generate/Generator';
import type { ResolutionContext } from '../resolution/ResolutionContext';
import type { GeneratorConfig } from './GeneratorConfig';
/**
 * Constructs a {@link Generator} with the proper configs.
 *
 * It will consider the following configs in order of priority:
 * * CLI arguments
 * * .componentsjs-generator-config.json
 * * Default values
 */
export declare class GeneratorFactory {
    private readonly resolutionContext;
    constructor(args: GeneratorFactoryArgs);
    createGenerator(cwd: string, cliArgs: Record<string, any>, packageRootDirectories: string[]): Promise<Generator>;
    getConfig(cwd: string, cliArgs: Record<string, any>): Promise<GeneratorConfig>;
    getDefaultConfig(): GeneratorConfig;
    getCliConfig(cliArgs: Record<string, any>): Promise<Partial<GeneratorConfig>>;
}
export interface GeneratorFactoryArgs {
    resolutionContext: ResolutionContext;
}
