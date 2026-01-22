import type { LogLevel } from 'componentsjs/lib/util/LogLevel';
import type { ResolutionContext } from '../resolution/ResolutionContext';
import type { PathDestinationDefinition } from '../serialize/ComponentConstructor';
/**
 * Generates a components file by parsing a typescript file.
 */
export declare class Generator {
    private readonly resolutionContext;
    private readonly pathDestinations;
    private readonly fileExtension;
    private readonly ignoreClasses;
    private readonly logLevel;
    private readonly debugState;
    private readonly prefixes?;
    private readonly hardErrorUnsupported;
    constructor(args: GeneratorArgs);
    generateComponents(): Promise<void>;
}
export interface GeneratorArgs {
    resolutionContext: ResolutionContext;
    pathDestinations: PathDestinationDefinition[];
    fileExtension: string;
    ignoreClasses: Record<string, boolean>;
    logLevel: LogLevel;
    debugState: boolean;
    prefixes?: string | Record<string, string>;
    hardErrorUnsupported: boolean;
}
