import type { ResolutionContext } from '../resolution/ResolutionContext';
import type { PathDestinationDefinition } from './ComponentConstructor';
import type { ComponentDefinitions, ComponentDefinitionsIndex } from './ComponentDefinitions';
import type { ContextRaw } from './ContextConstructor';
/**
 * Serializes components to files.
 */
export declare class ComponentSerializer {
    private readonly resolutionContext;
    private readonly pathDestination;
    private readonly fileExtension;
    private readonly indentation;
    constructor(args: ComponentSerializerArgs);
    protected writeJsonToFile(fileNameBase: string, data: any): Promise<string>;
    /**
     * Serialize the given components to files.
     * @param components Component definitions.
     * @return An array of absolute file paths that were created.
     */
    serializeComponents(components: ComponentDefinitions): Promise<string[]>;
    /**
     * Serialize the given components index to a file.
     * @param componentsIndex Component definitions index.
     * @return The absolute file path that was created.
     */
    serializeComponentsIndex(componentsIndex: ComponentDefinitionsIndex): Promise<string>;
    /**
     * Serialize the given context to a file.
     * @param contextRaw JSON-LD context contents.
     * @return The absolute file path that was created.
     */
    serializeContext(contextRaw: ContextRaw): Promise<string>;
}
export interface ComponentSerializerArgs {
    resolutionContext: ResolutionContext;
    pathDestination: PathDestinationDefinition;
    fileExtension: string;
    indentation: string;
}
