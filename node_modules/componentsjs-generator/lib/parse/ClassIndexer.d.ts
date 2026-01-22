/**
 * Creates an index of classes in a certain package.
 */
import type { Logger } from 'winston';
import type { ClassFinder } from './ClassFinder';
import type { ClassIndex, ClassReference, ClassReferenceLoadedClassOrInterface } from './ClassIndex';
import type { ClassLoader } from './ClassLoader';
export declare class ClassIndexer {
    private readonly classLoader;
    private readonly classFinder;
    private readonly ignoreClasses;
    private readonly logger;
    constructor(args: ClassIndexerArgs);
    /**
     * Load all class references in the given class index.
     * @param classReferences An index of class references.
     */
    createIndex(classReferences: ClassIndex<ClassReference>): Promise<ClassIndex<ClassReferenceLoadedClassOrInterface>>;
    /**
     * Load the referenced class, and obtain all required information,
     * such as its declaration and loaded super class referenced.
     * @param classReference The reference to a class or interface.
     */
    loadClassChain(classReference: ClassReference): Promise<ClassReferenceLoadedClassOrInterface>;
}
export interface ClassIndexerArgs {
    classLoader: ClassLoader;
    classFinder: ClassFinder;
    ignoreClasses: Record<string, boolean>;
    logger: Logger;
}
