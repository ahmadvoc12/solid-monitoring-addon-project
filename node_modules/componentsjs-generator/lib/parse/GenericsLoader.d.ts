import type { ClassIndex, ClassReferenceLoaded } from './ClassIndex';
import type { GenericTypeParameterData, ParameterLoader, ParameterRangeUnresolved } from './ParameterLoader';
/**
 * Loads the generics data of classes.
 */
export declare class GenericsLoader {
    private readonly parameterLoader;
    constructor(args: GenericsLoaderArgs);
    /**
     * Create a class index containing all generics data from the classes in the given index.
     * @param classIndex An index of loaded classes.
     */
    getGenerics(classIndex: ClassIndex<ClassReferenceLoaded>): ClassIndex<GenericsData<ParameterRangeUnresolved>>;
}
export interface GenericsLoaderArgs {
    parameterLoader: ParameterLoader;
}
/**
 * Generics parameter information
 */
export interface GenericsData<R> {
    genericTypeParameters: GenericTypeParameterData<R>[];
    classLoaded: ClassReferenceLoaded;
}
