import type { ClassReferenceLoaded, ClassReferenceLoadedClassOrInterface, ClassIndex } from './ClassIndex';
import type { MemberParameterData, ParameterLoader, ParameterRangeUnresolved } from './ParameterLoader';
/**
 * Loads the member data of classes.
 */
export declare class MemberLoader {
    private readonly parameterLoader;
    constructor(args: MemberLoaderArgs);
    /**
     * Create a class index containing all member data from the classes in the given index.
     * @param classIndex An index of loaded classes.
     */
    getMembers(classIndex: ClassIndex<ClassReferenceLoaded>): ClassIndex<MemberData<ParameterRangeUnresolved>>;
    /**
     * Obtain the class member fields.
     * This should correspond to the keys that are available within the `keyof` range of this class
     * @param classLoaded A class or interface
     */
    collectClassFields(classLoaded: ClassReferenceLoadedClassOrInterface): MemberParameterData<ParameterRangeUnresolved>[];
}
/**
 * Member parameter information
 */
export interface MemberData<R> {
    members: MemberParameterData<R>[];
    classLoaded: ClassReferenceLoaded;
}
export interface MemberLoaderArgs {
    parameterLoader: ParameterLoader;
}
