import type { TSESTree } from '@typescript-eslint/typescript-estree';
import type { ClassIndex, ClassReference, ClassReferenceLoaded, InterfaceLoaded } from './ClassIndex';
import type { ClassLoader } from './ClassLoader';
import type { ConstructorData } from './ConstructorLoader';
import type { GenericsData } from './GenericsLoader';
import type { MemberData } from './MemberLoader';
import type { ExtensionData, GenericTypeParameterData, ParameterData, ParameterRangeResolved, ParameterRangeUnresolved, ParameterLoader, MemberParameterData } from './ParameterLoader';
export declare class ParameterResolver {
    private readonly classLoader;
    private readonly parameterLoader;
    private readonly ignoreClasses;
    private readonly cacheInterfaceRange;
    constructor(args: ParameterResolverArgs);
    /**
     * Resolve all constructor parameters of a given constructor index.
     * @param unresolvedParametersIndex An index of unresolved constructor data.
     */
    resolveAllConstructorParameters(unresolvedParametersIndex: ClassIndex<ConstructorData<ParameterRangeUnresolved>>): Promise<ClassIndex<ConstructorData<ParameterRangeResolved>>>;
    /**
     * Resolve all parameters of a given constructor.
     * @param unresolvedConstructorData Unresolved constructor data.
     */
    resolveConstructorParameters(unresolvedConstructorData: ConstructorData<ParameterRangeUnresolved>): Promise<ConstructorData<ParameterRangeResolved>>;
    /**
     * Resolve all generic type parameters of a given constructor index.
     * @param unresolvedParametersIndex An index of unresolved constructor data.
     */
    resolveAllGenericTypeParameterData(unresolvedParametersIndex: ClassIndex<GenericsData<ParameterRangeUnresolved>>): Promise<ClassIndex<GenericsData<ParameterRangeResolved>>>;
    /**
     * Resolve the given array of generic type parameter data in parallel.
     * @param genericTypeParameters An array of unresolved generic type parameters.
     * @param owningClass The class in which the given generic type parameters are declared.
     * @param genericTypeRemappings A remapping of generic type names.
     */
    resolveGenericTypeParameterData(genericTypeParameters: GenericTypeParameterData<ParameterRangeUnresolved>[], owningClass: ClassReferenceLoaded, genericTypeRemappings: Record<string, ParameterRangeUnresolved>): Promise<GenericTypeParameterData<ParameterRangeResolved>[]>;
    /**
     * Resolve all member parameters of a given constructor index.
     * @param unresolvedParametersIndex An index of unresolved constructor data.
     */
    resolveAllMemberParameterData(unresolvedParametersIndex: ClassIndex<MemberData<ParameterRangeUnresolved>>): Promise<ClassIndex<MemberData<ParameterRangeResolved>>>;
    /**
     * Resolve the given array of member parameter data in parallel.
     * @param members An array of unresolved members.
     * @param owningClass The class in which the given generic type parameters are declared.
     * @param genericTypeRemappings A remapping of generic type names.
     */
    resolveMemberParameterData(members: MemberParameterData<ParameterRangeUnresolved>[], owningClass: ClassReferenceLoaded, genericTypeRemappings: Record<string, ParameterRangeUnresolved>): Promise<GenericTypeParameterData<ParameterRangeResolved>[]>;
    /**
     * Resolve the given array of parameter data in parallel.
     * @param parameters An array of unresolved parameters.
     * @param owningClass The class in which the given parameters are declared.
     * @param genericTypeRemappings A remapping of generic type names.
     * @param handlingInterfaces The names of interfaces that are being handled, and this interface is a part of.
     */
    resolveParameterData(parameters: ParameterData<ParameterRangeUnresolved>[], owningClass: ClassReferenceLoaded, genericTypeRemappings: Record<string, ParameterRangeUnresolved>, handlingInterfaces: Set<string>): Promise<ParameterData<ParameterRangeResolved>[]>;
    /**
     * Resolve all extension data of a given constructor index.
     * @param unresolvedExtensionData An index of unresolved constructor data.
     * @param classIndex The class index containing the owning class references.
     */
    resolveAllExtensionData(unresolvedExtensionData: ClassIndex<ExtensionData<ParameterRangeUnresolved>[]>, classIndex: ClassIndex<ClassReferenceLoaded>): Promise<ClassIndex<ExtensionData<ParameterRangeResolved>[]>>;
    /**
     * Resolve the given array of generic type parameter data in parallel.
     * @param extensionDatas The extensions of the class.
     * @param owningClass The class in which the given generic type parameters are declared.
     * @param genericTypeRemappings A remapping of generic type names.
     */
    resolveExtensionData(extensionDatas: ExtensionData<ParameterRangeUnresolved>[], owningClass: ClassReferenceLoaded, genericTypeRemappings: Record<string, ParameterRangeUnresolved>): Promise<ExtensionData<ParameterRangeResolved>[]>;
    protected isIgnored(qualifiedPath: string[] | undefined, className: string): boolean;
    /**
     * Resolve the given parameter range.
     * @param range An unresolved parameter range.
     * @param owningClass The class this range was defined in.
     * @param genericTypeRemappings A remapping of generic type names.
     * @param getNestedFields If Records and interfaces should produce nested field ranges.
     * @param handlingInterfaces The names of interfaces that are being handled, and this interface is a part of.
     */
    resolveRange(range: ParameterRangeUnresolved, owningClass: ClassReferenceLoaded, genericTypeRemappings: Record<string, ParameterRangeUnresolved>, getNestedFields: boolean, handlingInterfaces: Set<string>): Promise<ParameterRangeResolved>;
    /**
     * Hash the given parameter range to a unique string representation.
     * @param range An unresolved range.
     */
    hashParameterRangeUnresolved(range: ParameterRangeUnresolved): string;
    /**
     * Resolve a class or interface.
     * @param interfaceName A class or interface name.
     * @param qualifiedPath Qualified path to the class or interface. Is undefined if there is no qualified path.
     * @param genericTypeParameterInstances Generic type parameters that were supplied for instantiation.
     *                                      Note that these generics are NOT the same as the generics that may be defined
     *                                      within the class itself.
     * @param owningClass The class this interface was used in.
     * @param rootOwningClass The top-level class this interface was used in. Necessary for generic type resolution.
     * @param genericTypeRemappings A remapping of generic type names.
     * @param getNestedFields If Records and interfaces should produce nested field ranges.
     * @param handlingInterfaces The names of interfaces that are being handled, and this interface is a part of.
     */
    resolveRangeInterface(interfaceName: string, qualifiedPath: string[] | undefined, genericTypeParameterInstances: ParameterRangeUnresolved[] | undefined, owningClass: ClassReferenceLoaded, rootOwningClass: ClassReferenceLoaded, genericTypeRemappings: Record<string, ParameterRangeUnresolved>, getNestedFields: boolean, handlingInterfaces: Set<string>): Promise<ParameterRangeResolved>;
    protected resolveRangeInterfaceInner(interfaceName: string, qualifiedPath: string[] | undefined, genericTypeParameterInstances: ParameterRangeUnresolved[] | undefined, owningClass: ClassReferenceLoaded, rootOwningClass: ClassReferenceLoaded, genericTypeRemappings: Record<string, ParameterRangeUnresolved>, getNestedFields: boolean, handlingInterfaces: Set<string>): Promise<ParameterRangeResolved>;
    /**
     * Check if the given interface should actually be considered a class.
     * Concretely, it will check whether or not there is at least one method or constructor.
     * @param iface An interface.
     */
    isInterfaceImplicitClass(iface: InterfaceLoaded): boolean;
    /**
     * Load the given class reference, which could either be a class or interface.
     *
     * If it's a class, just load it, without loading its superclasses.
     * If it's an interface, load all of its superinterfaces recursively.
     *
     * This method will throw if an interface extends from a class.
     *
     * @param classReference A class reference.
     */
    loadClassOrInterfacesChain(classReference: ClassReference): Promise<ClassReferenceLoaded>;
    /**
     * Recursively get all fields from the given interface.
     * @param iface A loaded interface.
     * @param owningClass The class this hash is declared in.
     * @param genericTypeRemappings A remapping of generic type names.
     * @param handlingInterfaces The names of interfaces that are being handled, and this interface is a part of.
     */
    getNestedFieldsFromInterface(iface: InterfaceLoaded, owningClass: ClassReferenceLoaded, genericTypeRemappings: Record<string, ParameterRangeUnresolved>, handlingInterfaces: Set<string>): Promise<ParameterData<ParameterRangeResolved>[]>;
    /**
     * Recursively get all fields from the given hash.
     * @param hash A hash object.
     * @param owningClass The class this hash is declared in.
     * @param genericTypeRemappings A remapping of generic type names.
     * @param handlingInterfaces The names of interfaces that are being handled, and this interface is a part of.
     */
    getNestedFieldsFromHash(hash: TSESTree.TSTypeLiteral, owningClass: ClassReferenceLoaded, genericTypeRemappings: Record<string, ParameterRangeUnresolved>, handlingInterfaces: Set<string>): Promise<ParameterData<ParameterRangeResolved>[]>;
}
export interface ParameterResolverArgs {
    classLoader: ClassLoader;
    parameterLoader: ParameterLoader;
    ignoreClasses: Record<string, boolean>;
}
