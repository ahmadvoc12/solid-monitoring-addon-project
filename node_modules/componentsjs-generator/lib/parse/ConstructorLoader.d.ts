import type { AST, TSESTreeOptions, TSESTree } from '@typescript-eslint/typescript-estree';
import type { ClassIndex, ClassLoaded, ClassReferenceLoaded, GenericallyTyped } from './ClassIndex';
import type { ParameterDataField, ParameterRangeUnresolved, ParameterLoader } from './ParameterLoader';
/**
 * Loads the constructor data of classes.
 */
export declare class ConstructorLoader {
    private readonly parameterLoader;
    constructor(args: ConstructorLoaderArgs);
    /**
     * Create a class index containing all constructor data from the classes in the given index.
     * @param classIndex An index of loaded classes.
     */
    getConstructors(classIndex: ClassIndex<ClassReferenceLoaded>): ClassIndex<ConstructorData<ParameterRangeUnresolved>>;
    /**
     * Load the superclass chain of constructor holders starting from the given class.
     * @param classLoaded The class to start from.
     */
    getConstructorChain(classLoaded: GenericallyTyped<ClassLoaded>): ConstructorHolder[];
    /**
     * Retrieve the constructor in the given class, or its super class.
     * Can be undefined if no explicit constructor exists in this class or any of its super classes.
     * @param classLoaded A loaded class reference.
     */
    getConstructor(classLoaded: GenericallyTyped<ClassLoaded>): ConstructorHolder | undefined;
    /**
     * Retrieve the constructor in the given class, or undefined if it could not be found.
     * @param declaration A class declaration
     */
    getConstructorInClass(declaration: TSESTree.ClassDeclaration): TSESTree.MethodDefinition | undefined;
    /**
     * Find the first class with the given name in the given parsed typescript file.
     * An error will be thrown if no class could be found with that name.
     * @param className A class name.
     * @param ast A parsed typescript file
     * @param fileName The file name, for error reporting.
     */
    getClass(className: string, ast: AST<TSESTreeOptions>, fileName: string): TSESTree.ClassDeclaration;
}
export interface ConstructorLoaderArgs {
    parameterLoader: ParameterLoader;
}
/**
 * Constructor parameter information
 */
export interface ConstructorData<R> {
    parameters: ParameterDataField<R>[];
    classLoaded: ClassReferenceLoaded;
}
/**
 * Datastructure for holding a constructor and the class it is part of.
 */
export interface ConstructorHolder {
    constructor: TSESTree.MethodDefinition;
    classLoaded: GenericallyTyped<ClassLoaded>;
}
