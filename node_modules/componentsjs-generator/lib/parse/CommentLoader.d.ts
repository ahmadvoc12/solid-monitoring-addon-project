import type { TSESTree } from '@typescript-eslint/typescript-estree';
import type { ClassReference, ClassReferenceLoaded } from './ClassIndex';
import type { ConstructorHolder } from './ConstructorLoader';
import type { DefaultNested, DefaultValue, ParameterRangeUnresolved } from './ParameterLoader';
/**
 * Loads comments from fields in a given class.
 */
export declare class CommentLoader {
    /**
     * Extract comment data from the given constructor inheritance chain.
     * @param constructorChain An array of constructors within the class inheritance chain.
     */
    getCommentDataFromConstructor(constructorChain: ConstructorHolder[]): ConstructorCommentData;
    /**
     * Extract comment data from the given constructor.
     * @param classLoaded The loaded class in which the constructor is defined.
     * @param constructor A constructor.
     */
    getCommentDataFromConstructorSingle(classLoaded: ClassReferenceLoaded, constructor: TSESTree.MethodDefinition): ConstructorCommentData;
    /**
     * Get comment data from the given constructor comment.
     * @param comment A constructor comment string.
     * @param clazz A class reference, for error reporting.
     */
    static getCommentDataFromConstructorComment(comment: string, clazz: ClassReference): ConstructorCommentData;
    /**
     * Extract comment data from the given field.
     * @param classLoaded The loaded class in which the field is defined.
     * @param field A field.
     */
    getCommentDataFromField(classLoaded: ClassReferenceLoaded, field: TSESTree.TSPropertySignature | TSESTree.TSIndexSignature): CommentData;
    /**
     * Extract comment data from the given class.
     * @param classLoaded The loaded class or interface.
     */
    getCommentDataFromClassOrInterface(classLoaded: ClassReferenceLoaded): CommentData;
    /**
     * Get comment data from the given comment.
     * @param comment A comment string.
     * @param clazz A class reference, for error reporting.
     */
    static getCommentDataFromComment(comment: string, clazz: ClassReference): CommentData;
    /**
     * Parse the microsyntax of a default value.
     *
     * Can be one of:
     * * raw value: "abc"
     * * iri value: "<ex:abc>"
     * * type value: "a <ex:Type>"
     * * iri and type value: "<ex:abc> a <ex:Type>"
     *
     * @param value A default value string.
     * @param clazz The class reference this value is loaded in.
     */
    static getDefaultValue(value: string, clazz: ClassReference): DefaultValue;
    /**
     * Unbox an IRI wrapped in <>
     * @param iriBoxed An iri string within <>
     */
    static getIriValue(iriBoxed: string): string | undefined;
    /**
     * Get the comment string from the given node.
     * @param classLoaded The loaded class in which the field is defined.
     * @param node A node, such as a field or constructor.
     */
    getCommentRaw(classLoaded: ClassReferenceLoaded, node: TSESTree.BaseNode): string | undefined;
}
/**
 * Maps field keys to comments.
 */
export type ConstructorCommentData = Record<string, CommentData>;
export interface CommentData {
    /**
     * The range of the parameter values.
     */
    range?: ParameterRangeUnresolved;
    /**
     * The default values.
     */
    defaults?: DefaultValue[];
    /**
     * If the field referenced by this comment should be ignored.
     */
    ignored?: boolean;
    /**
     * The human-readable description of this comment.
     */
    description?: string;
    /**
     * Parameters that were defined in this comment.
     */
    params?: Record<string, string>;
    /**
     * The nested default values on parameters.
     */
    defaultNested?: DefaultNested[];
}
