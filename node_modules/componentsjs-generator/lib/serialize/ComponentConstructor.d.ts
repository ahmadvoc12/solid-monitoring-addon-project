import type { ContextParser, JsonLdContextNormalized } from 'jsonld-context-parser';
import type { ClassIndex, ClassLoaded, ClassReference, ClassReferenceLoadedClassOrInterface } from '../parse/ClassIndex';
import type { ConstructorData } from '../parse/ConstructorLoader';
import type { GenericsData } from '../parse/GenericsLoader';
import type { MemberData } from '../parse/MemberLoader';
import type { PackageMetadata } from '../parse/PackageMetadataLoader';
import type { DefaultNested, DefaultValue, GenericTypeParameterData, ParameterData, ParameterRangeResolved, ExtensionData, MemberParameterData } from '../parse/ParameterLoader';
import type { ExternalComponents } from '../resolution/ExternalModulesLoader';
import type { ComponentDefinition, ComponentDefinitions, ComponentDefinitionsIndex, ConstructorArgumentDefinition, ConstructorFieldDefinition, DefaultValueDefinition, ParameterDefinition, ParameterDefinitionRange, GenericTypeParameterDefinition, ExtensionDefinition, MemberFieldDefinition } from './ComponentDefinitions';
import { ContextConstructor } from './ContextConstructor';
/**
 * Creates declarative JSON components for the given classes.
 */
export declare class ComponentConstructor {
    private readonly packageMetadata;
    private readonly fileExtension;
    private readonly contextConstructor;
    private readonly pathDestination;
    private readonly classAndInterfaceIndex;
    private readonly classConstructors;
    private readonly classGenerics;
    private readonly classExtensions;
    private readonly classMembers;
    private readonly externalComponents;
    private readonly contextParser;
    constructor(args: ComponentConstructorArgs);
    /**
     * Construct component definitions for all classes in the current index.
     */
    constructComponents(): Promise<ComponentDefinitions>;
    /**
     * Construct a component definitions index.
     * @param definitions The component definitions for which the index should be constructed.
     */
    constructComponentsIndex(definitions: ComponentDefinitions): Promise<ComponentDefinitionsIndex>;
    /**
     * Determine the relative path of a component file within a package.
     * @param pathDestination The path destination.
     * @param sourcePath The absolute path to a class file.
     */
    static getPathRelative(pathDestination: PathDestinationDefinition, sourcePath: string): string;
    /**
     * Determine the path a component file should exist at based on a class source file path.
     * @param pathDestination The path destination.
     * @param sourcePath The absolute path to a class file.
     */
    static getPathDestination(pathDestination: PathDestinationDefinition, sourcePath: string): string;
    /**
     * Determine the IRI of the given source path.
     * @param sourcePath The relative path to a components file.
     */
    getImportPathIri(sourcePath: string): string;
    /**
     * Construct a component definition from the given constructor data.
     * @param context A parsed JSON-LD context.
     * @param externalContextsCallback Callback for external contexts.
     * @param classReference Class reference of the class component.
     * @param constructorData Constructor data of the owning class.
     * @param genericsData Generics data of the owning class.
     * @param classExtensions Class extensions of the owning class.
     * @param classMembers Class members of the owning class.
     */
    constructComponent(context: JsonLdContextNormalized, externalContextsCallback: ExternalContextCallback, classReference: ClassReferenceLoadedClassOrInterface, constructorData: ConstructorData<ParameterRangeResolved> | undefined, genericsData: GenericsData<ParameterRangeResolved> | undefined, classExtensions: ExtensionData<ParameterRangeResolved>[] | undefined, classMembers: MemberParameterData<ParameterRangeResolved>[] | undefined): Promise<ComponentDefinition>;
    /**
     * Construct a compacted class IRI.
     * @param context A parsed JSON-LD context.
     * @param externalContextsCallback Callback for external contexts.
     * @param extensionData The extension data.
     */
    constructExtensionDefinition(context: JsonLdContextNormalized, externalContextsCallback: ExternalContextCallback, extensionData: ExtensionData<ParameterRangeResolved>): Promise<ExtensionDefinition>;
    /**
     * Construct a compacted module IRI.
     * @param context A parsed JSON-LD context.
     */
    moduleIriToId(context: JsonLdContextNormalized): string;
    /**
     * Construct a compacted class IRI.
     * @param context A parsed JSON-LD context.
     * @param externalContextsCallback Callback for external contexts.
     * @param classReference The class reference.
     */
    classNameToId(context: JsonLdContextNormalized, externalContextsCallback: ExternalContextCallback, classReference: ClassReference): Promise<string>;
    static classNameToIdForPackage(context: JsonLdContextNormalized, packageMetadata: PackageMetadata, pathDestination: PathDestinationDefinition, classReference: ClassReference, fileExtension: string): Promise<string>;
    static classNameToIriForPackage(packageMetadata: PackageMetadata, pathDestination: PathDestinationDefinition, classReference: ClassReference, fileExtension: string): string;
    /**
     * Construct a compacted field IRI.
     * @param context A parsed JSON-LD context.
     * @param classReference The class reference.
     * @param fieldName The name of the field.
     * @param scope The current field scope.
     */
    fieldNameToId(context: JsonLdContextNormalized, classReference: ClassReference, fieldName: string, scope: FieldScope): string;
    /**
     * Construct a compacted generic name IRI.
     * @param context A parsed JSON-LD context.
     * @param classReference The class reference.
     * @param genericTypeName The name of the generic type.
     */
    genericNameToId(context: JsonLdContextNormalized, classReference: ClassReference, genericTypeName: string): string;
    /**
     * Construct a compacted member name IRI.
     * @param context A parsed JSON-LD context.
     * @param classReference The class reference.
     * @param memberName The name of the member type.
     */
    memberToId(context: JsonLdContextNormalized, classReference: ClassReference, memberName: string): string;
    /**
     * Construct constructor arguments from the given constructor data.
     * Additionally, parameters will be appended to the parameters array.
     *
     * @param context A parsed JSON-LD context.
     * @param externalContextsCallback Callback for external contexts.
     * @param classReference Class reference of the class component owning this constructor.
     * @param genericTypes Generic types of the class.
     */
    constructGenericTypeParameters(context: JsonLdContextNormalized, externalContextsCallback: ExternalContextCallback, classReference: ClassReferenceLoadedClassOrInterface, genericTypes: GenericTypeParameterData<ParameterRangeResolved>[]): Promise<GenericTypeParameterDefinition[]>;
    /**
     * Construct constructor arguments from the given member data.
     *
     * @param context A parsed JSON-LD context.
     * @param externalContextsCallback Callback for external contexts.
     * @param classReference Class reference of the class component owning this constructor.
     * @param members Members of the class.
     */
    constructMembers(context: JsonLdContextNormalized, externalContextsCallback: ExternalContextCallback, classReference: ClassReferenceLoadedClassOrInterface, members: MemberParameterData<ParameterRangeResolved>[]): Promise<MemberFieldDefinition[]>;
    /**
     * Construct constructor arguments from the given constructor data.
     * Additionally, parameters will be appended to the parameters array.
     *
     * @param context A parsed JSON-LD context.
     * @param externalContextsCallback Callback for external contexts.
     * @param classReference Class reference of the class component owning this constructor.
     * @param constructorData Constructor data of the owning class.
     * @param parameters The array of parameters of the owning class, which will be appended to.
     */
    constructParameters(context: JsonLdContextNormalized, externalContextsCallback: ExternalContextCallback, classReference: ClassLoaded, constructorData: ConstructorData<ParameterRangeResolved>, parameters: ParameterDefinition[]): Promise<ConstructorArgumentDefinition[]>;
    /**
     * Construct a constructor argument from the given parameter data.
     * Additionally, one (or more) parameters will be appended to the parameters array.
     *
     * This may be invoked recursively based on the parameter type.
     *
     * @param context A parsed JSON-LD context.
     * @param externalContextsCallback Callback for external contexts.
     * @param classReference Class reference of the class component owning this parameter.
     * @param parameterData Parameter data.
     * @param parameters The array of parameters of the owning class, which will be appended to.
     * @param fieldId The @id of the field.
     * @param scope The current field scope.
     */
    parameterDataToConstructorArgument(context: JsonLdContextNormalized, externalContextsCallback: ExternalContextCallback, classReference: ClassLoaded, parameterData: ParameterData<ParameterRangeResolved>, parameters: ParameterDefinition[], fieldId: string, scope: FieldScope): Promise<ConstructorArgumentDefinition>;
    constructDefaultValueDefinition(fieldId: string, context: JsonLdContextNormalized, externalContextsCallback: ExternalContextCallback, defaultValue: DefaultValue, range: ParameterRangeResolved): Promise<DefaultValueDefinition>;
    /**
     * For the given parameter with nested range, construct field definitions for all sub-parameters.
     * @param context A parsed JSON-LD context.
     * @param externalContextsCallback Callback for external contexts.
     * @param classReference Class reference of the class component owning this parameter.
     * @param parameterData Parameter data with nested range.
     * @param parameters The array of parameters of the owning class, which will be appended to.
     * @param subParamData The sub-parameter of the parameter with nested range.
     * @param fieldId The @id of the field.
     * @param scope The current field scope.
     */
    constructFieldDefinitionNested(context: JsonLdContextNormalized, externalContextsCallback: ExternalContextCallback, classReference: ClassLoaded, parameterData: ParameterData<ParameterRangeResolved> & {
        range: {
            type: 'nested';
        };
    }, parameters: ParameterDefinition[], subParamData: ParameterData<ParameterRangeResolved>, fieldId: string, scope: FieldScope): Promise<ConstructorFieldDefinition>;
    /**
     * Determine the parameter definition's range definition.
     * @param range The range of a parameter
     * @param context A parsed JSON-LD context.
     * @param externalContextsCallback Callback for external contexts.
     * @param fieldId The @id of the field.
     */
    constructParameterRange(range: ParameterRangeResolved, context: JsonLdContextNormalized, externalContextsCallback: ExternalContextCallback, fieldId: string): Promise<ParameterDefinitionRange>;
    /**
     * Fill in the optional parameter definition values based on the given parameter data.
     * @param parameterDefinition A paramater definition to fill in.
     * @param parameterData Parameter data to read from.
     */
    populateOptionalParameterFields(parameterDefinition: ParameterDefinition, parameterData: ParameterData<ParameterRangeResolved>): void;
}
export interface ComponentConstructorArgs {
    packageMetadata: PackageMetadata;
    fileExtension: string;
    contextConstructor: ContextConstructor;
    pathDestination: PathDestinationDefinition;
    classAndInterfaceIndex: ClassIndex<ClassReferenceLoadedClassOrInterface>;
    classConstructors: ClassIndex<ConstructorData<ParameterRangeResolved>>;
    classGenerics: ClassIndex<GenericsData<ParameterRangeResolved>>;
    classExtensions: ClassIndex<ExtensionData<ParameterRangeResolved>[]>;
    classMembers: ClassIndex<MemberData<ParameterRangeResolved>>;
    externalComponents: ExternalComponents;
    contextParser: ContextParser;
}
export interface PathDestinationDefinition {
    /**
     * Absolute path to the package root.
     */
    packageRootDirectory: string;
    /**
     * Absolute path to the package source directory.
     */
    originalPath: string;
    /**
     * Absolute path to the package components target directory.
     */
    replacementPath: string;
}
export interface FieldScope {
    /**
     * All parent field names for the current scope.
     */
    parentFieldNames: string[];
    /**
     * A hash containing all previously created field names, to ensure uniqueness.
     */
    fieldIdsHash: Record<string, number>;
    /**
     * The nested default values on parameters.
     */
    defaultNested: DefaultNested[];
}
export type ExternalContextCallback = (contextUrl: string) => void;
