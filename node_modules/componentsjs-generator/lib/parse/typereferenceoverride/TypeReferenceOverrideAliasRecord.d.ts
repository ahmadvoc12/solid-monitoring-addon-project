import type { TSESTree } from '@typescript-eslint/typescript-estree';
import type { ParameterRangeUnresolved } from '../ParameterLoader';
import type { TypeReferenceOverride } from './TypeReferenceOverride';
/**
 * Converts type aliases of the form `Record<K, V>` into `{[k: K]: V}`.
 */
export declare class TypeReferenceOverrideAliasRecord implements TypeReferenceOverride {
    handle(typeNode: TSESTree.TSTypeReference): ParameterRangeUnresolved | undefined;
}
