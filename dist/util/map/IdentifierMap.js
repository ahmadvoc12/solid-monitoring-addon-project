"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.IdentifierSetMultiMap = exports.IdentifierMap = exports.identifierHashFn = void 0;
const HashMap_1 = require("./HashMap");
const WrappedSetMultiMap_1 = require("./WrappedSetMultiMap");
/**
 * Converts a {@link ResourceIdentifier} into a string unique to that identifier.
 */
function identifierHashFn(identifier) {
    return identifier.path;
}
exports.identifierHashFn = identifierHashFn;
/**
 * A specific implementation of {@link HashMap} where the key type is {@link ResourceIdentifier}.
 */
class IdentifierMap extends HashMap_1.HashMap {
    constructor(iterable) {
        super(identifierHashFn, iterable);
    }
}
exports.IdentifierMap = IdentifierMap;
/**
 * A specific implementation of {@link WrappedSetMultiMap} where the key type is {@link ResourceIdentifier}.
 */
class IdentifierSetMultiMap extends WrappedSetMultiMap_1.WrappedSetMultiMap {
    constructor(iterable) {
        super(IdentifierMap, iterable);
    }
}
exports.IdentifierSetMultiMap = IdentifierSetMultiMap;
//# sourceMappingURL=IdentifierMap.js.map