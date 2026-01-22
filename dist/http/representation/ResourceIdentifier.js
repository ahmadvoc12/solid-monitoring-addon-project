"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isResourceIdentifier = void 0;
/**
 * Determines whether the object is a {@link ResourceIdentifier}.
 */
function isResourceIdentifier(object) {
    return Boolean(object) && typeof object.path === 'string';
}
exports.isResourceIdentifier = isResourceIdentifier;
//# sourceMappingURL=ResourceIdentifier.js.map