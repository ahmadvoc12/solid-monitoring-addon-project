"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.toLiteral = exports.toObjectTerm = exports.toPredicateTerm = exports.toNamedTerm = exports.isTerm = void 0;
const n3_1 = require("n3");
const { namedNode, literal } = n3_1.DataFactory;
/**
 * @param input - Checks if this is a {@link Term}.
 */
function isTerm(input) {
    return Boolean(input) && typeof input.termType === 'string';
}
exports.isTerm = isTerm;
function toNamedTerm(subject) {
    return typeof subject === 'string' ? namedNode(subject) : subject;
}
exports.toNamedTerm = toNamedTerm;
exports.toPredicateTerm = toNamedTerm;
function toObjectTerm(object, preferLiteral = false) {
    if (typeof object === 'string') {
        return preferLiteral ? literal(object) : namedNode(object);
    }
    return object;
}
exports.toObjectTerm = toObjectTerm;
/**
 * Creates a literal by first converting the dataType string to a named node.
 *
 * @param object - Object value.
 * @param dataType - Object data type (as string).
 */
function toLiteral(object, dataType) {
    return literal(`${object}`, dataType);
}
exports.toLiteral = toLiteral;
//# sourceMappingURL=TermUtil.js.map