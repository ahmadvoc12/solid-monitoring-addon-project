"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createGenericEventEmitterClass = void 0;
const node_events_1 = require("node:events");
/**
 * Creates a class that is an implementation of {@link EventEmitter}
 * but with specific typings based on {@link GenericEventEmitter}.
 * Useful in case a class needs to extend {@link EventEmitter} and wants specific internal typings.
 */
function createGenericEventEmitterClass() {
    return node_events_1.EventEmitter;
}
exports.createGenericEventEmitterClass = createGenericEventEmitterClass;
//# sourceMappingURL=GenericEventEmitter.js.map