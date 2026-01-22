"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.GenericsLoader = void 0;
/**
 * Loads the generics data of classes.
 */
class GenericsLoader {
    constructor(args) {
        this.parameterLoader = args.parameterLoader;
    }
    /**
     * Create a class index containing all generics data from the classes in the given index.
     * @param classIndex An index of loaded classes.
     */
    getGenerics(classIndex) {
        const genericsDataIndex = {};
        for (const [className, classLoadedRoot] of Object.entries(classIndex)) {
            if (classLoadedRoot.type === 'class' || classLoadedRoot.type === 'interface') {
                genericsDataIndex[className] = this.parameterLoader.loadClassGenerics(classLoadedRoot);
            }
        }
        return genericsDataIndex;
    }
}
exports.GenericsLoader = GenericsLoader;
//# sourceMappingURL=GenericsLoader.js.map