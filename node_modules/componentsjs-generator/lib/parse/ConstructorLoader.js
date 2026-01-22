"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ConstructorLoader = void 0;
const typescript_estree_1 = require("@typescript-eslint/typescript-estree");
/**
 * Loads the constructor data of classes.
 */
class ConstructorLoader {
    constructor(args) {
        this.parameterLoader = args.parameterLoader;
    }
    /**
     * Create a class index containing all constructor data from the classes in the given index.
     * @param classIndex An index of loaded classes.
     */
    getConstructors(classIndex) {
        const constructorDataIndex = {};
        for (const [className, classLoadedRoot] of Object.entries(classIndex)) {
            // Initialize default value
            constructorDataIndex[className] = {
                parameters: [],
                classLoaded: classLoadedRoot,
            };
            // Fill in constructor data if we're loading a class, and we find a constructor in the inheritance chain.
            if (classLoadedRoot.type === 'class') {
                const constructorChain = this.getConstructorChain({ value: classLoadedRoot });
                if (constructorChain.length > 0) {
                    constructorDataIndex[className] = this.parameterLoader.loadConstructorFields(constructorChain);
                }
            }
        }
        return constructorDataIndex;
    }
    /**
     * Load the superclass chain of constructor holders starting from the given class.
     * @param classLoaded The class to start from.
     */
    getConstructorChain(classLoaded) {
        const constructorData = this.getConstructor(classLoaded);
        const chain = [];
        if (constructorData) {
            chain.push(constructorData);
            if (constructorData.classLoaded.value.superClass) {
                chain.push(...this.getConstructorChain(constructorData.classLoaded.value.superClass));
            }
        }
        return chain;
    }
    /**
     * Retrieve the constructor in the given class, or its super class.
     * Can be undefined if no explicit constructor exists in this class or any of its super classes.
     * @param classLoaded A loaded class reference.
     */
    getConstructor(classLoaded) {
        // First look for the constructor in this class
        let constructor = this.getConstructorInClass(classLoaded.value.declaration);
        // If no constructor was found, look in the super class
        if (!constructor && classLoaded.value.superClass) {
            const constructorDataSuper = this.getConstructor(classLoaded.value.superClass);
            if (constructorDataSuper) {
                constructor = constructorDataSuper.constructor;
                classLoaded = constructorDataSuper.classLoaded;
            }
        }
        return constructor ? { constructor, classLoaded } : undefined;
    }
    /**
     * Retrieve the constructor in the given class, or undefined if it could not be found.
     * @param declaration A class declaration
     */
    getConstructorInClass(declaration) {
        for (const element of declaration.body.body) {
            if (element.type === typescript_estree_1.AST_NODE_TYPES.MethodDefinition &&
                element.kind === 'constructor') {
                return element;
            }
        }
    }
    /**
     * Find the first class with the given name in the given parsed typescript file.
     * An error will be thrown if no class could be found with that name.
     * @param className A class name.
     * @param ast A parsed typescript file
     * @param fileName The file name, for error reporting.
     */
    getClass(className, ast, fileName) {
        for (const statement of ast.body) {
            // Classes in the form of `declare class A {}`
            if (statement.type === typescript_estree_1.AST_NODE_TYPES.ClassDeclaration &&
                statement.id &&
                statement.id.name === className) {
                return statement;
            }
            // Classes in the form of `export class A{}`
            if (statement.type === typescript_estree_1.AST_NODE_TYPES.ExportNamedDeclaration &&
                statement.declaration &&
                statement.declaration.type === typescript_estree_1.AST_NODE_TYPES.ClassDeclaration &&
                statement.declaration.id &&
                statement.declaration.id.name === className) {
                return statement.declaration;
            }
        }
        throw new Error(`Could not find class ${className} in ${fileName}`);
    }
}
exports.ConstructorLoader = ConstructorLoader;
//# sourceMappingURL=ConstructorLoader.js.map