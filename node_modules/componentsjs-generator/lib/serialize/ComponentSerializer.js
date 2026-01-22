"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ComponentSerializer = void 0;
const PathUtil_1 = require("../util/PathUtil");
/**
 * Serializes components to files.
 */
class ComponentSerializer {
    constructor(args) {
        this.resolutionContext = args.resolutionContext;
        this.pathDestination = args.pathDestination;
        this.fileExtension = args.fileExtension;
        this.indentation = args.indentation;
    }
    async writeJsonToFile(fileNameBase, data) {
        const filePath = `${fileNameBase}.${this.fileExtension}`;
        await this.resolutionContext.writeFileContent(filePath, JSON.stringify(data, null, this.indentation));
        return filePath;
    }
    /**
     * Serialize the given components to files.
     * @param components Component definitions.
     * @return An array of absolute file paths that were created.
     */
    async serializeComponents(components) {
        const createdFiles = [];
        for (const [fileNameBase, component] of Object.entries(components)) {
            createdFiles.push(await this.writeJsonToFile(fileNameBase, component));
        }
        return createdFiles;
    }
    /**
     * Serialize the given components index to a file.
     * @param componentsIndex Component definitions index.
     * @return The absolute file path that was created.
     */
    async serializeComponentsIndex(componentsIndex) {
        const filePathBase = (0, PathUtil_1.joinFilePath)(this.pathDestination.replacementPath, 'components');
        return await this.writeJsonToFile(filePathBase, componentsIndex);
    }
    /**
     * Serialize the given context to a file.
     * @param contextRaw JSON-LD context contents.
     * @return The absolute file path that was created.
     */
    async serializeContext(contextRaw) {
        const filePathBase = (0, PathUtil_1.joinFilePath)(this.pathDestination.replacementPath, 'context');
        return await this.writeJsonToFile(filePathBase, contextRaw);
    }
}
exports.ComponentSerializer = ComponentSerializer;
//# sourceMappingURL=ComponentSerializer.js.map