"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.analyzeScopes = void 0;
function analyzeScopes(scopes) {
    const map = {
        profile: ['foaf:name', 'vcard:fn'],
        webid: ['foaf:name', 'foaf:mbox'],
        'solid:read': ['any RDF resource'],
        'solid:write': ['modify POD data'],
        'solid:control': ['ACL & policies']
    };
    const fields = new Set();
    scopes.forEach(s => (map[s] || []).forEach(f => fields.add(f)));
    return [...fields];
}
exports.analyzeScopes = analyzeScopes;
//# sourceMappingURL=intentAnalyzer.js.map