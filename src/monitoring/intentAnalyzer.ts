export function analyzeScopes(scopes: string[]) {
  const map: Record<string, string[]> = {
    profile: ['foaf:name', 'vcard:fn'],
    webid: ['foaf:name', 'foaf:mbox'],
    'solid:read': ['any RDF resource'],
    'solid:write': ['modify POD data'],
    'solid:control': ['ACL & policies']
  };

  const fields = new Set<string>();
  scopes.forEach(s => (map[s] || []).forEach(f => fields.add(f)));

  return [...fields];
}
