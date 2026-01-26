interface AutoAclParams {
    podRootPath: string;
    ownerWebId: string;
    appWebId: string;
}
export declare function ensureBaseAcl({ podRootPath, ownerWebId, appWebId }: AutoAclParams): Promise<void>;
export {};
