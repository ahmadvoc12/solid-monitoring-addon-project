import type { HttpHandler, HttpRequest, HttpResponse } from '@solid/community-server';
export declare class AuditAutologger implements HttpHandler {
    private readonly logBasePath;
    constructor(logBasePath: string);
    handle(request: HttpRequest): Promise<HttpResponse>;
}
