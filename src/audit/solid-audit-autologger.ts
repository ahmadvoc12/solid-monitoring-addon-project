import type {
  HttpHandler,
  HttpRequest,
  HttpResponse,
} from '@solid/community-server';

export class AuditAutologger implements HttpHandler {
  private readonly logBasePath: string;

  public constructor(logBasePath: string) {
    this.logBasePath = logBasePath;
  }

  public async handle(request: HttpRequest): Promise<HttpResponse> {
    const webId =
      request.headers.authorization ??
      request.headers['solid-webid'] ??
      'anonymous';

    console.log('[DPV-AUDIT]', {
      method: request.method,
      url: request.url,
      webId,
      logBasePath: this.logBasePath,
      time: new Date().toISOString(),
    });

    // ⚠️ WAJIB lanjutkan pipeline
    return request.next();
  }
}
