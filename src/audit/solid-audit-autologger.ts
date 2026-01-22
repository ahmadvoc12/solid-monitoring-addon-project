import type {
  HttpHandler,
  HttpHandlerInput,
  HttpRequest,
} from '@solid/community-server';

export class AuditAutologger implements HttpHandler {
  private readonly logBasePath: string;

  public constructor(logBasePath: string) {
    this.logBasePath = logBasePath;
  }

  public async handle(input: HttpHandlerInput): Promise<void> {
    const request = input.request as HttpRequest;

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

    // ✅ lanjutkan pipeline dengan BENAR
    await input.next();
  }
}
