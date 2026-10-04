import type { IncomingMessage, ServerResponse, RequestListener } from 'node:http';

class RequestError extends Error {
  constructor(message: string, readonly status: number) { super(message); }
}

export async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = []; let size = 0;
  // Keep the socket open on an early return so oversized requests receive a response.
  for await (const chunk of req.iterator({ destroyOnReturn: false })) {
    size += chunk.length;
    if (size > 1024 * 1024) {
      req.resume();
      throw new RequestError('请求超过 1MB', 413);
    }
    chunks.push(chunk);
  }
  let data: unknown;
  try { data = chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}; }
  catch { throw new RequestError('无效 JSON', 400); }
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new RequestError('请求必须是 JSON 对象', 400);
  return data as Record<string, unknown>;
}

export function withRequestErrors(handler: (req: IncomingMessage, res: ServerResponse) => Promise<void>): RequestListener {
  return (req, res) => {
    void handler(req, res).catch((e: unknown) => {
      if (res.destroyed || res.writableEnded) return;
      if (res.headersSent) { res.destroy(); return; }
      const error = e as Error & { stderr?: string; stdout?: string };
      res.writeHead(e instanceof RequestError ? e.status : 400, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ error: error?.stderr || error?.message || '请求处理失败', output: error?.stdout }));
    });
  };
}
