import { readFile } from 'node:fs/promises';

export interface WatchStatus { state: 'unknown' | 'waiting' | 'applied' | 'failed'; message: string; appliedAt: number | null }
export function watchStatus(text: string, report: unknown, now = Date.now()): WatchStatus {
  const r = report as { applied_text?: string; error?: string; applied_at?: number; updated_at?: number; interval_ms?: number } | null;
  const appliedAt = typeof r?.applied_at === 'number' ? r.applied_at : null;
  if (!r || typeof r.updated_at !== 'number' || now - r.updated_at > Math.max(30_000, (r.interval_ms ?? 500) * 3 + 1000)) {
    return { state: 'unknown', message: '未检测到近期热载报告，请检查 apply --watch 是否运行', appliedAt };
  }
  if (r.applied_text === text && appliedAt) return { state: 'applied', message: '当前文件已热载成功', appliedAt };
  if (r.error) return { state: 'failed', message: r.error, appliedAt };
  return { state: 'waiting', message: '文件已保存，等待 watch 热载', appliedAt };
}
export async function readWatchStatus(path: string): Promise<WatchStatus> {
  const text = await readFile(path, 'utf8');
  let report: unknown = null;
  try { report = JSON.parse(await readFile(path + '.watch.json', 'utf8')); } catch { /* Old or stopped watchers may have no readable report. */ }
  return watchStatus(text, report);
}
