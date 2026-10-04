import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { readFile, writeFile, rename, unlink } from 'node:fs/promises';

export const DEFAULT_USER = 'admin';
export const DEFAULT_PASSWORD = '123456';
const SCRYPT = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

export interface User {
  username: string;
  salt: string;
  hash: string;
  changed: boolean;
}
export interface AuthFile { users: User[] }

export function hashPassword(password: string, salt = randomBytes(16)): { salt: string; hash: string } {
  return {
    salt: salt.toString('base64'),
    hash: scryptSync(password, salt, 32, SCRYPT).toString('base64'),
  };
}
export function verifyPassword(password: string, user: Pick<User, 'salt' | 'hash'>): boolean {
  const expected = Buffer.from(user.hash, 'base64');
  const actual = scryptSync(password, Buffer.from(user.salt, 'base64'), expected.length, SCRYPT);
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}
export function validUsername(username: string): boolean {
  return /^[A-Za-z0-9._-]{1,32}$/.test(username);
}
export function defaultAuth(): AuthFile {
  return { users: [{ username: DEFAULT_USER, ...hashPassword(DEFAULT_PASSWORD), changed: false }] };
}
const dummyUser = { ...hashPassword('unused-timing-pad'), username: 'dummy', changed: true };
export async function loadAuth(path: string): Promise<AuthFile> {
  try {
    const parsed = JSON.parse(await readFile(path, 'utf8')) as AuthFile;
    if (!Array.isArray(parsed.users) || parsed.users.some(u => !u.username || !u.salt || !u.hash)) throw new Error('账号文件无效');
    return parsed;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
    const auth = defaultAuth();
    await saveAuth(path, auth);
    return auth;
  }
}
export async function saveAuth(path: string, auth: AuthFile): Promise<void> {
  const temp = path + '.tmp.' + randomBytes(8).toString('hex');
  await writeFile(temp, JSON.stringify(auth, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  try { await rename(temp, path); } catch (e) { await unlink(temp).catch(() => {}); throw e; }
}
export function authenticate(auth: AuthFile, username: string, password: string): User | undefined {
  const user = auth.users.find(u => u.username === username);
  const ok = verifyPassword(password, user ?? dummyUser);
  return user && ok ? user : undefined;
}
