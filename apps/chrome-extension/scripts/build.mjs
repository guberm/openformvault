import { mkdir, rm, cp, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dist = path.join(root, 'dist');
const out = path.join(dist, 'openformvault-chrome-extension');
await rm(dist, { recursive: true, force: true });
await mkdir(out, { recursive: true });
await cp(path.join(root, 'extension'), out, { recursive: true });
await writeFile(path.join(dist, 'README.txt'), 'Load openformvault-chrome-extension as an unpacked MV3 extension.\n');
const zip = path.join(dist, 'openformvault-chrome-extension-v0.1.0-alpha.1.zip');
const result = spawnSync('zip', ['-qr', zip, 'openformvault-chrome-extension'], { cwd: dist, stdio: 'inherit' });
if (result.status !== 0) process.exit(result.status ?? 1);
console.log(zip);
