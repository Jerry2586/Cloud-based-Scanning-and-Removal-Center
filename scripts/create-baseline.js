import { createHash } from 'node:crypto';
import { readdirSync, lstatSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve, relative, sep } from 'node:path';
const root = resolve(process.argv[2] ?? '.');
const files = {};
const excluded = new Set(['.git', 'node_modules', 'var', '.codex', '.codex-tmp']);
function walk(path) {
  const full = resolve(root, path);
  let stat;
  try { stat = lstatSync(full); } catch (error) { if (error.code === 'ENOENT') return; throw error; }
  if (stat.isDirectory()) for (const child of readdirSync(full)) {
    if (!excluded.has(child)) walk(relative(root, resolve(full, child)));
  } else if (stat.isFile()) files[path.replaceAll('\\', '/')] = createHash('sha256').update(readFileSync(full)).digest('hex');
  else if (stat.isSymbolicLink()) files[path.replaceAll('\\', '/')] = 'SYMLINK';
}
for (const path of ['apps', 'packages', 'scripts', 'Dockerfile', 'compose.yaml']) walk(path);
process.stdout.write(JSON.stringify(files, null, 2) + '\n');
