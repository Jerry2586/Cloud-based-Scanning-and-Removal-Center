#!/usr/bin/env node
// Keep the copyable empty-server entry byte-for-byte aligned with the tested script.
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
const root = new URL('../', import.meta.url);
const entry = (await readFile(new URL('scripts/git-install-entry.sh', root), 'utf8')).trimEnd();
const blocks = ['local', 'cloud'].map(role => {
  const title = role === 'local' ? '**需要保护的服务器：铁幕安全。**' : '**独立安全服务器：玄武引擎。**';
  return title + '\n\n\x60\x60\x60sh\nsudo sh -s -- ' + role + " <<'IRONCURTAIN_INSTALL'\n" + entry + '\nIRONCURTAIN_INSTALL\n\x60\x60\x60';
}).join('\n\n');
const start = '<!-- ONLINE-INSTALL:START -->';
const end = '<!-- ONLINE-INSTALL:END -->';
const readmeFile = new URL('README.md', root);
const readme = await readFile(readmeFile, 'utf8');
const first = readme.indexOf(start), last = readme.indexOf(end);
if (first < 0 || last <= first || readme.indexOf(start, first + 1) >= 0 || readme.indexOf(end, last + 1) >= 0) throw new Error('Online install markers must occur exactly once');
const updated = readme.slice(0, first) + start + '\n\n' + blocks + '\n\n' + readme.slice(last);
if (process.argv.includes('--check')) {
  if (updated !== readme) throw new Error('README install commands differ from scripts/git-install-entry.sh; run node scripts/render-git-install.js');
  console.log('Git online install commands match the tested entry');
} else {
  await writeFile(fileURLToPath(readmeFile), updated);
}
