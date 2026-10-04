#!/usr/bin/env node
// Generate short README commands and retain the full token-reusing entry in advanced docs.
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
const root = new URL('../', import.meta.url);
const check = process.argv.includes('--check');
for (const [target, source, delimiter] of [
  ['README.md', 'scripts/git-install-short.sh', 'IC'],
  ['docs/git-online-install.md', 'scripts/git-install-entry.sh', 'IRONCURTAIN_INSTALL']
]) {
  const entry = (await readFile(new URL(source, root), 'utf8')).trimEnd().replace(/^#![^\n]*\n/, '');
  const blocks = ['local', 'cloud'].map(role => {
    const title = role === 'local' ? '**需要保护的服务器：铁幕安全。**' : '**独立安全服务器：玄武引擎。**';
    return title + '\n\n```sh\nsudo sh -s -- ' + role + " <<'" + delimiter + "'\n" + entry + '\n' + delimiter + '\n```';
  }).join('\n\n');
  const path = new URL(target, root), text = await readFile(path, 'utf8');
  const start = '<!-- ONLINE-INSTALL:START -->', end = '<!-- ONLINE-INSTALL:END -->';
  const first = text.indexOf(start), last = text.indexOf(end);
  if (first < 0 || last <= first || text.indexOf(start, first + 1) >= 0 || text.indexOf(end, last + 1) >= 0) throw new Error(target + ': online install markers must occur exactly once');
  const updated = text.slice(0, first) + start + '\n\n' + blocks + '\n\n' + text.slice(last);
  if (check) {
    if (updated !== text) throw new Error(target + ': commands differ from the tested entry; run node scripts/render-git-install.js');
  } else await writeFile(fileURLToPath(path), updated);
}
if (check) console.log('Short and full Git install commands match their tested entries');
