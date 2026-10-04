import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { verifyRelease } from '../src/release-verification.js';
const args = process.argv.slice(2);
const value = name => {
  const index = args.indexOf(name);
  if (index < 0 || !args[index + 1]) throw Error('Missing ' + name);
  return args[index + 1];
};
const result = verifyRelease({ directory: resolve(value('--dir')), publicKey: readFileSync(resolve(value('--public-key'))),
  expectedVersion: args.includes('--version') ? value('--version') : undefined });
console.log('Verified signed release v' + result.version + ' (' + result.assets.length + ' assets)');
