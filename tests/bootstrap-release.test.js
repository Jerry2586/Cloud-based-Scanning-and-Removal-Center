import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync, sign, createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
const installer = readFileSync(new URL('../install.sh', import.meta.url), 'utf8');
const definitions = installer.slice(installer.indexOf('ca_ready() {'), installer.indexOf('\ninstall_tools\n'));
const linuxTools = process.platform === 'linux' && ['sh', 'jq', 'openssl'].every(tool => spawnSync('which', [tool]).status === 0);

function attempt(mode) {
  const dir = mkdtempSync(join(tmpdir(), 'ironcurtain-bootstrap-release-'));
  try {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const payload = Buffer.from('#!/bin/sh\nexit 0\n');
    const manifest = Buffer.from(JSON.stringify({schema:1, product:'appgog-cloud-security-center', version:'0.4.0', run_name:'APPGOG-Cloud-Security-Center-0.4.0.run', run_sha256:createHash('sha256').update(payload).digest('hex')}));
    writeFileSync(join(dir,'key.pem'), publicKey.export({type:'spki',format:'pem'}));
    writeFileSync(join(dir,'fixture.json'), manifest);
    writeFileSync(join(dir,'fixture.sig'), mode === 'signature' ? Buffer.alloc(64) : sign(null,manifest,privateKey));
    writeFileSync(join(dir,'fixture.run'), mode === 'hash' ? 'corrupted' : payload);
    const script = definitions + `
WORK="$TEST_DIR"
PRODUCT=appgog-cloud-security-center
ARTIFACT_PREFIX=APPGOG-Cloud-Security-Center
REQUESTED_VERSION=''
APPGOG_SECURITY_RELEASE_PUBLIC_KEY_FILE="$WORK/key.pem"
APPGOG_SECURITY_ALLOW_TEST_KEY=true
fail() { echo "$*" >&2; exit 1; }
curl() {
  [ "$1" = -q ] || { echo 'curlrc not disabled' >&2; return 1; }
  dest=''
  while [ "$#" -gt 0 ]; do case "$1" in -o) dest=$2; shift ;; esac; shift; done
  case "$TEST_MODE" in auth) printf 404; return 22 ;; network) printf 000; return 7 ;; rate_limit) printf 403; return 22 ;; server) printf 503; return 22 ;; esac
  case "$dest" in */release-manifest.json) cp "$WORK/fixture.json" "$dest" ;; */release-manifest.json.sig) cp "$WORK/fixture.sig" "$dest" ;; */installer.run) cp "$WORK/fixture.run" "$dest" ;; *) return 1 ;; esac
  printf 200
}
write_public_key "$WORK/release-public.pem"
if try_release https://example.invalid; then echo 'RESULT=accepted'; else echo "RESULT=$RELEASE_FAILURE"; fi
`;
    return spawnSync('sh', ['-s'], { input:script, encoding:'utf8', env:{...process.env, TEST_DIR:dir, TEST_MODE:mode} });
  } finally { rmSync(dir,{recursive:true,force:true}); }
}
for (const [mode, expected] of [['good','accepted'], ['signature','signature'], ['hash','hash'], ['auth','auth'], ['network','download'], ['rate_limit','download'], ['server','download']]) {
  test(`bootstrap distinguishes ${mode} without executing an unverified package`, {skip:!linuxTools}, () => {
    const result = attempt(mode);
    assert.equal(result.status,0,result.stderr);
    assert.match(result.stdout,new RegExp('RESULT=' + expected));
    if (mode === 'signature') assert.match(result.stderr,/不需要输入 Token/);
  });
}
test('bootstrap only considers hidden token prompt after an HTTP authentication failure', () => {
  assert.match(installer,/elif \[ "\$RELEASE_FAILURE" = auth \] && ! private_release_enabled && request_release_token; then/);
  assert.doesNotMatch(installer,/\bcurl (?:-fs|--proto)/);
});
