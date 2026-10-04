import assert from 'node:assert/strict';
import { accessSync, constants, copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import test from 'node:test';

const root = resolve(import.meta.dirname, '..');
const projectVersion = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version;
const scripts = {
  bootstrap: join(root, 'install-docker.sh'),
  docker: join(root, 'scripts/docker.sh'),
  installer: join(root, 'scripts/install-linux.sh'),
  manager: join(root, 'scripts/appgog.sh'),
  securityLocal: join(root, 'scripts/security-local.sh'),
  securityConnect: join(root, 'scripts/security-connect.sh'),
  securityDoctor: join(root, 'scripts/security-doctor.sh'),
  updateHelper: join(root, 'scripts/update-helper.sh'),
  signedUpdateLibrary: join(root, 'scripts/lib/signed-update.sh'),
  releaseDownloadLibrary: join(root, 'scripts/lib/release-download.sh'),
  releaseInstallLibrary: join(root, 'scripts/lib/release-install.sh'),
  managerMigrationLibrary: join(root, 'scripts/lib/manager-migration.sh'),
  deploymentRoleLibrary: join(root, 'scripts/lib/deployment-role.sh'),
  migration: join(root, 'scripts/migration.sh'),
  dockerInstallLibrary: join(root, 'scripts/lib/docker-install.sh'),
  platformLibrary: join(root, 'scripts/lib/platform.sh'),
  verifySplit: join(root, 'scripts/docker/verify-split.sh'),
};

function text(path) {
  const contents = readFileSync(path, 'utf8');
  assert.ok(!contents.includes('\r\n'), `${path} 必须保持 LF 行尾`);
  return contents;
}

test('Linux installer installs Docker, protects existing configuration, and creates the global manager', () => {
  const installer = text(scripts.installer);
  const releaseInstaller = text(scripts.releaseInstallLibrary);
  assert.match(installer, /docker-ce docker-ce-cli containerd\.io docker-buildx-plugin docker-compose-plugin/);
  assert.match(installer, /appgog_compose_version_supported 24/);
  assert.match(text(scripts.dockerInstallLibrary), /compose_minor.*-ge "\$required_minor"/);
  assert.match(installer, /appgog_supported_arch "\$ARCH"/);
  assert.match(text(scripts.platformLibrary), /x86_64\|amd64\|aarch64\|arm64/);
  assert.match(installer, /docker buildx version/);
  assert.match(installer, /4194304/);
  assert.match(installer, /add-port=443\/udp/);
  assert.match(installer, /verify_download/);
  assert.match(installer, /--source MODE/);
  assert.match(installer, /scripts\/lib\/release-install\.sh/);
  assert.match(releaseInstaller, /release-manifest\.json\.sig/);
  assert.match(releaseInstaller, /openssl pkeyutl -verify/);
  assert.match(installer, /cloudflare_upsert_record/);
  assert.match(installer, /APPGOG_DOCKER_REGISTRY_MIRROR/);
  assert.match(installer, /select_base_images/);
  assert.match(installer, /m\.daocloud\.io\/docker\.io\/library\/node:24-bookworm-slim/);
  assert.match(installer, /docker\.m\.daocloud\.io\/library\/caddy:2\.10/);
  assert.match(installer, /手工指定的基础镜像不可用，未自动覆盖/);
  assert.match(installer, /--node-image[\s\S]*NODE_IMAGE_EXPLICIT=true/);
  assert.match(installer, /--caddy-image[\s\S]*CADDY_IMAGE_EXPLICIT=true/);
  assert.match(installer, /valid_image_ref/);
  assert.match(installer, /APPGOG_NODE_IMAGE=.*NODE_IMAGE/);
  assert.match(installer, /APPGOG_CADDY_IMAGE=.*CADDY_IMAGE/);
  assert.doesNotMatch(installer, /insecure-registries/);
  assert.match(installer, /sh scripts\/docker\.sh update/);
  assert.match(installer, /git clone.*\$temp_dir\/repository/);
  assert.match(installer, /copy_release_root "\$temp_dir\/repository"/);
  assert.match(installer, /\/opt\/appgog/);
  assert.match(installer, /保留已有 \.env/);
  assert.match(installer, /APPGOG_VERSION=.*package_version/);
  assert.match(installer, /chmod 600 "\$SHARED_DIR\/\.env"/);
  assert.match(installer, /RELEASES_DIR=.*releases/);
  assert.match(installer, /CURRENT_LINK=.*current/);
  assert.match(installer, /stage_release/);
  assert.match(installer, /mv -Tf .*CURRENT_LINK/);
  assert.match(installer, /appgog-update-helper\.service/);
  assert.match(installer, /case "\$existing" in[\s\S]*"\$INSTALL_ROOT"\/\*/);
  assert.doesNotMatch(installer.split('install_host_security_agent() {')[0], /ProtectSystem=strict/);
  assert.match(installer, /install_host_security_agent\(\)[\s\S]*install-host-security\.sh/);
  const hostInstaller=text(join(root, 'scripts/install-host-security.sh'));
  assert.match(hostInstaller, /ProtectSystem=strict/);
  assert.match(hostInstaller, /install -o root -g root -m 0700/);
  assert.match(hostInstaller, /ExecStart=\$python_bin -I \$AGENT_FILE/);
  assert.match(installer, /\/usr\/local\/bin\/appgog/);
  assert.match(installer, /preflight_network/);
  assert.match(installer, /DNS A 记录/);
  assert.match(installer, /Caddy 自动申请并续期 HTTPS/);
  assert.match(installer, /wait_public_https/);
  assert.match(installer, /validate_project_contract\(\)/);
  assert.match(installer, /compose\.license\.yaml/);
  assert.match(installer, /compose\.build\.yaml/);
  assert.match(installer, /scripts\/lib\/deployment-role\.sh/);
});

test('split role menu restricts authorization-only operations and keeps business pairing available', () => {
  const manager = text(scripts.manager);
  const docker = text(scripts.docker);
  const connector = text(join(root, 'scripts/business-connect.sh'));
  const splitSmoke = text(join(root, 'scripts/docker/verify-split.sh'));
  assert.match(manager, /APPGOG_BUSINESS_PAIRED/);
  assert.match(manager, /business_pair_export\(\)/);
  assert.match(manager, /business_pair_import\(\)/);
  assert.match(manager, /业务中心跨机配对/);
  assert.match(manager, /打包机没有授权管理员凭证/);
  assert.match(manager, /打包机不持有授权控制中心/);
  assert.match(docker, /独立打包机没有管理员凭证/);
  assert.match(connector, /needs_rollback=true[\s\S]*mv "\$tmp\/new-env" "\$envfile"/);
  assert.match(splitSmoke, /business\.status !== 503/);
  assert.match(splitSmoke, /ed25519-private\.pem/);
});

test('deployment role library selects one immutable compose contract and management scripts reuse it', () => {
  const roleLibrary = text(scripts.deploymentRoleLibrary);
  assert.match(roleLibrary, /appgog_deployment_role\(\)/);
  assert.match(roleLibrary, /APPGOG_DEPLOYMENT_ROLE/);
  assert.match(roleLibrary, /all\|license\|build/);
  assert.match(roleLibrary, /compose\.yaml/);
  assert.match(roleLibrary, /compose\.license\.yaml/);
  assert.match(roleLibrary, /compose\.build\.yaml/);
  assert.match(roleLibrary, /部署角色无效/);
  assert.match(roleLibrary, /角色 Compose 文件不存在/);
  assert.doesNotMatch(roleLibrary, /(^|\n)\s*\.\s+["']?\$?[^\n]*\.env/);

  for (const script of [scripts.docker, scripts.manager, scripts.migration, scripts.securityConnect, scripts.securityDoctor]) {
    const contents = text(script);
    assert.match(contents, /scripts\/lib\/deployment-role\.sh/);
    assert.match(contents, /appgog_compose_file/);
    assert.doesNotMatch(contents, /-f\s+(?:"\$ROOT_DIR\/)?compose\.yaml/);
  }

  const migration = text(scripts.migration);
  assert.match(migration, /appgog_require_control_role/);
  const splitSmoke = text(scripts.verifySplit);
  assert.match(splitSmoke, /compose\.license\.yaml/);
  assert.match(splitSmoke, /compose\.build\.yaml/);
});

test('deployment role resolver defaults legacy installs to all and fails closed for invalid or missing contracts', t => {
  if (process.platform === 'win32') {
    t.skip('Windows Node test environment does not guarantee a POSIX shell on PATH');
    return;
  }
  accessSync('/bin/sh', constants.X_OK);
  const fixture = mkdtempSync(join(tmpdir(), 'appgog-role-'));
  t.after(() => rmSync(fixture, { recursive: true, force: true }));
  for (const name of ['compose.yaml', 'compose.license.yaml', 'compose.build.yaml']) writeFileSync(join(fixture, name), 'services: {}\n');
  const envPath = join(fixture, '.env');
  const command = `set -e; . "${scripts.deploymentRoleLibrary}"; role=$(appgog_deployment_role "${envPath}"); file=$(appgog_compose_file "${fixture}" "${envPath}"); printf '%s|%s\\n' "$role" "$file"`;

  writeFileSync(envPath, 'AUTH_DOMAIN=example.test\n');
  let result = spawnSync('/bin/sh', ['-c', command], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), `all|${join(fixture, 'compose.yaml')}`);

  writeFileSync(envPath, 'APPGOG_DEPLOYMENT_ROLE=license\n');
  result = spawnSync('/bin/sh', ['-c', command], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), `license|${join(fixture, 'compose.license.yaml')}`);

  writeFileSync(envPath, 'APPGOG_DEPLOYMENT_ROLE=attacker\n');
  result = spawnSync('/bin/sh', ['-c', command], { encoding: 'utf8' });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /部署角色无效/);

  writeFileSync(envPath, 'APPGOG_DEPLOYMENT_ROLE=build\n');
  rmSync(join(fixture, 'compose.build.yaml'));
  result = spawnSync('/bin/sh', ['-c', command], { encoding: 'utf8' });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /角色 Compose 文件不存在/);
});
test('stable bootstrap downloads, verifies, installs, upgrades, and rejects downgrade', () => {
  const bootstrap = text(scripts.bootstrap);
  assert.match(bootstrap, /releases\/latest\/download/);
  assert.match(bootstrap, /release-manifest\.json\.sig/);
  assert.match(bootstrap, /openssl pkeyutl -verify/);
  assert.match(bootstrap, /run_name/);
  assert.match(bootstrap, /run_sha256/);
  assert.match(bootstrap, /sha256sum -c/);
  assert.match(bootstrap, /ghfast\.top/);
  assert.match(bootstrap, /gh-proxy\.com/);
  assert.match(bootstrap, /running_image_version/);
  assert.match(bootstrap, /docker cp .*\/app\/package\.json/);
  assert.match(bootstrap, /State\.Health\.Status/);
  assert.match(bootstrap, /源码与运行镜像一致/);
  assert.match(bootstrap, /自动修复并重新部署/);
  assert.match(bootstrap, /拒绝自动降级/);
  assert.match(bootstrap, /sh "\$WORK_DIR\/installer\.run" "\$@"/);
});

test('existing installations bypass the fresh-install DNS ownership gate during upgrades', () => {
  const installer = text(scripts.installer);
  const start = installer.indexOf('preflight_network() {');
  const end = installer.indexOf('\n}\n\nprompt_domain()', start);
  assert.ok(start >= 0 && end > start, '无法定位安装器网络预检函数');
  const preflight = installer.slice(start, end);
  assert.match(preflight, /if \[ "\$UPGRADE_MODE" = true \]; then/);
  assert.match(preflight, /保留现有域名配置，跳过首装 DNS 指向强制校验/);
  assert.match(preflight, /else[\s\S]*域名 \$domain 未指向本机公网地址 \$public_ip/);
  assert.match(preflight, /ufw allow 80\/tcp/);
});

test('management menu exposes safe lifecycle, logs, configuration, backup, restore, and diagnostics', () => {
  const manager = text(scripts.manager);
  for (const command of ['install', 'status', 'start', 'stop', 'restart', 'logs', 'config', 'services', 'credentials', 'update', 'backup', 'restore', 'doctor', 'diagnostics', 'repair', 'repair-source', 'uninstall', 'cleanup']) {
    assert.ok(manager.includes(command), `管理脚本缺少 ${command}`);
  }
  assert.match(manager, /确认保存配置/);
  assert.match(manager, /backups\/env-/);
  assert.match(manager, /危险操作会再次要求确认/);
  assert.match(manager, /operations\.log/);
  assert.match(manager, /配置差异/);
  assert.match(manager, /最近备份/);
  assert.match(manager, /更新状态/);
  assert.match(manager, /Cloudflare API Token/);
  assert.match(manager, /LICENSE_SERVICE_ENABLED/);
  assert.match(manager, /卸载系统（保留数据）/);
  assert.match(manager, /run_signed_installer/);
  assert.match(manager, /rm -rf "\$INSTALL_ROOT\/releases"/);
  assert.match(manager, /安全更新最新版本/);
  assert.doesNotMatch(manager, /appgog rollback|回滚最近一次更新/);
  assert.match(manager, /migration-rollback-export/);
  assert.match(manager, /scripts\/lib\/manager-migration\.sh/);
  assert.match(text(scripts.managerMigrationLibrary), /rollback-inbox/);
  assert.match(manager, /migration-rollback-import/);
  assert.doesNotMatch(manager, /rm -f "\$fence"/);
});

test('online update helper accepts signed lifecycle actions and bounded migration actions', () => {
  const helper = text(scripts.updateHelper);
  assert.match(helper, /check-update\)/);
  assert.match(helper, /install-version\)/);
  assert.match(helper, /repair-current\)/);
  assert.match(helper, /transfer-source\|import-target\)/);
  assert.match(helper, /scripts\/migration\.sh/);
  assert.match(helper, /openssl pkeyutl -verify/);
  assert.match(helper, /install-docker\.sh/);
  assert.match(helper, /chmod 770 "\$CONTROL_DIR" "\$REQUEST_DIR"/);
  assert.match(helper, /--healthcheck/);
  assert.match(helper, /schema:2/);
  assert.match(helper, /last_successful_latest_version/);
  assert.match(helper, /check_status/);
  assert.match(helper, /checked_at/);
  assert.match(helper, /signed-release/);
  assert.match(helper, /latest_version:\(if \$latest == "__preserve__"[\s\S]*elif \$latest == "" then null else \$latest end\)/);
  assert.doesNotMatch(helper, /latest_version:\(\$latest\|select\(length>0\)\)/);
  assert.match(helper, /exec "\$CURRENT_LINK\/scripts\/update-helper\.sh" --daemon/);
  assert.ok(!helper.includes('eval '));

  const migration = text(scripts.migration);
  assert.match(migration, /source-fenced\.json/);
  assert.match(migration, /source_deployment_id/);
  assert.match(migration, /rollback-export/);
  assert.match(migration, /rollback-inbox/);
  assert.match(migration, /prepare-rollback-export/);
  assert.match(migration, /activate-source-rollback/);
  assert.match(migration, /安全回滚输入只能来自固定 rollback-inbox 目录/);
  assert.match(migration, /bundle_sha256/);
  assert.match(migration, /APPGOG_RESTORE_NO_START=true/);
  assert.match(migration, /api\/v1\/control-migrations\/handshake/);
  assert.match(migration, /APPGOG_BACKUP_LEAVE_STOPPED=true/);
  assert.match(migration, /APPGOG_RESTORE_NO_START=true/);
  assert.match(migration, /sha256sum/);
  assert.match(migration, /split -b 64m/);
  assert.match(migration, /bundle\/chunks\/\$chunk_number/);
  assert.match(migration, /bundle\/complete/);
  assert.doesNotMatch(migration, /eval |docker compose down -v/);
  assert.doesNotMatch(migration, /down -v/);

  const installer = text(scripts.installer);
  assert.match(installer, /update-helper-startup-/);
  assert.match(installer, /业务系统已经健康运行，但在线更新助手尚未就绪/);
  assert.doesNotMatch(installer, /fail '在线更新助手启动失败/);
});

test('online update helper writes valid readiness JSON before a latest version exists', async (t) => {
  if (process.platform === 'win32') {
    t.skip('Windows Node test environment does not guarantee POSIX sh and jq');
    return;
  }
  accessSync('/bin/sh', constants.X_OK);
  if (spawnSync('jq', ['--version'], { stdio: 'ignore' }).status !== 0) {
    t.skip('jq is required for the real update-helper readiness regression test');
    return;
  }

  const installRoot = mkdtempSync(join(tmpdir(), 'appgog-update-helper-'));
  t.after(() => rmSync(installRoot, { recursive: true, force: true }));
  mkdirSync(join(installRoot, 'current'), { recursive: true });
  mkdirSync(join(installRoot, 'current', 'scripts', 'lib'), { recursive: true });
  writeFileSync(join(installRoot, 'current', 'package.json'), `${JSON.stringify({ version: projectVersion }, null, 2)}\n`);
  copyFileSync(scripts.signedUpdateLibrary, join(installRoot, 'current', 'scripts', 'lib', 'signed-update.sh'));
  copyFileSync(scripts.releaseDownloadLibrary, join(installRoot, 'current', 'scripts', 'lib', 'release-download.sh'));

  const child = spawn('/bin/sh', [scripts.updateHelper, '--daemon', installRoot], { stdio: 'ignore' });
  t.after(() => { if (child.exitCode === null) child.kill('SIGTERM'); });

  const statusPath = join(installRoot, 'shared', 'update-control', 'status.json');
  let status = null;
  for (let attempt = 0; attempt < 40; attempt += 1) {
    try { status = JSON.parse(readFileSync(statusPath, 'utf8')); break; } catch { /* wait for atomic write */ }
    await new Promise((resolveWait) => setTimeout(resolveWait, 50));
  }

  assert.ok(status, '更新助手必须在启动后生成非空、有效的 JSON 状态文件');
  assert.equal(status.schema, 2);
  assert.equal(status.state, 'idle');
  assert.equal(status.current_version, projectVersion);
  assert.equal(status.latest_version, null);
  assert.equal(status.check_status, 'unchecked');
  assert.equal(status.checked_at, null);
  assert.equal(status.install_root, installRoot);

  const health = spawnSync('/bin/sh', [scripts.updateHelper, '--healthcheck', installRoot], { encoding: 'utf8' });
  assert.equal(health.status, 0, health.stderr || health.stdout);
});

test('Docker operations keep destructive volume removal out of the supported workflow', () => {
  const docker = text(scripts.docker);
  assert.match(docker, /install\|update\)/);
  assert.match(docker, /doctor\(\)/);
  assert.match(docker, /logs\(\)/);
  assert.match(docker, /appgog-platform:rollback/);
  assert.doesNotMatch(docker, /^\s*rollback\)/m);
  assert.match(docker, /diagnostics\(\)/);
  assert.match(docker, /repair_permissions\(\)/);
  assert.match(docker, /prepare_update_control\(\)/);
  assert.match(docker, /build_with_retry\(\)/);
  assert.match(docker, /APPGOG_BUILD_ATTEMPTS/);
  assert.match(docker, /基础镜像仓库、DNS 或 TLS 网络不可用/);
  assert.match(docker, /capture_startup_failure\(\)/);
  assert.match(docker, /startup-failure-/);
  assert.match(docker, /新版本首次启动未通过健康检查，自动重试一次/);
  assert.match(docker, /APPGOG_COMPOSE_WAIT_TIMEOUT/);
  assert.match(docker, /APPGOG_RESTORE_NO_START/);
  assert.match(docker, /mkdir -p \/app\/var\/update-control\/requests/);
  assert.match(docker, /chown -R 1000:1000[\s\S]*\/app\/var\/update-control/);
  assert.match(docker, /chmod 770 \/app\/var\/update-control \/app\/var\/update-control\/requests/);
  assert.match(docker, /docker image prune -f/);
  assert.match(docker, /compose stop appgog/);
  assert.match(docker, /backup-integrity\.py" encrypt/);
  assert.match(docker, /--producer docker compose/);
  assert.match(docker, /\.backup-key/);
  assert.match(docker, /DNS A 记录可解析/);
  assert.match(docker, /TLS 证书到期/);
  assert.match(docker, /Ed25519 签名密钥完整/);
  assert.match(docker, /--consumer env APPGOG_RESTORE_STREAM_INTERNAL=true/);
  assert.match(docker, /备份认证、解密或恢复失败/);
  assert.ok(!docker.includes('openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass "$BACKUP_KEY_FILE" -in "$archive" \\\n          | compose'));
  assert.ok(!docker.includes('down -v'));
  assert.ok(!docker.includes('volume rm'));
});

test('management shell scripts pass POSIX syntax validation when sh is available', t => {
  if (process.platform === 'win32') {
    t.skip('Windows Node test environment does not guarantee a POSIX shell on PATH');
    return;
  }
  accessSync('/bin/sh', constants.X_OK);
  for (const script of Object.values(scripts)) {
    const result = spawnSync('/bin/sh', ['-n', script], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  }
});
