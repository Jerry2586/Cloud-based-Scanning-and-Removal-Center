#!/usr/bin/env python3
"""Offline signed source repair; never runs package scripts or changes business data."""
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

MAX_ARCHIVE = 128 * 1024 * 1024
MAX_EXPANDED = 256 * 1024 * 1024
ROOT_FILES = {'.env.example', '.env.docker.example', '.gitignore', '.dockerignore', 'AGENTS.md',
              'Caddyfile', 'Caddyfile.license', 'Caddyfile.build', 'compose.yaml', 'compose.license.yaml',
              'compose.build.yaml', 'Dockerfile', 'package.json', 'pnpm-lock.yaml', 'README.md',
              'release-contract.json', 'install-docker.sh'}
DIRECTORIES = {'apps', 'packages', 'scripts', 'docs'}


def verified_bundle(control, directory):
    directory = control.trusted(directory, directory=True)
    manifest_path = directory / 'release-manifest.json'
    signature_path = directory / 'release-manifest.json.sig'
    manifest_bytes = control.AGENT.read_regular(control.trusted(manifest_path), 16384)
    signature = control.AGENT.read_regular(control.trusted(signature_path), 128)
    if len(signature) != 64:
        raise ValueError('invalid Ed25519 signature length')
    # Verify stable copies of the exact bounded bytes, not paths that could change during verification.
    with tempfile.TemporaryDirectory(dir=control.STATE, prefix='.verify-') as temporary:
        manifest_copy = Path(temporary) / 'manifest'
        signature_copy = Path(temporary) / 'signature'
        manifest_copy.write_bytes(manifest_bytes)
        signature_copy.write_bytes(signature)
        result = subprocess.run(['/usr/bin/openssl', 'pkeyutl', '-verify', '-pubin', '-inkey',
                                 str(control.DIRECTORY / 'release-public.pem'), '-rawin', '-in',
                                 str(manifest_copy), '-sigfile', str(signature_copy)],
                                capture_output=True, timeout=10, check=False)
        if result.returncode != 0:
            raise ValueError('release signature rejected by independently pinned key')
    manifest = json.loads(manifest_bytes)
    version = manifest.get('version', '')
    name = 'APPGOG-Packaging-Licensing-System-' + version + '.zip'
    if manifest.get('schema') != 2 or manifest.get('product') != 'appgog' or \
            not re.fullmatch(r'\d+\.\d+\.\d+', version) or manifest.get('zip_name') != name or \
            not re.fullmatch(r'[a-f0-9]{64}', manifest.get('zip_sha256', '')):
        raise ValueError('invalid signed release contract')
    archive = control.AGENT.read_regular(control.trusted(directory / name), MAX_ARCHIVE)
    if hashlib.sha256(archive).hexdigest() != manifest['zip_sha256']:
        raise ValueError('signed release SHA-256 mismatch')
    return manifest, manifest_bytes, signature, archive


def validated_entries(archive, version):
    prefix = 'APPGOG-Packaging-Licensing-System-' + version
    entries, seen, expanded = [], set(), 0
    with zipfile.ZipFile(io.BytesIO(archive)) as package:
        inventory = package.infolist()
        if len(inventory) > 8192:
            raise ValueError('release entry budget exceeded')
        for member in inventory:
            name = member.orig_filename
            parts = name.rstrip('/').split('/')
            if '\\' in name or '\x00' in name or any(x in {'', '.', '..'} for x in parts) or parts[0] != prefix:
                raise ValueError('unsafe ZIP path')
            if len(parts) == 1:
                if not member.is_dir():
                    raise ValueError('invalid release root')
                continue
            relative = PurePosixPath(*parts[1:])
            if relative.parts[0] not in DIRECTORIES and str(relative) not in ROOT_FILES:
                raise ValueError('release contains an unexpected root entry')
            if str(relative) in seen:
                raise ValueError('duplicate ZIP entry')
            seen.add(str(relative))
            mode = member.external_attr >> 16
            kind = stat.S_IFMT(mode)
            if kind not in {0, stat.S_IFREG, stat.S_IFDIR} or member.flag_bits & 1:
                raise ValueError('symlink, special or encrypted release entry')
            if kind == stat.S_IFDIR and not member.is_dir():
                raise ValueError('inconsistent ZIP directory type')
            if member.is_dir():
                if kind not in {0, stat.S_IFDIR}:
                    raise ValueError('inconsistent ZIP member type')
                continue
            expanded += member.file_size
            if member.file_size > 8 * 1024 * 1024 or expanded > MAX_EXPANDED:
                raise ValueError('release expansion budget exceeded')
            data = package.read(member)
            if len(data) != member.file_size:
                raise ValueError('invalid release member size')
            entries.append((relative, data))
    files = {str(relative): data for relative, data in entries}
    if any(name not in files for name in ('package.json', 'compose.yaml', 'compose.license.yaml',
                                         'compose.build.yaml', 'scripts/host-security-agent.py')):
        raise ValueError('incomplete source release')
    if json.loads(files['package.json']).get('version') != version:
        raise ValueError('signed archive version mismatch')
    return entries


def write_file(path, data):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(0o600)


def cache(control, directory):
    manifest, manifest_bytes, signature, archive = verified_bundle(control, directory)
    validated_entries(archive, manifest['version'])
    parent = control.STATE / 'trusted-releases'
    control.AGENT.private_directory(parent)
    destination = parent / manifest['version']
    if destination.exists() or destination.is_symlink():
        existing = verified_bundle(control, destination)
        if existing[1:] != (manifest_bytes, signature, archive):
            raise ValueError('cached version differs; refuse replacement')
        return {'state': 'cached', 'version': manifest['version']}
    temporary = Path(tempfile.mkdtemp(dir=parent, prefix='.cache-'))
    try:
        write_file(temporary / 'release-manifest.json', manifest_bytes)
        write_file(temporary / 'release-manifest.json.sig', signature)
        write_file(temporary / manifest['zip_name'], archive)
        os.rename(temporary, destination)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    return {'state': 'cached', 'version': manifest['version'], 'trust': 'pinned-Ed25519-and-SHA256'}


def repair(control, version):
    if version != control.VERSION:
        raise ValueError('repair only the independently recorded installed version; no implicit upgrade/downgrade')
    item = control.incident()
    if not item or item['state'] == 'released':
        raise ValueError('contain the service before source repair')
    owned = control.target()
    if owned['Id'] != item['container_id'] or owned.get('State', {}).get('Running') is not False:
        raise ValueError('expected original stopped container')
    manifest, manifest_bytes, _, archive = verified_bundle(control, control.STATE / 'trusted-releases' / version)
    if manifest['version'] != version:
        raise ValueError('cached version mismatch')
    entries = validated_entries(archive, version)
    current = control.ROOT / 'current'
    if not current.is_symlink():
        raise ValueError('independent repair requires the managed releases/current layout')
    previous = control.AGENT.release_root()
    releases = control.trusted(control.ROOT / 'releases', directory=True)
    temporary = Path(tempfile.mkdtemp(dir=releases, prefix=version + '-repaired-'))
    activated = False
    previous_baseline = control.AGENT.read_state(control.AGENT.BASELINE)
    link = control.ROOT / ('.current-repair-' + temporary.name)
    try:
        for relative, data in entries:
            write_file(temporary / str(relative), data)
        # The shared business configuration is retained; it is neither included in the signed source nor repaired.
        shared_env = control.trusted(control.ROOT / 'shared' / '.env')
        os.symlink(shared_env, temporary / '.env')
        os.symlink(temporary, link)
        os.replace(link, current)
        activated = True
        control.AGENT.write_baseline()
        item['source_repaired'] = True
        item['source_manifest_sha256'] = hashlib.sha256(manifest_bytes).hexdigest()
        item['previous_release'] = str(previous)
        item['repaired_release'] = str(temporary)
        control.save(item, 'source_repaired')
    except Exception:
        if activated:
            os.symlink(previous, link)
            os.replace(link, current)
            control.AGENT.atomic_json(control.AGENT.BASELINE, json.loads(previous_baseline))
        raise
    finally:
        if link.is_symlink():
            link.unlink()
        # Preserve staged files and original suspect release as evidence; never delete business or program evidence.
    return {'state': 'source_repaired', 'version': version, 'service': 'still-contained',
            'scope': 'signed program files only; image and writable business data require separate review'}


def execute(control, args):
    if args[0] == 'cache-release':
        return cache(control, args[1])
    return repair(control, args[1])
