#!/usr/bin/env python3
"""Authenticated independent-role backups. No business files or remote execution."""
import argparse
import hashlib
import hmac
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time

MAGIC = b"IRONCURTAIN-RECOVERY-V1\n"
MAX_BYTES = 1024 * 1024 * 1024
MAX_FILE = 128 * 1024 * 1024
MAX_MEMBERS = 16384
INSTALL_FIELDS = ("schema", "role", "host", "bind", "image", "version")


def private_open(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
        os.close(fd)
        raise ValueError("输入必须是 root:0600、无链接的普通文件")
    return os.fdopen(fd, "rb")


def read_key(path):
    with private_open(path) as stream:
        key = stream.read(129)
    if len(key) != 64:
        raise ValueError("恢复密钥必须为 64 字节，不能使用登录密码")
    return key


def binding(install, role, machine):
    with private_open(install) as stream:
        record = json.loads(stream.read(16385))
    if record.get("schema") != 1 or record.get("role") != role:
        raise ValueError("安装身份无效")
    machine_id = Path(machine).read_text().strip()
    if len(machine_id) != 32 or any(c not in "0123456789abcdef" for c in machine_id):
        raise ValueError("宿主 machine-id 无效")
    return {"schema": 1, "product": "ironcurtain-recovery", "role": role,
            "machine": hashlib.sha256(("ironcurtain:" + machine_id).encode()).hexdigest(),
            "install": {key: record[key] for key in INSTALL_FIELDS}}


def check_member(member, names, total):
    name = member.name
    parts = PurePosixPath(name).parts
    if not parts or name != "/".join(parts) or any(p in (".", "..") for p in parts) or parts[0] not in ("conf", "data"):
        raise ValueError("备份路径越界")
    if name in names or any("/".join(parts[:i]) in names and names["/".join(parts[:i])] != "dir" for i in range(1, len(parts))):
        raise ValueError("重复路径或父路径不是目录")
    if any(existing.startswith(name + "/") for existing in names) and not member.isdir():
        raise ValueError("文件与子目录冲突")
    if not member.isdir() and not member.isreg() or member.issparse():
        raise ValueError("备份不接受符号链接、硬链接、设备、FIFO 或稀疏文件")
    if member.uid not in (0, 10001) or member.gid not in (0, 10001) or member.mode & 0o7022:
        raise ValueError("备份所有者或权限无效")
    if member.uid == 10001 and (len(parts) < 2 or parts[:2] not in (("conf", "runtime"), ("data", "runtime"))):
        raise ValueError("非 root 文件越出运行时目录")
    if member.size < 0 or member.size > MAX_FILE or (member.isdir() and member.size):
        raise ValueError("备份单文件超过预算")
    total += member.size
    if total > MAX_BYTES or len(names) >= MAX_MEMBERS:
        raise ValueError("备份超过容量预算")
    names[name] = "dir" if member.isdir() else "file"
    return total


def create_tar(snapshot, metadata, target):
    names, total = {}, 0
    with tarfile.open(target, "w:gz", format=tarfile.PAX_FORMAT) as dest:
        content = json.dumps({**metadata, "created_at": int(time.time())}, sort_keys=True).encode()
        entry = tarfile.TarInfo("metadata.json")
        entry.mode = 0o600
        entry.size = len(content)
        dest.addfile(entry, io.BytesIO(content))
        for prefix, source in (("conf", "config.tar"), ("data", "data.tar")):
            with private_open(str(Path(snapshot) / source)) as source_file, tarfile.open(fileobj=source_file, mode="r:") as archive:
                for member in archive:
                    original = member.name
                    relative = original[2:] if original.startswith("./") else original
                    if original in (".", "./"):
                        relative = ""
                    if prefix == "conf" and relative.split("/", 1)[0] == "exports":
                        continue  # exported pairing packages are not live recovery identities
                    if prefix == "conf" and relative.split("/", 1)[0].startswith(".admin."):
                        continue
                    member.name = prefix + ("/" + relative if relative else "")
                    total = check_member(member, names, total)
                    member.pax_headers = {}
                    dest.addfile(member, archive.extractfile(member) if member.isreg() else None)


def inspect_tar(path, expected):
    names, total, entries = {}, 0, []
    with tarfile.open(path, "r:gz") as archive:
        first = archive.next()
        if first is None or first.name != "metadata.json" or not first.isreg() or first.size > 16384:
            raise ValueError("恢复包缺少有效清单")
        metadata = json.loads(archive.extractfile(first).read())
        if any(metadata.get(key) != value for key, value in expected.items()):
            raise ValueError("恢复包角色、机器或程序版本不匹配；禁止克隆身份或跨版本盲恢复")
        for member in archive:
            # Iteration includes cached metadata entry; it is handled exactly once above.
            if member is first:
                continue
            total = check_member(member, names, total)
            if member.isreg():
                with archive.extractfile(member) as source:
                    remaining = member.size
                    while remaining:
                        chunk = source.read(min(remaining, 1024 * 1024))
                        if not chunk:
                            raise ValueError("归档文件不完整")
                        remaining -= len(chunk)
            entries.append(member)
    if names.get("conf") != "dir" or names.get("data") != "dir":
        raise ValueError("恢复包缺少角色目录")
    return metadata, entries


def crypt(key, source, target, decrypt=False):
    password = hmac.digest(key, b"ironcurtain-recovery/encryption/v1", "sha256").hex().encode() + b"\n"
    command = ["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "200000", "-md", "sha256", "-salt",
               "-in", str(source), "-out", str(target), "-pass", "stdin"]
    if decrypt:
        command.append("-d")
    result = subprocess.run(command, input=password, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=180)
    if result.returncode:
        raise ValueError("恢复包加密或解密失败")
    os.chmod(target, 0o600)


def authenticator(key):
    return hmac.new(hmac.digest(key, b"ironcurtain-recovery/authentication/v1", "sha256"), MAGIC, "sha256")


def seal(cipher, output, key):
    mac = authenticator(key)
    with open(cipher, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            mac.update(block)
    with open(output, "xb") as dest, open(cipher, "rb") as stream:
        os.chmod(output, 0o600)
        dest.write(MAGIC + mac.digest())
        shutil.copyfileobj(stream, dest, 1024 * 1024)
        dest.flush()
        os.fsync(dest.fileno())


def unseal(backup, cipher, key):
    mac, total = authenticator(key), 0
    with private_open(backup) as source, open(cipher, "xb") as dest:
        if source.read(len(MAGIC)) != MAGIC:
            raise ValueError("恢复包格式无效")
        expected = source.read(32)
        for block in iter(lambda: source.read(1024 * 1024), b""):
            total += len(block)
            if total > MAX_BYTES + 16 * 1024 * 1024:
                raise ValueError("加密包超过容量预算")
            mac.update(block)
            dest.write(block)
    if not total or len(expected) != 32 or not hmac.compare_digest(mac.digest(), expected):
        raise ValueError("恢复包认证失败；拒绝解密与写入")


def extract(path, directory, entries):
    root = Path(directory)
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700 or any(root.iterdir()):
        raise ValueError("解包目标必须为 root:0700 空目录")
    # Every member was authenticated and validated before any extraction. Never use tar.extractall.
    with tarfile.open(path, "r:gz") as archive:
        mapping = {member.name: member for member in entries}
        dirs = []
        for member in archive:
            if member.name not in mapping:
                continue
            target = root.joinpath(*PurePosixPath(member.name).parts)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if member.isdir():
                target.mkdir(mode=0o700, exist_ok=True)
                dirs.append((target, member))
            else:
                with target.open("xb") as dest, archive.extractfile(member) as source:
                    shutil.copyfileobj(source, dest, 1024 * 1024)
                    dest.flush()
                    os.fsync(dest.fileno())
                os.chown(target, member.uid, member.gid)
                os.chmod(target, member.mode)
        for target, member in sorted(dirs, key=lambda item: len(item[0].parts), reverse=True):
            os.chown(target, member.uid, member.gid)
            os.chmod(target, member.mode)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("create", "verify", "extract"))
    for name in ("key", "install", "role", "machine"):
        parser.add_argument("--" + name, required=True)
    for name in ("snapshot", "backup", "output", "directory"):
        parser.add_argument("--" + name)
    args = parser.parse_args()
    if os.geteuid() != 0 or args.role not in ("local", "cloud"):
        raise ValueError("此操作仅供 Linux root 管理员使用")
    os.umask(0o077)
    key, expected = read_key(args.key), binding(args.install, args.role, args.machine)
    with tempfile.TemporaryDirectory(prefix="ironcurtain-recovery-") as work:
        plain, cipher = Path(work) / "archive.tar.gz", Path(work) / "cipher"
        if args.action == "create":
            if not args.snapshot or not args.output:
                raise ValueError("缺少快照或输出路径")
            create_tar(args.snapshot, expected, plain)
            inspect_tar(plain, expected)
            crypt(key, plain, cipher)
            seal(cipher, args.output, key)
            print(json.dumps({"state": "created", "role": args.role, "version": expected["install"]["version"]}))
        else:
            if not args.backup:
                raise ValueError("缺少恢复包")
            unseal(args.backup, cipher, key)
            crypt(key, cipher, plain, decrypt=True)
            metadata, entries = inspect_tar(plain, expected)
            if args.action == "extract":
                if not args.directory:
                    raise ValueError("缺少解包目标")
                extract(plain, args.directory, entries)
            print(json.dumps({"state": "verified", "role": args.role, "version": metadata["install"]["version"],
                              "created_at": metadata["created_at"], "entries": len(entries)}))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, tarfile.TarError, subprocess.SubprocessError) as error:
        print("恢复包操作失败：" + str(error), file=__import__("sys").stderr)
        raise SystemExit(1)
