"""Disposable CI only: exercise the real root menu's /dev/tty input."""
import errno, os, pty, select, signal, sys, time
if os.geteuid() != 0 or os.environ.get('IRONCURTAIN_ACCEPT_DISPOSABLE_RUNNER') != '1':
    raise SystemExit('Requires disposable root CI')
if len(sys.argv) != 2 or not sys.argv[1].startswith('/opt/ironcurtain-deployment-test.') or '\n' in sys.argv[1]:
    raise SystemExit('Invalid test release path')
pid, fd = pty.fork()
if pid == 0:
    os.execv('/usr/local/bin/xuanwu', ['xuanwu', 'release-import'])
end = time.monotonic() + 240
buffer = b''
sent = False
try:
    while True:
        if time.monotonic() >= end:
            raise TimeoutError('Real release import timed out')
        readable, _, _ = select.select([fd], [], [], 1)
        if not readable:
            continue
        try:
            chunk = os.read(fd, 65536)
        except OSError as error:
            if error.errno != errno.EIO:
                raise
            break
        if not chunk:
            break
        sys.stdout.buffer.write(chunk)
        sys.stdout.buffer.flush()
        buffer = (buffer + chunk)[-65536:]
        if not sent and '六个正式签名附件所在的绝对目录：'.encode() in buffer:
            os.write(fd, (sys.argv[1] + '\n').encode())
            sent = True
    _, status = os.waitpid(pid, 0)
    pid = None
    if not sent:
        raise RuntimeError('Root menu never requested the release directory')
    raise SystemExit(os.waitstatus_to_exitcode(status))
finally:
    os.close(fd)
    if pid is not None:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
