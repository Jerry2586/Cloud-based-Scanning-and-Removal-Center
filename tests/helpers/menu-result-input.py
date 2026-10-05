"""Real /dev/tty result acknowledgement; only on disposable root Linux runners."""
import errno
import os
import pty
import select
import signal
import subprocess
import time

if os.geteuid() != 0 or os.environ.get('IRONCURTAIN_ACCEPT_DISPOSABLE_RUNNER') != '1':
    raise SystemExit('Requires disposable root CI')

PROMPT = '请输入菜单编号（0 退出）：'.encode()
PAUSE = '按回车返回管理菜单（Ctrl+C 退出）：'.encode()
HEADER = 'Linux 管理菜单'.encode()


class Menu:
    def __init__(self, entry):
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.environ['NO_COLOR'] = '1'
            os.environ['TERM'] = 'xterm'
            os.execv('/usr/local/bin/' + entry, [entry])
        self.output = b''
        self.closed = False
        self.deadline = time.monotonic() + 120

    def read(self, timeout):
        if self.closed:
            return
        readable, _, _ = select.select([self.fd], [], [], timeout)
        if readable:
            try:
                data = os.read(self.fd, 65536)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                data = b''
            if not data:
                self.closed = True
            self.output += data

    def until(self, value, count=1):
        while self.output.count(value) < count:
            if self.closed or time.monotonic() > self.deadline:
                raise AssertionError('Missing terminal output: ' + value.decode())
            self.read(0.2)

    def send(self, data):
        os.write(self.fd, data)

    def stays(self, prompts, headers):
        # Explicitly withhold input: queued newlines cannot fake this regression test.
        end = time.monotonic() + 1
        while time.monotonic() < end:
            self.read(0.1)
        assert not self.closed, 'Menu exited before acknowledgement'
        assert self.output.count(PROMPT) == prompts, 'Menu returned without acknowledgement'
        assert self.output.count(HEADER) == headers, 'Menu redrew the home page too early'

    def finish(self):
        while not self.closed:
            if time.monotonic() > self.deadline:
                raise TimeoutError('Menu did not exit')
            self.read(0.2)
        _, status = os.waitpid(self.pid, 0)
        self.pid = None
        assert os.waitstatus_to_exitcode(status) == 0, 'Menu exited unsuccessfully'

    def close(self):
        os.close(self.fd)
        if self.pid is not None:
            os.kill(self.pid, signal.SIGKILL)
            os.waitpid(self.pid, 0)
            self.pid = None


def result_case(entry, number, expected, eof=False):
    menu = Menu(entry)
    try:
        menu.until(PROMPT)
        menu.send(number)
        menu.until(PAUSE)
        assert expected in menu.output, 'Selected action did not run'
        headers = 2 if number.strip() == b'1' else 1
        menu.stays(1, headers)
        if eof:
            menu.send(b'\x04')
        else:
            menu.send(b'\n')
            menu.until(PROMPT, 2)
            assert menu.output.count(HEADER) == headers + 1
            menu.send(b'0\n')
        menu.finish()
    finally:
        menu.close()


def main():
    for entry in ('tiemu', 'xuanwu'):
        # status includes a fresh header; allow leading/trailing menu-only whitespace.
        result_case(entry, b' \t1 \r', '运行状态：'.encode())
        menu = Menu(entry)
        try:
            menu.until(PROMPT)
            hidden = b'28\n' if entry == 'tiemu' else b'12\n'
            for count, invalid in enumerate((b'\n', b'999\n', b'1junk\n', hidden), 2):
                menu.send(invalid)
                menu.until(PROMPT, count)
                assert menu.output.count(HEADER) == 1, 'Invalid input refreshed the home page'
                assert PAUSE not in menu.output, 'Invalid input executed an action'
            assert '请选择有效菜单项'.encode() in menu.output
            assert '请选择当前角色显示的有效菜单项'.encode() in menu.output
            menu.send(b'0\n')
            menu.finish()
        finally:
            menu.close()
        # EOF at the initial prompt and at result acknowledgement must exit cleanly.
        menu = Menu(entry)
        try:
            menu.until(PROMPT)
            menu.send(b'\x04')
            menu.finish()
        finally:
            menu.close()
        result_case(entry, b'1\n', '运行状态：'.encode(), eof=True)
        command = subprocess.run(['/usr/local/bin/' + entry, 'status'], capture_output=True, timeout=60)
        assert command.returncode == 0 and PAUSE not in command.stdout + command.stderr
        print(entry + ': status stays, acknowledgement returns once, invalid input and EOF pass')

    result_case('xuanwu', b'11\n', b'/etc/ironcurtain/cloud/credentials/reader.p12')
    # Installed here without pairing: exercise a real failed operation as well as success.
    result_case('tiemu', b'11\n', '操作未完成；现有状态请运行诊断核对。'.encode())
    command = subprocess.run(['/usr/local/bin/xuanwu', 'reader'], capture_output=True, timeout=60)
    assert command.returncode == 0 and PAUSE not in command.stdout + command.stderr
    assert b'/etc/ironcurtain/cloud/credentials/reader.p12' in command.stdout
    print('Certificate guidance and failed handshake stay; direct CLI remains noninteractive')


if __name__ == '__main__':
    main()
