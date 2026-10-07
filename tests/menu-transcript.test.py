"""Reproduce changing runtime health without relaxing menu/NO_COLOR contracts."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('menu_transcript', Path(__file__).parent / 'helpers/menu-transcript.py')
menu = importlib.util.module_from_spec(spec)
spec.loader.exec_module(menu)

class TranscriptTest(unittest.TestCase):
    def fixture(self, healthy=True):
        expected = list(range(1, 12)) + [13, 14] + list(range(22, 31)) + [35, 36, 0]
        health = '正常（容器健康）' if healthy else '容器未通过健康检查，请运行环境诊断'
        return ('╔' + '═' * 58 + '╗\n' + '║' + ' ' * 58 + '║\n' +
                '╠' + '═' * 58 + '╣\n' + '╚' + '═' * 58 + '╝\n' +
                '安装目录：0.6.1\n运行状态：' + health + '\n登记节点：0 个\n' +
                '打开菜单：sudo xuanwu\n更新程序：sudo xuanwu update\n' +
                ''.join(f'{number:2}. 管理项目\n' for number in expected) +
                '玄武引擎 · 请输入菜单编号（0 退出）：')
    def check(self, colored=None, plain=None):
        menu.validate_pair('\x1b[1;34m' + (colored or self.fixture()) + '\x1b[0m', plain or self.fixture(), 'xuanwu')
    def test_real_health_can_change_between_terminal_samples(self):
        self.check(plain=self.fixture(False))
    def test_fixed_command_change_still_fails(self):
        with self.assertRaises(AssertionError):
            self.check(plain=self.fixture().replace('sudo xuanwu update', 'sudo wrong update'))
    def test_plain_terminal_escapes_still_fail(self):
        with self.assertRaises(AssertionError):
            self.check(plain='\x1b[0m' + self.fixture())
    def test_missing_health_still_fails(self):
        with self.assertRaises(AssertionError):
            self.check(colored=self.fixture().replace('运行状态：正常（容器健康）', '运行状态：未知伪状态'))
    def test_missing_menu_item_still_fails(self):
        with self.assertRaises(AssertionError):
            changed=self.fixture().replace('35. 管理项目\n', '')
            self.check(colored=changed, plain=changed)
    def test_frame_width_still_fails(self):
        with self.assertRaises(AssertionError):
            changed=self.fixture().replace('║' + ' ' * 58 + '║', '║' + ' ' * 57 + '║')
            self.check(colored=changed, plain=changed)

if __name__ == '__main__':
    unittest.main()
