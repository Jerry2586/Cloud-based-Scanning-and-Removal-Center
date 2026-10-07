"""Validate presentation independently of live Docker health transitions."""
import re
import sys
import unicodedata
from pathlib import Path

ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
HEALTH = re.compile(r'^运行状态：(正常（容器健康）|容器未通过健康检查，请运行环境诊断)$', re.M)
PROMPT = '请输入菜单编号（0 退出）'

def body(text):
    return text[text.index('╔'):text.index(PROMPT)]

def stable(text):
    value = body(text)
    assert len(HEALTH.findall(value)) == 1, 'Missing or invalid real health status'
    return HEALTH.sub('运行状态：<live>', value)

def validate_pair(raw, plain, entry):
    assert entry in ('tiemu', 'xuanwu'), 'Invalid role menu'
    assert '\x1b[1;34m' in raw, 'Color menu omitted its heading color'
    text = ANSI.sub('', raw)
    assert '\x1b' not in plain, 'NO_COLOR output contains terminal escapes'
    # The two PTYs query real state at different times. Preserve every other
    # character; Docker health convergence is checked separately by the gate.
    assert stable(text) == stable(plain), 'Color/plain layout or fixed data mismatch'
    lines = text.splitlines()
    items = [line for line in lines if re.match(r'^ *\d+\. ', line)]
    expected = (list(range(1, 28)) + [29, 31, 32, 33, 34, 35, 36, 37, 0]
                if entry == 'tiemu' else list(range(1, 12)) + [13, 14] + list(range(22, 31)) + [35, 36, 0])
    actual = [int(re.match(r'^ *(\d+)\.', line)[1]) for line in items]
    assert actual == expected, (actual, expected)
    assert all(len(re.findall(r'\d+\. ', line)) == 1 for line in items)
    assert all(symbol in text for symbol in ('╔', '╠', '╚'))
    assert '安装目录：' in text
    assert not re.search(r'"(?:engine|installed|updater|state)"\s*:', text)
    for line in lines:
        if line.startswith('║'):
            width = sum(0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in ('W', 'F') else 1 for c in line)
            assert width == 60, (width, line)
    if entry == 'tiemu':
        assert '病毒引擎：未就绪' in text and '玄武连接：尚未配对' in text
    else:
        assert '登记节点：0 个' in text

if __name__ == '__main__':
    path = Path(sys.argv[1])
    validate_pair(path.read_text(encoding='utf-8'),
                  path.with_name(path.name.replace('-menu.log', '-plain-menu.log')).read_text(encoding='utf-8'), sys.argv[2])
