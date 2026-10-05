#!/usr/bin/env bash
# Display-only helpers; action dispatch and trust boundaries stay in the manager.
IC_MENU_BLUE='' IC_MENU_GREEN='' IC_MENU_YELLOW='' IC_MENU_RED='' IC_MENU_RESET=''
if [[ -t 1 && ${TERM:-dumb} != dumb && ! -v NO_COLOR ]]; then
  IC_MENU_BLUE=$'\033[1;34m'
  IC_MENU_GREEN=$'\033[1;32m'
  IC_MENU_YELLOW=$'\033[1;33m'
  IC_MENU_RED=$'\033[1;31m'
  IC_MENU_RESET=$'\033[0m'
fi
ic_menu_clean() { LC_ALL=C tr -d '\000-\037\177'; }
ic_menu_row() {
  local label=${1:?} value=${2:-} color=${3:-}
  value=$(printf '%s' "$value" | ic_menu_clean)
  printf '%s：%s%s%s\n' "$label" "$color" "$value" "$IC_MENU_RESET"
}
ic_menu_header() {
  printf '%s' "$IC_MENU_BLUE"
  python3 - "$PRODUCT_NAME" "${1:?}" "${2:?}" <<'PY'
import sys, unicodedata
width = 58
def clean(value):
    return ''.join(c for c in value if not unicodedata.category(c).startswith('C'))
def fit(value):
    result, size = '', 0
    for char in clean(value):
        cell = 0 if unicodedata.combining(char) else 2 if unicodedata.east_asian_width(char) in ('W', 'F') else 1
        if size + cell > width:
            break
        result += char
        size += cell
    left = (width - size) // 2
    return ' ' * left + result + ' ' * (width - size - left)
print('╔' + '═' * width + '╗')
print('║' + fit(sys.argv[1] + ' 管理中心 · Linux 管理菜单') + '║')
print('╠' + '═' * width + '╣')
print('║' + fit('版本：' + sys.argv[2] + '    安装目录：' + sys.argv[3]) + '║')
print('╚' + '═' * width + '╝')
PY
  printf '%s' "$IC_MENU_RESET"
}
ic_menu_item() { printf '%2s. %s\n' "${1:?}" "${2:?}"; }
