# 铁幕安全 · 玄武引擎

独立 Linux 安全项目，统一源码、独立角色：**铁幕安全**部署在需要保护的服务器，**玄武引擎**部署在独立的安全服务器。每个角色运行一个 Docker 容器；铁幕额外安装一个固定权限的宿主扫描服务。可保护 APPGOG，也可配置其他网站和容器。

APPGOG 的授权、打包、账号、数据库和升级仍由其自己的项目负责。安全面板、检测逻辑、节点身份和安全更新在本仓库维护。

> 当前代码版本 **0.6.8**。**v0.6.0** 已正式发布并完成六附件独立回取验签，包含玄武持久化插件目录、策略修订、摘要分析任务、审计与云端工作台；**v0.6.1** 补齐正式包遗漏的域名管理入口并加强宿主控制服务验收；**v0.6.2** 增加铁幕固定周期检查、维护互锁、任务状态持久化和中断恢复。**v0.6.3** 增加铁幕与玄武 Linux 菜单修改面板密码，以及玄武用户中心；改密后旧会话失效，安装和重启保留新密码。**v0.6.4** 修复云端刷新打断阅读、节点诊断和审计状态，整理铁幕主机与容器页面并补齐域名/规则不可用反馈。**v0.6.5** 修复铁幕冷启动和刷新中的端云状态并发误报，多请求等待同一次认证检查；v0.6.5 已完成候选、预演、主分支、正式发布、六附件回取验签及双端生产升级。**v0.6.6** 增加玄武网页检查与安装签名正式版本，使用独立宿主更新控制器和固定任务；本版本的发布和部署结果以独立验收记录为准。**v0.6.7** 已完成签名正式发布、双端生产升级，修复首页覆盖结论与会话变化后的请求锁。**v0.6.8** 修复版本检查及更新排队时读取前一任务结果的问题；本版正式发布与部署证据分别记录。本轮真实接口、官方库扫描与 UI 验收及未达标项见 [R034 验收记录](docs/acceptance-r034.md)。任务与策略保存在 SQLite，重启后保留；缺少可信特征、主机代理或外部权限时保持未知/不可用，不自动处置。源码、正式发布与实际部署分别验收，各版本状态以 Release 回取报告与实机证据为准，具体范围见 [玄武控制与摘要分析](docs/xuanwu-control.md)、[安全中心架构](docs/security-center-architecture.md) 和 [功能与验收矩阵](docs/capability-status.md)。

## 本地宿主检查与文件深度查杀

R009 新增宿主/容器发现、目录纳管、真实 ClamAV 文件队列、扫描计数和重启恢复。Linux 菜单新增 31–34，可选择保护对象并查看覆盖缺口。新增能力纳入 **v0.5.0** 安装载荷；正式发布以对应 Release 及六附件回取验签为准。具体限制和验收范围见 [本地宿主发现与文件深度查杀](docs/local-host-full-scan.md)。

## 一行安装 / 更新

首次安装：选择下方 **铁幕** 或 **玄武**，复制代码框里的 **一行命令**，粘贴到 Linux SSH 终端。可在空的 `/root` 或任何目录执行，无需上传文件、克隆源码或安装 Git。

私有仓库出现 `password` 提示时，输入本仓库 `Contents: Read` 的 **GitHub 只读 Token**，输入隐藏。首次安装器还会询问同一个 Token，将其安全保存；不要输入服务器密码或六位验证码。公开仓库匿名下载成功时不用 Token。短入口每次下载私有引导器会重新询问 Token；安装后的日常更新用下方一行命令，会复用已保存令牌。

首次安装自动识别服务器公网 IPv4，无需输入；升级沿用已有地址。需要域名可用引导器的 `--host` 参数指定。命令自动补下载环境、核对固定引导器 SHA-256，再安装或更新签名正式包。安装入口获取 GitHub Latest 的签名正式包；部署新增宿主发现与深度查杀时，请确认验签提示为 v0.5.0 或更新正式版本。发布结果以 Release 与回取验签为准。

<!-- ONLINE-INSTALL:START -->

**需要保护的服务器：铁幕安全。**

```sh
sudo sh -c 'set -eu; set +x; umask 077; [ "$(id -u)" = 0 ] && [ "$(uname -s)" = Linux ] || { echo '\''请在 Linux 使用 sudo 或 root。'\'' >&2; exit 1; }; [ "$#" = 1 ]; case "$1" in local|cloud) ;; *) exit 1 ;; esac; ca_ready() { for ca in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do [ ! -s "$ca" ] || return 0; done; return 1; }; if ! command -v curl >/dev/null || ! command -v sha256sum >/dev/null || ! ca_ready; then . /etc/os-release; case "$ID" in debian|ubuntu) apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-remove curl ca-certificates coreutils ;; centos|rhel|rocky|almalinux|fedora|ol) if command -v dnf >/dev/null; then dnf install -y curl ca-certificates coreutils; else yum install -y curl ca-certificates coreutils; fi ;; *) echo '\''软件源不受支持。'\'' >&2; exit 1 ;; esac; ca_ready || exit 1; fi; work=$(mktemp -d /tmp/ironcurtain-online.XXXXXXXX); trap '\''rm -rf -- "$work"'\'' 0; trap '\''exit 130'\'' 2; trap '\''exit 143'\'' 15; url=https://api.github.com/repos/Jerry2586/Cloud-based-Scanning-and-Removal-Center/contents/install.sh?ref=d1e381b437d19d501675a1f20980d77a8a7900b2; fetch() { curl -q --proto '\''=https'\'' --tlsv1.2 -fsS --connect-timeout 15 --max-time 120 -H '\''Accept: application/vnd.github.raw+json'\'' "$@" "$url" -o "$work/install.sh" -w '\''%{http_code}'\'' > "$work/http-status"; }; if ! fetch; then case "$(cat "$work/http-status")" in 401|404) echo '\''password 提示请输入 GitHub 只读 Token；安装器首次保存时会再询问一次。'\'' >&2; fetch --user Jerry2586 ;; *) echo '\''下载失败，请检查网络、CA 或限流；不需要输入 Token。'\'' >&2; exit 1 ;; esac; fi; printf '\''%s  %s\n'\'' b06aa388a69add6ed2573eccd7e88004be467e551802ef8ec46e0d87f859d826 "$work/install.sh" | sha256sum -c -; sh "$work/install.sh" --role "$1"' -- local
```

**独立安全服务器：玄武引擎。**

```sh
sudo sh -c 'set -eu; set +x; umask 077; [ "$(id -u)" = 0 ] && [ "$(uname -s)" = Linux ] || { echo '\''请在 Linux 使用 sudo 或 root。'\'' >&2; exit 1; }; [ "$#" = 1 ]; case "$1" in local|cloud) ;; *) exit 1 ;; esac; ca_ready() { for ca in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do [ ! -s "$ca" ] || return 0; done; return 1; }; if ! command -v curl >/dev/null || ! command -v sha256sum >/dev/null || ! ca_ready; then . /etc/os-release; case "$ID" in debian|ubuntu) apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-remove curl ca-certificates coreutils ;; centos|rhel|rocky|almalinux|fedora|ol) if command -v dnf >/dev/null; then dnf install -y curl ca-certificates coreutils; else yum install -y curl ca-certificates coreutils; fi ;; *) echo '\''软件源不受支持。'\'' >&2; exit 1 ;; esac; ca_ready || exit 1; fi; work=$(mktemp -d /tmp/ironcurtain-online.XXXXXXXX); trap '\''rm -rf -- "$work"'\'' 0; trap '\''exit 130'\'' 2; trap '\''exit 143'\'' 15; url=https://api.github.com/repos/Jerry2586/Cloud-based-Scanning-and-Removal-Center/contents/install.sh?ref=d1e381b437d19d501675a1f20980d77a8a7900b2; fetch() { curl -q --proto '\''=https'\'' --tlsv1.2 -fsS --connect-timeout 15 --max-time 120 -H '\''Accept: application/vnd.github.raw+json'\'' "$@" "$url" -o "$work/install.sh" -w '\''%{http_code}'\'' > "$work/http-status"; }; if ! fetch; then case "$(cat "$work/http-status")" in 401|404) echo '\''password 提示请输入 GitHub 只读 Token；安装器首次保存时会再询问一次。'\'' >&2; fetch --user Jerry2586 ;; *) echo '\''下载失败，请检查网络、CA 或限流；不需要输入 Token。'\'' >&2; exit 1 ;; esac; fi; printf '\''%s  %s\n'\'' b06aa388a69add6ed2573eccd7e88004be467e551802ef8ec46e0d87f859d826 "$work/install.sh" | sha256sum -c -; sh "$work/install.sh" --role "$1"' -- cloud
```

<!-- ONLINE-INSTALL:END -->

**安装成功后，每次更新只需一行。**

铁幕更新：

```sh
sudo tiemu update
```

玄武更新：

```sh
sudo xuanwu update
```

打开菜单：铁幕输入 `sudo tiemu`；玄武输入 `sudo xuanwu`。

**旧版铁幕先运行一次 `sudo ironcurtain update`，升级至 v0.5.1 或更新正式版后即可使用 `tiemu`。**旧命令仍可用。两边菜单都会显示产品名称、网页面板地址和更新命令。

详细步骤、令牌权限与失败处理见 [Git 在线安装说明](docs/git-online-install.md)。正式安装仍验证 Ed25519 清单签名与安装包 SHA-256，拒绝降级和同版本内容变更。私有仓库令牌过期时，更新受保护令牌文件后重试；无人值守维护也可用已获得的引导器指定 `--token-file /绝对路径/令牌文件`。手动获取 `install.sh` 仍可作为离线传输入口，但不再是在线安装的前置步骤。

## 自动补环境的支持范围

需要 root、运行中的 systemd、x86_64/aarch64 CPU，以及可用的系统软件源和 HTTPS 网络。支持 Debian/Ubuntu 与使用 dnf/yum 的 CentOS/RHEL/Rocky/AlmaLinux/Fedora/Oracle Linux，但版本必须能从受信任软件源提供 Python >=3.9（含 sqlite3/ssl）及支持 Ed25519 raw 签名的 OpenSSL。已停止维护的旧系统可能无法满足这些条件；脚本会给出具体原因，不会假报成功。

引导器自动安装缺少的 Bash、下载/归档工具和 CA 包。角色安装器补齐宿主扫描工具，安装 Docker，补装 Buildx，并安装或升级 Compose 至 >=2.24.0。已有发行版 docker.io 优先使用对应插件包，禁止自动移除现有运行时；远程 Docker context、被屏蔽的服务、包冲突、端口占用和不可用软件源会明确停止。运行时 Node.js 在容器中，无需额外安装宿主 Node.js 或 MySQL。

源码安装器已增加基础镜像网络回退：优先 Docker Hub，连接超时、DNS 故障或限流时尝试 DaoCloud 的固定镜像路径。两者使用同一份 SHA-256 摘要，摘要不一致、鉴权失败或镜像不存在时立即停止。安装器复用摘要一致的本地镜像，不修改宿主 DNS、Docker 全局配置或关闭 TLS。每次拉取最多 180 秒、每次构建最多 300 秒，记录保存在 `/var/lib/ironcurtain/<local或cloud>/logs/image-build.*.log`。**v0.4.1 安装包包含此修复；原 v0.4.0 安装包没有备用源切换功能。安装时请确认验签提示版本至少为 v0.4.1。**

本地角色默认尝试安装 ClamAV/freshclam。RPM 系采用当前可用的 dnf 或 yum；软件源不提供病毒引擎或病毒库更新失败时显示“尚未就绪”，记录在角色 logs/antivirus-install.log，可运行 `sudo tiemu engine-install`重试。容器健康不等于病毒库已经可用。

默认面板端口：铁幕 8790，玄武管理面板 8791；玄武节点 mTLS 接口 9443。按管理来源限制安全组与主机防火墙；自签/私有 CA 证书须核对指纹并导入信任，安装器不关闭 TLS 校验。

## 开发 / 离线源码安装

只有已经获取并校验完整源码时，才在源码目录使用以下内部入口：

```sh
sudo bash scripts/install-independent.sh --role local
sudo bash scripts/install-independent.sh --role cloud
```

这两个命令不会自行下载源码。离线首装还需提前准备系统依赖、Docker/插件和所需镜像；上传源码不能代替这些依赖。

现有 `APPGOG-Cloud-Security-Center-*` 文件名和发布产品标识保留为发布链兼容标识；它们不使程序依赖 APPGOG。正式切换名称时需兼顾旧引导器，不更换验签公钥。

## Linux 可视化菜单与加密对接

铁幕运行 `sudo tiemu`，玄武运行 `sudo xuanwu`。菜单提供启停、日志、签名更新、环境诊断和角色专属对接。

1. 在玄武选择“登记节点与加密导出”，只需填写如 `node-server1` 的唯一名称。玄武为每台铁幕自动生成独立的随机解锁密码，在可信 SSH 终端显示，并保存在加密包旁的 `.icpair.unlock` 文件中（root:root、600 权限）；不再要求手动设置密码。玄武可管理多个节点。
2. 将生成的 `.icpair` **加密身份包**通过可信通道复制到对应铁幕主机。玄武 CA 私钥和浏览器 reader 身份留在玄武管理域。
3. 在铁幕选择“导入玄武身份包”，填写文件路径、从独立管理通道核对的 CA SHA-256 指纹，粘贴玄武自动生成的解锁密码。密码与 `.icpair` 文件分开传递和保管；不要将 `.unlock` 文件作为加密包公开下载。先验证证书、节点、私钥、令牌及真实 mTLS 握手；成功后提交新身份。
4. 在铁幕选择“配置保护范围”，填写程序目录、业务目录、关键配置、凭据权限检查项、SQLite、容器和允许端口。未配置的项目显示未就绪。
5. 用“一键扫描”和“检查加密连接”查看真实结果；在玄武选择“浏览器面板证书”获取 reader 导入指引。

本地面板使用独立随机管理员密码；`sudo tiemu credentials` 仅在可信终端查看，`sudo tiemu reset-password` 重置并使旧会话失效。玄武网页 `/dashboard` 需 reader 客户端证书及独立登录凭据。铁幕网页新增「设置 · 版本与更新」，显示运行版本、安装版本、文件摘要校准、Git main 提交及最新签名正式版本；可检查并启动固定的签名升级任务。保护范围、配对和撤销仍由 Linux 菜单管理。详见 [版本校准与更新](docs/local-version-settings.md)。

## 检测范围与边界

铁幕固定 25 项检查覆盖文件摘要、配置、容器隔离和镜像身份、系统/SSH/权限、TCP/UDP 监听、路由、内核、防火墙、进程、失败服务、SQLite、可选 ClamAV 及 Cloudflare 只读检查。百分比来自已完成检查项，不等于文件数量；缺少依赖、签名基线、配置或权限显示 `unavailable`。Cloudflare 检查需本机专属只读配置和显式批准基线。

本机按固定周期巡检，保留报告和变化记录，主动通过 mTLS 上报玄武。断开玄武时本机检查继续。玄武无业务主机 SSH、Docker socket、任意命令执行或自动删除权限。命中文件隔离与恢复由 Linux root 菜单按证据显式执行；网页读取隔离记录。自动病毒特征库刷新、通用自动修复、不可变异地灾备及灾难切换仍在完善，未接通的按钮不显示成功。

## 目录与开发验证

- `src/local`：铁幕独立网页、登录、扫描及玄武连接客户端。
- `src/host`：宿主检查服务与只读 Cloudflare 采集。
- `src/server.js`、`src/monitor.js`、`src/dashboard.js`：玄武 mTLS 服务、节点状态与面板。
- `docker`：local/cloud 独立容器定义。
- `scripts/install-independent.sh`、`scripts/ironcurtain.sh`：安装事务与 Linux 菜单。
- `migration/source-map.json`：从旧业务项目迁出的代码来源记录。

`node --test`、`python3 tests/host-agent.test.py` 是本机接口和扫描验证。Linux CI 另执行事务文件系统验证及一次性 runner 上真实 Docker/systemd 首装、配对、扫描和升级。详见 [独立架构](docs/security-center-architecture.md)、[面板说明](docs/security-console.md)、[处置与恢复边界](docs/local-security-response.md)。

## 独立系统加密备份与同机恢复

铁幕与玄武菜单分别提供创建恢复包、验证恢复包、同机恢复。备份只包含该安全角色的配置和状态，不备份受保护网站的业务数据库。恢复要求同一机器、同一角色、同一程序版本；保留当前密码、证书、已撤销节点与解绑状态。加密包和独立密钥须通过可信通道分别保存到异地。同机恢复不等于干净主机重建或不可变灾备。具体命令与验收边界见 [独立恢复说明](docs/independent-recovery.md)。

## 玄武分发签名程序包

玄武 root 管理员使用 `xuanwu release-import` 导入独立发布环境签名的六份正式附件；铁幕 root 管理员使用 `tiemu release-update`，通过已有节点 mTLS 身份主动获取并独立验签，然后调用原安装器更新。玄武分发的程序更新由本地管理员执行；铁幕网页设置也可显式启动 GitHub 最新签名正式版本升级，规则同步不会自动触发程序安装。命令、信任边界与验收范围见 [签名程序分发说明](docs/signed-program-delivery.md)。

## 玄武分发官方病毒库

独立发布环境验证 ClamAV 官方 CVD 并签名，玄武菜单 29 导入，铁幕菜单 29 通过已有 mTLS 身份拉取、验证发布签名和官方 CVD 签名、真实加载检查后原子启用。启用后关闭本机 freshclam 定时器，避免两种更新源同时写库；后续从同一菜单手动刷新。此流程只更新病毒库，不执行云端指令。详细准备步骤与验收边界见 [签名病毒库分发说明](docs/signed-virus-database.md)。

## 域名与自动 HTTPS

先在 Cloudflare 将域名指向服务器，然后在面板设置填写域名并保存；Linux 菜单 35 同样可用，菜单 36 查看结果。证书申请及每日续期由程序处理，原 IP 入口保留。两端自行管理域名和证书，不依赖任何业务项目。自动申请需要公网 80/443 可用；端口被其他服务占用时明确显示冲突并保留原入口，不修改其他网站配置。玄武浏览器管理端口为 8791，节点 mTLS 仍为 9443。详见 [域名设置与运行条件](docs/domain-https-settings.md)。

## 修改面板密码

铁幕服务器运行 `sudo tiemu password`，玄武服务器运行 `sudo xuanwu password`，或在管理菜单选择 **14 修改面板密码 / 随机重置**。选择自定义密码后隐藏输入两次（12–256 字符）；root 管理员无需输入旧面板密码。忘记密码可选择随机重置。

玄武网页右上角或侧栏进入 **用户中心**，填写当前密码、新密码并确认。修改成功后所有旧登录会话失效，请用新密码重新登录；服务器和容器重启会保留新密码。
