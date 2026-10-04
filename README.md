# 铁幕安全 · 玄武引擎

独立 Linux 安全项目，统一源码、独立角色：**铁幕安全**部署在需要保护的服务器，**玄武引擎**部署在独立的安全服务器。每个角色运行一个 Docker 容器；铁幕额外安装一个固定权限的宿主扫描服务。可保护 APPGOG，也可配置其他网站和容器。

APPGOG 的授权、打包、账号、数据库和升级仍由其自己的项目负责。安全面板、检测逻辑、节点身份和安全更新在本仓库维护。

> 当前程序版本 **0.4.0**，增加玄武官方病毒库签名缓存、认证流式下发和铁幕 root 菜单原子启用。源码验收 37189710268 三组 Linux 检查全部通过；官方库验收 37189710784 完成真实 CVD 下载、独立发布/官方双重验签、mTLS 传输、本地启用及正常/EICAR 扫描。v0.3.0 的六附件正式验收记录保留；新版本正式状态以 GitHub Release 与回取验签报告为准。异地灾备和跨主机扩展仍需补齐。实际范围见 [功能与验收矩阵](docs/capability-status.md)。

## 安装 / 更新：只需一个独立安装文件

**不要在空的服务器目录运行 `sudo bash scripts/install-independent.sh`。** 这是源码内部脚本，没有下载源码时会报“找不到文件”。正式服务器使用根目录的独立引导器 `install.sh`；它负责获取签名正式安装包，不需要先克隆仓库、进入源码目录或安装 Git、Node.js、数据库。

首次把从本仓库可信渠道取得的 **install.sh 单文件**上传到服务器的 `/root/install.sh`。当前仓库私有，请在已登录 GitHub 的页面下载；匿名链接不能读取私有文件。该文件必须来自已完成验收的正式版本，不能把开发版引导器当成已发布功能。

**需要保护的服务器：铁幕安全。** 在任何目录执行：

```sh
sudo sh /root/install.sh --role local
```

**独立安全服务器：玄武引擎。** 在任何目录执行：

```sh
sudo sh /root/install.sh --role cloud
```

首次输入域名或固定 IPv4。公开发布源可直接下载；私有发布源首次下载失败时会提示隐藏输入 GitHub Token，并保存至 `/etc/ironcurtain/github-release.token`（root 所有、600 权限）。令牌只需本仓库 Contents: Read，不写进 URL、命令、日志或 .env。无人值守安装使用 `--token-file /绝对路径/令牌文件`；文件须为 root 所有、600/400 权限的普通文件。

重复执行相同命令：未安装则安装，已有安装则检查最新签名正式版本并升级；同版本、载荷一致且服务健康则安全退出。程序更新前验证 Ed25519 清单签名与安装包 SHA-256，拒绝降级、同版本变更及不受控目录；安装失败由原事务流程恢复旧配置、身份和服务。

已安装后更短：铁幕输入 `sudo ironcurtain update`，玄武输入 `sudo xuanwu update`。私有仓库必须保留有效的只读令牌，失效时更新该文件再重试。

## 自动补环境的支持范围

需要 root、运行中的 systemd、x86_64/aarch64 CPU，以及可用的系统软件源和 HTTPS 网络。支持 Debian/Ubuntu 与使用 dnf/yum 的 CentOS/RHEL/Rocky/AlmaLinux/Fedora/Oracle Linux，但版本必须能从受信任软件源提供 Python >=3.9（含 sqlite3/ssl）及支持 Ed25519 raw 签名的 OpenSSL。已停止维护的旧系统可能无法满足这些条件；脚本会给出具体原因，不会假报成功。

引导器自动安装缺少的 Bash、下载/归档工具和 CA 包。角色安装器补齐宿主扫描工具，安装 Docker，补装 Buildx，并安装或升级 Compose 至 >=2.24.0。已有发行版 docker.io 优先使用对应插件包，禁止自动移除现有运行时；远程 Docker context、被屏蔽的服务、包冲突、端口占用和不可用软件源会明确停止。运行时 Node.js 在容器中，无需额外安装宿主 Node.js 或 MySQL。

本地角色默认尝试安装 ClamAV/freshclam。RPM 系采用当前可用的 dnf 或 yum；软件源不提供病毒引擎或病毒库更新失败时显示“尚未就绪”，记录在角色 logs/antivirus-install.log，可运行 `sudo ironcurtain engine-install`重试。容器健康不等于病毒库已经可用。

默认面板端口：铁幕 8790，玄武 9443。按管理来源限制安全组与主机防火墙；自签/私有 CA 证书须核对指纹并导入信任，安装器不关闭 TLS 校验。

## 开发 / 离线源码安装

只有已经获取并校验完整源码时，才在源码目录使用以下内部入口：

```sh
sudo bash scripts/install-independent.sh --role local
sudo bash scripts/install-independent.sh --role cloud
```

这两个命令不会自行下载源码。离线首装还需提前准备系统依赖、Docker/插件和所需镜像；上传源码不能代替这些依赖。

现有 `APPGOG-Cloud-Security-Center-*` 文件名和发布产品标识保留为发布链兼容标识；它们不使程序依赖 APPGOG。正式切换名称时需兼顾旧引导器，不更换验签公钥。

## Linux 可视化菜单与加密对接

铁幕运行 `sudo ironcurtain`，玄武运行 `sudo xuanwu`。菜单提供启停、日志、签名更新、环境诊断和角色专属对接。

1. 在玄武选择“登记节点与加密导出”，填写如 `node-server1` 的唯一名称和至少 16 字符的解锁密码。每台铁幕独立登记，玄武可管理多个节点。
2. 将生成的 `.icpair` **加密身份包**通过可信通道复制到对应铁幕主机。玄武 CA 私钥和浏览器 reader 身份留在玄武管理域。
3. 在铁幕选择“导入玄武身份包”，填写文件路径、从独立管理通道核对的 CA SHA-256 指纹和解锁密码。先验证证书、节点、私钥、令牌及真实 mTLS 握手；成功后提交新身份。
4. 在铁幕选择“配置保护范围”，填写程序目录、业务目录、关键配置、凭据权限检查项、SQLite、容器和允许端口。未配置的项目显示未就绪。
5. 用“一键扫描”和“检查加密连接”查看真实结果；在玄武选择“浏览器面板证书”获取 reader 导入指引。

本地面板使用独立随机管理员密码；`sudo ironcurtain credentials` 仅在可信终端查看，`sudo ironcurtain reset-password` 重置并使旧会话失效。玄武网页 `/dashboard` 需 reader 客户端证书及独立登录凭据。网页当前读取状态；保护范围、配对、撤销、更新等管理动作走 Linux 菜单。

## 检测范围与边界

铁幕固定 27 项检查覆盖文件摘要、配置、容器隔离和镜像身份、系统/SSH/权限、TCP/UDP 监听、路由、内核、防火墙、进程、失败服务、SQLite、可选 ClamAV 及 Cloudflare 只读检查。百分比来自已完成检查项，不等于文件数量；缺少依赖、签名基线、配置或权限显示 `unavailable`。Cloudflare 检查需本机专属只读配置和显式批准基线。

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

玄武 root 管理员使用 `xuanwu release-import` 导入独立发布环境签名的六份正式附件；铁幕 root 管理员使用 `ironcurtain release-update`，通过已有节点 mTLS 身份主动获取并独立验签，然后调用原安装器更新。程序更新不由网页或规则自动同步触发。命令、信任边界与验收范围见 [签名程序分发说明](docs/signed-program-delivery.md)。

## 玄武分发官方病毒库

独立发布环境验证 ClamAV 官方 CVD 并签名，玄武菜单 29 导入，铁幕菜单 29 通过已有 mTLS 身份拉取、验证发布签名和官方 CVD 签名、真实加载检查后原子启用。启用后关闭本机 freshclam 定时器，避免两种更新源同时写库；后续从同一菜单手动刷新。此流程只更新病毒库，不执行云端指令。详细准备步骤与验收边界见 [签名病毒库分发说明](docs/signed-virus-database.md)。
