# 铁幕安全 · 玄武引擎

独立 Linux 安全项目，统一源码、独立角色：**铁幕安全**部署在需要保护的服务器，**玄武引擎**部署在独立的安全服务器。每个角色运行一个 Docker 容器；铁幕额外安装一个固定权限的宿主扫描服务。可保护 APPGOG，也可配置其他网站和容器。

APPGOG 的授权、打包、账号、数据库和升级仍由其自己的项目负责。安全面板、检测逻辑、节点身份和安全更新在本仓库维护。

> 当前程序版本 **0.4.0**，增加玄武官方病毒库签名缓存、认证流式下发和铁幕 root 菜单原子启用。源码验收 37189710268 三组 Linux 检查全部通过；官方库验收 37189710784 完成真实 CVD 下载、独立发布/官方双重验签、mTLS 传输、本地启用及正常/EICAR 扫描。v0.3.0 的六附件正式验收记录保留；新版本正式状态以 GitHub Release 与回取验签报告为准。异地灾备和跨主机扩展仍需补齐。实际范围见 [功能与验收矩阵](docs/capability-status.md)。

## 小白安装：选一个角色，运行一条命令

先把经过校验的本项目源码放到服务器，进入项目目录。使用带 systemd 的 Debian/Ubuntu，或支持 dnf/yum 的 RHEL/Rocky/AlmaLinux/Fedora/Oracle Linux；CPU 为 x86_64 或 aarch64。脚本识别支持范围、补齐基础工具、Docker、Compose 和 Buildx，无需另外安装 Node.js 数据库环境。

**需要保护的服务器：安装铁幕安全。** 首装询问服务器域名或固定 IPv4。

```sh
sudo bash scripts/install-independent.sh --role local
```

**独立安全服务器：安装玄武引擎。** 首装询问其域名或固定 IPv4。

```sh
sudo bash scripts/install-independent.sh --role cloud
```

更高版本的可信源码使用相同命令升级；同版本且载荷一致、服务健康则安全退出。同版本内容变化、降级、端口冲突或不受控路径会拒绝。升级前保存 root 私有恢复快照，失败恢复旧配置、身份、版本链接和服务状态。首次失败恢复安装前状态。

默认面板端口：铁幕 `8790`，玄武 `9443`。安装器不会替你开放所有防火墙端口；按管理来源限制安全组与主机防火墙。自签/私有 CA 证书需核对指纹并导入信任，不能用关闭 TLS 校验替代身份核验。

## 正式发布后的固定安装 / 更新入口

经过正式签名发布后，把该 Release 的 `install.sh` 下载到服务器。首次执行选择角色；每次执行仍用同一条命令：

```sh
sudo sh ./install.sh --role local
```

本行安装/更新铁幕。玄武使用：

```sh
sudo sh ./install.sh --role cloud
```

已有安装可以更短：`sudo ironcurtain update` 或 `sudo xuanwu update`。引导器先校验内置公钥对应的 Ed25519 发布签名，再校验安装包 SHA-256，然后执行安装。云端服务没有发布签名私钥。

公开仓库通过 HTTPS 获取正式附件。私有仓库使用只授予本仓库读取权限的 GitHub 令牌，存入 root 专属文件 `/etc/ironcurtain/github-release.token`，权限 `600`；不把令牌放在命令、URL、日志或 `.env`。也可通过 `IRONCURTAIN_GITHUB_TOKEN_FILE` 指定同等权限文件。私有仓库首次获取引导器仍需要已登录 GitHub 下载或可信分发；一条匿名 raw URL 无法读取私有源码。已安装节点保留引导器后，重复命令可认证下载更新。

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
