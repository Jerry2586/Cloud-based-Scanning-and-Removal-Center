# 独立云端安全监测中心

此仓库运行在独立 Linux 服务器。Node 24 服务通过私有 CA 签发的客户端证书和独立令牌识别授权中心、打包中心与只读后台；定时从公网 HTTPS 健康端点探测两个业务节点，并比较业务节点上报的文件摘要与可信发布包的基线。它是文件完整性和可用性监测器，不是病毒特征查杀器；云端本身不远程执行命令或删除业务文件。

## 安装

支持带 systemd 的 x86_64/aarch64 Linux，apt 或 dnf 包管理器。安装脚本安装缺失的基础依赖、从 nodejs.org 下载并校验 Node 24 的 SHA-256、生成独立 CA 和服务证书、保存状态目录、设置 systemd 并执行本机 HTTPS 身份检查。使用域名时把 DNS A 记录指向这台服务器；也可直接用固定公网 IPv4 地址。放通 TCP 9443：

```sh
sudo bash scripts/install-linux.sh --host security.example.com
# 无域名时：sudo bash scripts/install-linux.sh --host 203.0.113.10
```

重复运行同一个版本只能使用相同源码；升级时须提升 `package.json` 的版本。旧状态保存在 `/var/lib/appgog-security`；配置和私钥保存在 `/etc/appgog-security`，不得从业务服务器复制过来。

### 私有仓库从干净 Linux 一行安装

在安全服务器预先配置**只读** SSH deploy key、核对 GitHub SSH 主机指纹并保存到 root 的 `known_hosts`；从受信的开发/发布环境取得并审核 40 位提交 SHA。下面是一条命令，替换末尾的 `COMMIT_SHA` 和 `SERVER_HOST`。命令不会把 GitHub 凭据写到参数、日志或仓库中；SSH 身份不可用时会直接失败，不会回退到匿名下载。支持 systemd、apt/dnf、x86_64/aarch64，其他环境明确停止。

```sh
sudo bash -c 'set -eu; umask 077; if ! command -v git >/dev/null || ! command -v ssh >/dev/null; then if command -v apt-get >/dev/null; then apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y git openssh-client; elif command -v dnf >/dev/null; then dnf install -y git openssh-clients; else echo "Unsupported package manager" >&2; exit 1; fi; fi; workdir=$(mktemp -d); trap '\''rm -r -- "$workdir"'\'' EXIT; GIT_SSH_COMMAND="ssh -o StrictHostKeyChecking=yes" git clone --quiet --no-checkout git@github.com:Jerry2586/Cloud-based-Scanning-and-Removal-Center.git "$workdir"; cd "$workdir"; git cat-file -e "$1^{commit}"; git checkout --quiet --detach "$1"; test "$(git rev-parse HEAD)" = "$1"; bash scripts/install-linux.sh --host "$2"' _ COMMIT_SHA SERVER_HOST
```

这条命令自动补齐基础依赖并安装服务；私有源码的**读权限、可信提交 SHA 和 SSH 主机身份**必须由管理员独立提供。首次配对前，从本机控制台独立记录安装器输出的 CA SHA-256 指纹，业务机配对时输入该指纹。多次运行同一提交可做重装检查；升级先审查新提交并提高项目版本。安装成功不代表已与授权/打包节点配对，也不代表跨机容灾演练通过。

## 注册和交付凭据

基线必须从独立校验过的同版本源码生成。**不要从已经怀疑受入侵的业务机器采样并批准基线。**

```sh
node scripts/create-baseline.js /path/to/verified/APPGOG > /root/appgog-baseline.json
sudo bash scripts/enroll-node.sh license-center https://auth.example.com/health /root/appgog-baseline.json
sudo bash scripts/enroll-node.sh build-center https://build.example.com/health /root/appgog-baseline.json
sudo bash scripts/export-business-bundle.sh all /root/business-pairing
```

同机业务安装用 `all` 导出的身份包，复制到该机的私有目录，再运行其版本化 `scripts/security-connect.sh`。三台服务器分别安装时，只能分别导出 `license` 和 `build`，禁止给打包机发放 `reader` 身份。业务仓库的安装器支持 `--role license` 和 `--role build`；打包分机首装需要授权后台分别签发的两个节点凭据。分机方案仍需在真实 Linux 主机上完成首装、升级和断线验收。

云端服务器上 `/v1/connectivity` 返回已认证身份；`/v1/status` 仅允许 reader，`/v1/report` 仅允许两个上报节点。通过 `scripts/rotate-identity.sh stage|commit <role>` 分两步换证和令牌：先在云端 stage，部署并验证新身份，再 commit 撤销旧身份。公网 `/health` 只表示云端进程存活，不能当作业务节点安全判据。

## 宿主检查自报

授权和打包节点各自的 systemd 代理启动后以及每五分钟运行固定范围检查，节点通过既有 mTLS 身份和令牌上报状态、检查时间及四种状态计数，不上报文件内容、详细路径或本地日志。云端严格校验形状、计数与未来时间；自报超过十五分钟或节点报告超过两分钟未刷新时显示过期，异常状态变化记为 host.finding / host.warning / host.unavailable / host.stale，恢复记为 host.resumed。旧节点未上报宿主结果时显示不可用；该数据带 node-self-report 来源标签，业务节点失守时不具备独立可信性。公网探测由云端独立执行，保持独立字段。

## 运维限制

服务上报代码目录的文件哈希，不读取业务数据卷、数据库、私钥和系统进程；节点失联时云端仍会继续探测公网健康端点并留下事件。超过两分钟没有收到节点报告会记录 `report.stale`，重新收到经过身份认证的报告会记录 `report.resumed`；事件只保留最近 300 条，必须额外转发到独立日志存储以支持长期取证。若攻击者取得业务进程权限，可伪造该进程可读取的数据和报告；应结合独立备份、审计、主机侧隔离与应急响应。新基线需要在完成签名版本核验后再批准，不随被监控主机的报告自动更新。

## 手动部署到独立安全服务器

在你的电脑上先确认服务器的 SSH 能正常完成握手，然后在**安全服务器**上执行下列命令。私有仓库需要使用你自己的 GitHub 访问方式完成认证；不要把服务器登录密码或 GitHub 令牌写进命令、脚本或仓库。

```sh
# 连接前把 SERVER_IP 换成安全服务器的公网 IPv4；SSH 端口按服务商实际配置填写。
ssh -p 1500 root@SERVER_IP

# 以下在安全服务器上执行：
apt-get update && apt-get install -y git
# 若服务器使用 dnf：dnf install -y git
cd /root
git clone https://github.com/Jerry2586/Cloud-based-Scanning-and-Removal-Center.git cloud-security-center
cd cloud-security-center
sudo bash scripts/install-linux.sh --host SERVER_IP
sudo systemctl status appgog-security.service --no-pager
```

若私有仓库使用 HTTPS 克隆，GitHub 身份验证须通过事先配置的凭据管理器或短期凭据进行；也可以先为这台服务器配置只有此仓库读取权限的 SSH deploy key，再用 SSH 地址克隆。不要把登录口令放到克隆 URL。

安装后在**安全服务器本机**以已签发的 reader 身份检验服务证书和客户端认证，以下检查应返回 JSON 状态；它不会注册业务节点：

```sh
CONF=/etc/appgog-security
TOKEN=$(sudo cat "$CONF/credentials/reader.token")
sudo curl --fail-with-body --cacert "$CONF/ca.crt" \
  --cert "$CONF/credentials/reader.crt" --key "$CONF/credentials/reader.key" \
  -H "Authorization: Bearer $TOKEN" \
  "https://SERVER_IP:9443/v1/status"
unset TOKEN
```

从业务服务器访问时，还须放通安全服务器入站 TCP 9443，并在业务服务器上完成身份包配置；仅本机状态正常不等于业务认证连通。不要把 `/etc/appgog-security` 下的私钥、令牌或 CA 私钥提交到 Git。
