# 独立云端安全监测中心

此仓库运行在独立 Linux 服务器。Node 24 服务通过私有 CA 签发的客户端证书和独立令牌识别授权中心、打包中心与只读后台；定时从公网 HTTPS 健康端点探测两个业务节点，并比较业务节点上报的文件摘要与可信发布包的基线。它是文件完整性和可用性监测器，不是病毒特征查杀器；云端本身不远程执行命令或删除业务文件。

## 签名 Release 一键安装与更新

正式安装只信任 GitHub Release 中的版本化 `.run`、Ed25519 签名清单和 SHA-256，不以 Git 分支源码作为生产更新源。同一条命令在未安装时执行首装，已安装时检查并升级到最新正式版；同版本健康时幂等退出，拒绝自动降级。升级前自动创建完整加密备份，安装、systemd 或认证健康检查失败时自动恢复旧版本、旧配置、数据和原服务状态。

支持带 systemd 的 Debian、Ubuntu、CentOS、RHEL、Rocky Linux、AlmaLinux、Fedora、Oracle Linux，支持 amd64/arm64。安装器自动补齐 CA、curl、OpenSSL、coreutils、jq 等基础工具，下载并校验合同固定的 Node 24 运行时，生成独立 CA 与服务身份并开放本机管理入口。服务器需放通 TCP 9443。

公共仓库可在干净 Linux 上执行：

```sh
curl -fsSL https://raw.githubusercontent.com/Jerry2586/Cloud-based-Scanning-and-Removal-Center/main/install.sh -o /tmp/appgog-security-install.sh && sudo sh /tmp/appgog-security-install.sh --host security.example.com
```

没有域名时，把 `security.example.com` 换成固定公网 IPv4。首次成功后，引导器保存为 `/opt/appgog-security/install.sh`，以后输入 `appgog-security update` 即可走同一套签名更新流程。

私有仓库首次安装时，先从已登录的 GitHub 仓库 **Code** 页面下载并核对可信的 `install.sh`，再上传到服务器；已经成功安装过的服务器可复用保存于 `/opt/appgog-security/install.sh` 的引导器。随后为服务器创建仅限本仓库 `Contents: Read` 的细粒度令牌，写入 root 专用文件，不把令牌放进命令行、`.env` 或日志：

```sh
sudo install -d -m 700 /etc/appgog-security
sudo install -m 600 /dev/stdin /etc/appgog-security/github-release.token
sudo sh ./install.sh --host security.example.com
```

第二行会等待管理员从终端标准输入粘贴令牌并按 `Ctrl-D` 结束。之后同样使用 `appgog-security update`；引导器只把令牌发送给 GitHub API，跟随到对象存储的下载请求不会携带授权头。公共与私有模式下载后都必须通过同一套签名、发布合同、包内版本和哈希检查，任一不一致立即停止。

配置、证书和身份保存在 `/etc/appgog-security`，运行状态和加密备份保存在 `/var/lib/appgog-security`，版本程序保存在 `/opt/appgog-security/releases`。备份密钥 `/etc/appgog-security/backup.key` 不包含在备份包内，必须单独离线保管；密钥丢失时加密备份无法恢复。正式环境不要把这三个目录或任何令牌、私钥提交到 Git。

安装完成输入 `appgog-security` 打开 Linux 管理菜单，可查看状态、启停、日志、诊断、安全更新、加密备份、事务恢复和保留数据卸载。首次配对前，从服务器控制台独立记录安装器输出的 CA SHA-256 指纹，业务机连接时必须核对。安装成功只证明云端本机通过认证健康检查，不代表授权/打包节点已配对，也不代表双机或三机容灾演练已经完成。

源码方式仅用于开发维护：在可信源码目录运行 `sudo bash scripts/install-linux.sh --host security.example.com`。它不能替代正式签名 Release。

## 注册和交付凭据

基线必须从独立校验过的同版本源码生成。**不要从已经怀疑受入侵的业务机器采样并批准基线。**

```sh
node scripts/create-baseline.js /path/to/verified/APPGOG > /root/appgog-baseline.json
sudo bash scripts/enroll-node.sh license-center https://auth.example.com/health /root/appgog-baseline.json
sudo bash scripts/enroll-node.sh build-center https://build.example.com/health /root/appgog-baseline.json
sudo bash scripts/export-business-bundle.sh all /root/business-pairing
```

同机业务安装用 `all` 导出的身份包，复制到该机的私有目录，再运行其版本化 `scripts/security-connect.sh`。三台服务器分别安装时，只能分别导出 `license` 和 `build`，禁止给打包机发放 `reader` 身份。业务仓库的安装器支持 `--role license` 和 `--role build`；打包分机首装需要授权后台分别签发的两个节点凭据。分机方案仍需在真实 Linux 主机上完成首装、升级和断线验收。

### 只读 API 与安全面板

除公网 `/health` 外，所有接口都要求受私有 CA 信任的客户端证书以及对应的独立令牌。`/health` 只表示云端进程存活，不能当作业务节点安全判据。

| 路径 | 身份 | 用途 |
|---|---|---|
| `/v1/connectivity` | reader、授权节点或打包节点 | 返回当前已经认证的角色，不泄露凭据 |
| `/v1/status` | reader | 汇总节点探测、文件完整性、宿主检查和报告新鲜度 |
| `/v1/identity` | reader | 查看证书有效期、轮换状态和旧身份撤销状态 |
| `/v1/audit` | reader | 查看最近安全事件；长期取证仍应转发到独立日志存储 |
| `/v1/policy` | reader、授权节点或打包节点 | 拉取只读、固定为 fail-closed 的公开策略 |
| `/v1/report` | 对应授权节点或打包节点 | 上报固定结构的文件摘要和宿主检查计数 |
| `/dashboard` | reader | 服务端渲染的只读安全面板 |

浏览器访问 `/dashboard` 时必须同时满足两层认证：浏览器持有 reader 客户端证书，并通过 HTTP Basic 登录。用户名固定为 `reader`，密码是 `/etc/appgog-security/credentials/reader.token` 的当前内容。页面不包含客户端 JavaScript，也不会把令牌、私钥或节点凭据写进 HTML。

需要从管理员电脑查看面板时，在安全服务器本机生成带强导出密码的临时 PKCS#12 文件：

```sh
sudo openssl pkcs12 -export \
  -inkey /etc/appgog-security/credentials/reader.key \
  -in /etc/appgog-security/credentials/reader.crt \
  -certfile /etc/appgog-security/ca.crt \
  -name APPGOG-reader -out /root/appgog-reader.p12
```

通过独立加密通道把 `appgog-reader.p12` 和 `ca.crt` 交付到管理员电脑：把 `ca.crt` 导入受信任证书颁发机构，把 PKCS#12 导入个人证书存储，然后访问 `https://安全服务器地址:9443/dashboard`。确认可用后立即删除服务器和管理员电脑上的 PKCS#12 临时文件；不得通过聊天、邮件正文、Git 或工单附件传输私钥与令牌。

### 两阶段身份轮换

`scripts/rotate-identity.sh` 支持 `reader`、`license-center`、`build-center` 三种身份。轮换顺序固定为：

1. 在云端执行 `sudo bash scripts/rotate-identity.sh stage <role>`，此时旧身份保持 `active`，新身份为 `staged`，两者都可完成认证。
2. 通过独立加密通道把 `.next.crt`、`.next.key`、`.next.token` 部署到对应业务节点。reader 轮换时使用 `reader.next.crt`、`reader.next.key`、`reader.next.token`：用前两个文件生成并导入新的 PKCS#12，新面板的 Basic 密码是 `reader.next.token` 的内容。
3. 用新证书和新令牌完成真实 `/v1/connectivity`、业务报告或 `/dashboard` 检查，并确认 `/v1/identity` 显示轮换中。
4. 只有新身份在真实链路通过后，才执行 `sudo bash scripts/rotate-identity.sh commit <role>`；提交会删除旧身份的认证资格并把新身份设为唯一 `active`。

不得在新身份尚未部署或未完成实机检查时执行 `commit`。证书已过期会进入风险状态，接近到期或存在尚未提交的 staged 身份会进入警告状态。安装器会把旧版 reader 的单证书结构迁移成身份数组；旧配置缺少 reader 时，会使用本机现有 reader 证书和令牌补齐。迁移只接受与本机证书指纹一致的 reader，不会静默信任陌生身份。

reader 处于 staged 阶段时，临时 PKCS#12 必须明确引用新身份文件：

```sh
sudo openssl pkcs12 -export \
  -inkey /etc/appgog-security/credentials/reader.next.key \
  -in /etc/appgog-security/credentials/reader.next.crt \
  -certfile /etc/appgog-security/ca.crt \
  -name APPGOG-reader-next -out /root/appgog-reader-next.p12
```

## 宿主检查自报

授权和打包节点各自的 systemd 代理启动后以及每五分钟运行固定范围检查，节点通过既有 mTLS 身份和令牌上报状态、检查时间及四种状态计数，不上报文件内容、详细路径或本地日志。云端严格校验形状、计数与未来时间；自报超过十五分钟或节点报告超过两分钟未刷新时显示过期，异常状态变化记为 host.finding / host.warning / host.unavailable / host.stale，恢复记为 host.resumed。旧节点未上报宿主结果时显示不可用；该数据带 node-self-report 来源标签，业务节点失守时不具备独立可信性。公网探测由云端独立执行，保持独立字段。

## 运维限制

服务上报代码目录的文件哈希，不读取业务数据卷、数据库、私钥和系统进程；节点失联时云端仍会继续探测公网健康端点并留下事件。超过两分钟没有收到节点报告会记录 `report.stale`，重新收到经过身份认证的报告会记录 `report.resumed`；事件只保留最近 300 条，必须额外转发到独立日志存储以支持长期取证。若攻击者取得业务进程权限，可伪造该进程可读取的数据和报告；应结合独立备份、审计、主机侧隔离与应急响应。新基线需要在完成签名版本核验后再批准，不随被监控主机的报告自动更新。

云端与业务端的边界是 **Pull-only + 本地处置**：云端只接收经过 mTLS 与独立令牌认证的报告、执行公网探测、保存审计事件并发布只读安全策略。安全服务器不得保存业务服务器 SSH 私钥，不得挂载业务 Docker Socket，不提供任意命令、任意路径扫描、远程删除或主动推送修复能力。隔离可疑容器、恢复可信镜像、断网自治、回滚与文件修复必须由业务服务器上的本地代理按本地批准策略执行。即使云端被攻破，也不能因此直接取得业务服务器命令执行权。

策略校验固定拒绝未签名更新、远程命令和云端主动推送；配置中出现重复令牌、重复证书指纹、未知角色、非 HTTPS 健康地址、带用户名/密码的健康地址、非法摘要或不完整轮换状态时，服务拒绝启动。

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
