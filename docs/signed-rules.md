# 签名哈希规则：发布、导入、更新

当前为 0.2.0 候选。人工导入和拉取已实现；真实 Linux 验收以 capability-status.md 为准。规则与 ClamAV 官方病毒库分别维护，当前没有云端程序灰度或病毒库统一分发承诺。

## 发布环境

在独立发布环境准备 JSON，文件权限 600。字段固定：schema 为 ironcurtain-threat-rules/v1；version 和 minimum_agent_version 是三段版本；sequence 为递增正整数；issued_at、expires_at 为 Unix 秒；indicators 是最多 1024 个包含 id、sha256、label 的对象。摘要必须为 64 位小写十六进制，ID 和摘要不重复。有效期最多 31 天，不允许浮点数、重复键或额外字段。

发布私钥必须对应本项目 release-public.pem；它只存在于独立发布环境，不能上传玄武或业务服务器。原文和私钥由发布账号控制，权限为 600。运行：

~~~sh
node scripts/sign-rules.js rules.json offline-private.pem signed-rules.json
~~~

脚本固定校验格式和兼容性，并生成 Ed25519 签名封装。目标文件必须不存在。签名提供真实性及完整性，规则摘要本身不加密。

## 玄武导入

将签名文件通过可信通道复制到玄武服务器 root 私有目录。在 sudo xuanwu 菜单 25 填写文件绝对路径；也可执行：

~~~sh
sudo xuanwu rules-sync /root/signed-rules.json
sudo xuanwu rules-status
~~~

玄武验签后写入 /etc/ironcurtain/cloud/runtime/rules.json，服务以只读文件访问。固定 /v1/rules 端点要求客户端证书及节点或 reader 令牌。云端没有签名私钥，不能制造合法新规则。

## 铁幕拉取

先通过 Linux 菜单导入节点加密身份包并核对 CA 指纹。sudo ironcurtain 菜单 25 主动拉取，26 查看状态；命令方式：

~~~sh
sudo ironcurtain rules-sync
sudo ironcurtain rules-status
~~~

原生客户端只访问已配对 HTTPS 主机的 /v1/connectivity 和 /v1/rules；验证主机名、mTLS、独立令牌、节点名称、两次响应的相同服务端证书，并限制总时间和字节数。拒绝重定向、超大响应、过期、不兼容和无效签名。当前更新需手动触发；宿主周期扫描继续独立运行。

## 激活与恢复边界

有效规则与独立签名高水位保存在 root 管理目录。激活用 Linux 进程锁串行化，先保留高水位，再原子替换规则。相同序号只接受完全相同内容；拒绝序号或版本回退，拒绝同序号不同内容。中断允许重试当前或更新的合法规则，不恢复旧序号。

同机备份恢复保留现行规则和高水位，清理过期命中日志，再按恢复后的实际文件扫描。高水位保护依赖宿主 root 和磁盘状态可信；root 被攻克并删除全部状态时需要独立可信记录与干净主机重建。

## 实际检测

宿主代理在配置的业务目录中按预算读取真实文件字节，计算 SHA-256，与已验签且未过期的规则比较，最多输出 8 条证据。命中记录和路径只在本机；玄武只收状态与摘要。缺规则、过期、预算不足、无法读取或规则损坏不会伪装为扫描安全。哈希只匹配已知的精确文件，变形文件和未知威胁需要其他检测来源。

哈希命中不授予网页删除或隔离权限，也不能绕过 ClamAV 固定描述符复扫和 root 人工处置边界。规则不能指定 shell、文件路径、自动解锁、删除、可信基线或改动防火墙。
