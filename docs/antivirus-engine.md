# 铁幕本地病毒引擎

独立 local 安装默认从系统已配置的软件源安装 ClamAV，建立专属病毒库和更新定时器。云端角色不安装宿主病毒引擎。离线可使用 --antivirus skip；跳过或下载失败时面板明确显示不可用。

在 Linux 输入 ironcurtain 打开菜单，可安装引擎、更新官方病毒库和查看状态：

~~~sh
sudo ironcurtain engine-install
sudo ironcurtain engine-update
sudo ironcurtain engine-status
~~~

引擎包由 apt/dnf 受信任软件源提供；缺包时停止，不自动添加未知源。病毒库位于 /var/lib/ironcurtain-antivirus/database，专用无登录账户 ironcurtain-av 写入。freshclam 使用固定官方镜像和 TestDatabases 检查，定时器每六小时触发并加入随机延迟。真实日志通过 journalctl -u ironcurtain-antivirus-update.service 查看。

0.2.0 的官方库测试暴露 Ubuntu AppArmor 拒绝 freshclam 读取专属配置的故障。0.2.1 候选在保留发行版策略和管理员规则的前提下增加专属路径授权：仅读取本产品的更新器配置、读写并锁定专属数据库目录；不关闭 AppArmor，不替换发行版 freshclam.conf。未知策略、符号链接、共享可写文件或策略加载失败时停止。已安装节点升级时也核对并修复这组策略；engine-update 使用相同检查。官方联网库验收 37182808096 已通过：三个官方库逐个验签，正常样本通过、EICAR 被检出；dnf 与其他架构仍需单独验收。

面板区分未安装、库缺失/异常、过期、元数据配置完成和定时更新停用/失败。库时间来自 CVD/CLD 元数据；元数据检查不证明签名或查杀效果。实际扫描限定专属库，由 ClamAV 加载并检查文件。浏览器和云端不能安装宿主软件、指定任意库路径或执行命令。

root 菜单隔离需使用固定扫描证据和重新扫描后的文件描述符，复制校验后再移除原文件。权限、目标范围和恢复限制见 independent-recovery.md 与 security-center-architecture.md。程序升级回滚保留引擎和官方数据库。

常规 CI 使用真实 ClamAV 和明确隔离的测试特征库，不能代替官方库公网下载。独立官方库闸门实际运行 systemd 更新器，验证 main/daily/bytecode 签名，再扫描正常与 EICAR 样本；失败必须明确记录。
