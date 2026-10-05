# 铁幕 / 玄武独立恢复

每个角色有自己的恢复密钥和恢复包。只由可信 Linux root 菜单或 CLI 发起；网页、云端节点不能执行恢复。菜单 22 创建，23 验证，24 同机恢复。角色命令为 `tiemu` / `xuanwu`。

```sh
sudo tiemu backup
sudo tiemu verify-backup
sudo tiemu restore-backup
```

后两项交互询问恢复包的绝对路径；恢复还要求输入 `SAME-HOST-RESTORE`。玄武把上述命令的 `tiemu` 换成 `xuanwu`。安装目录内的专用脚本支持可信运维自动化：

```sh
sudo bash /opt/ironcurtain/local/current/scripts/independent-backup.sh local verify-backup /绝对路径/local.icbackup
sudo bash /opt/ironcurtain/local/current/scripts/independent-backup.sh local restore-backup /绝对路径/local.icbackup SAME-HOST-RESTORE
```

备份前记录容器和宿主代理的原运行状态，停止写入，保存该角色 `/etc/ironcurtain/<role>` 和 `/var/lib/ironcurtain/<role>`；不包含受保护网站、APPGOG 或其他业务的数据库。完成后恢复原服务状态，可能产生短暂管理面板不可用。恢复密钥位于 `/opt/ironcurtain/<role>/recovery.key`（root:0600），不放进恢复包。密钥丢失无法解密；把包和密钥分别通过可信通道保存到异地。

包采用 OpenSSL AES-256-CBC / PBKDF2-SHA256 200000 次，另用独立派生认证密钥执行 HMAC-SHA256。先认证全部密文再解密，归档路径、权限、类型和容量全部验证后才停服。拒绝损坏密文、错误密钥、软硬链接、目录穿越、设备和超限文件。

只支持同一 machine-id、同一角色、相同安装 host/bind/image/version。普通恢复保留当前运行身份和管理凭据，玄武保留当前 CA、节点允许名单及撤销状态；旧恢复包不能恢复已撤销节点或旧登录密码。铁幕恢复保护范围与状态，但丢弃旧的可处置扫描证据，隔离前须重新扫描。

替换配置与状态前建立本机回滚事务；恢复失败会尝试回滚并检查实际服务状态。被替换目录与事务快照保留在 root 私有目录；未完成事务须恢复成功后再继续管理。仅本机加密包不能防范宿主 root 沦陷，事务快照也不是不可变备份。跨版本、跨机器身份迁移、对象存储锁定、干净主机重建与 RPO/RTO 演练尚未交付。

验收：Python 归档正反例和实际 Docker local/cloud 备份恢复、恢复后证书不变、撤销不复活、损坏包不写入不停止健康服务，由 Linux CI 执行。编写用例或 Windows 跳过不计为通过。
