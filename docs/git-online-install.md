# Git 在线安装：空服务器也能直接运行

README 中 local/cloud 的代码框是一个完整命令。复制从 `sudo sh -s` 到 `IRONCURTAIN_INSTALL` 的所有行，一次粘贴到 Linux SSH 终端。任何目录都能运行，不要求服务器已有 `install.sh`、源码或 Git。

## 首次准备

1. 登录 GitHub，为 `Jerry2586/Cloud-based-Scanning-and-Removal-Center` 创建只读细粒度 Token，只选择此仓库，授予 `Contents: Read`。如仓库受组织审批或 SSO 约束，还需完成相应授权。
2. 在需要保护的服务器复制 README 的 local 完整命令；在独立安全服务器复制 cloud 完整命令。
3. 若匿名请求报 404/401，接下来 curl 会提示 `Enter host password for user 'Jerry2586'`，输入 Token，输入不显示。安装器随后再次隐藏询问同一个 Token，用于保存更新凭据；第一次 curl 的交互输入不会被保存。
4. 按提示填写域名或固定 IPv4，等待安装检查。以后使用角色菜单；更新分别运行 `sudo ironcurtain update` 或 `sudo xuanwu update`。重复 README 完整命令也会检查最新签名正式版本，并复用已经保存的有效 Token。

## 获取和更新的边界

入口从 GitHub Contents API 获取固定提交 `ebceaf3a7a7aabd749f185f43c9b0c02deeadc62` 中的 `install.sh`，并校验固定 SHA-256。随后引导器下载 Latest 签名正式 Release，验证项目身份、Ed25519 签名、安装包摘要和安全路径。固定入口不代表固定程序版本。安装临时文件在 root 私有临时目录，执行结束清理，不覆盖 `/root/install.sh`。

公开仓库匿名请求成功时不用 Token；私有仓库必须获得授权。令牌只发送到固定 GitHub API，通过受保护的请求头文件或 curl 终端交互传递；不写进 URL、命令参数或下载日志，不随重定向转发。已有令牌必须是 root 所有、600/400 权限的普通文件，目录不能被其他用户写入或使用符号链接。

首次脚本只补齐 curl、CA 和基础校验工具。完整环境准备仍由引导器和角色安装器负责，支持范围见 README。系统软件源、DNS 或 HTTPS 不能访问时应修复网络；脚本不会关闭 TLS 或绕过签名。

当前 Latest 为 v0.4.0。本轮环境修复与在线入口在 main 源码中，尚未发布新的签名安装包；源码上传不能代替正式发布。使用本入口会获取当前正式包，不能声称安装了未发布修复。

## 常见问题

- `scripts/install-independent.sh: No such file`：复制了源码内部命令；空服务器应复制 README 的在线完整命令。
- `cannot open /root/install.sh`：服务器没有手动上传文件；在线入口无需这个文件。
- Token 无效或权限不足：确认 Token 选择此私有仓库并有 Contents: Read。若已保存的 Token 过期，通过可信终端更新 `/etc/ironcurtain/github-release.token`，恢复 root 所有与600权限后重试；不要将它发给助手。
- 签名、摘要或 HTTPS 失败：安装停止，检查可信发布源与网络，不能删除校验步骤继续执行。
- Git 已更新但程序仍是旧版本：更新入口读取签名 Release；应发布更高版本的正式包，不能替换同版本附件。

## 维护这些命令

入口源文件是 `scripts/git-install-entry.sh`；`node scripts/render-git-install.js` 生成 README 中两种角色的完整命令，`--check` 检查是否一致。CI 对渲染结果、固定摘要、下载失败和权限边界进行检查。修改固定引导器引用时先验收该提交，再同步 SHA-256；不要改成从 main 下载后直接执行。
