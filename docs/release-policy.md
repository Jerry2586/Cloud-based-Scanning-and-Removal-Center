# 独立安全项目发布与验收

程序版本由 package.json 定义，正式标签严格使用 vX.Y.Z。铁幕和玄武共享版本，安装时分别选择 local/cloud 角色；不改变 APPGOG 的业务发布。

候选分支 candidate/** 先运行三个质量闸门：接口与签名安装/事务测试、真实 Docker/systemd 部署、真实 ClamAV 的隔离测试库扫描。全部通过后使用 GitHub 保存的发布私钥生成六份候选附件并上传工作流制品。候选签名步骤不创建正式 Release。

六附件固定为版本化 .run、.run.sha256、.tar.gz、.tar.gz.sha256、release-manifest.json、release-manifest.json.sig。验签使用仓库固定 release-public.pem；检查清单身份、环境合同、两个真实摘要、两份校验附件、自解压头部及其载荷与 TAR 完全相同、归档路径无越界/重复/链接/特殊文件、包内版本匹配。签名私钥只在 runner 临时目录使用并清理，不进入程序或服务器。

候选附件回下载验证后，正式标签指向已验收的提交。正式发布工作流重复 Linux 质量闸门、生成签名包并发布；随后通过 GitHub API 解析真实标签提交，确认它与已验收提交一致，核对 Latest、正式状态和恰好六个附件，再从 Release 回下载并重复验证。验证报告和回取附件保存为工作流制品。附件下载支持 GitHub CLI 当前认证身份，也适用于私有仓库。

发布回取命令仅用于开发/发布环境：

~~~sh
node scripts/verify-published-release.js --tag v0.2.1 --expected-commit <已验收的40位提交> --output-dir <尚不存在的验收目录>
~~~

如果签名、包内版本、标签、安装或回取验证失败，发布不能记为验收通过；修复后重新进入候选流程，不强推已发布标签。程序更新通过固定引导器，或由本地 root 菜单从玄武拉取、独立验签后安装；规则自动同步只更新数据规则，不自动运行新程序。候选与正式工作流均执行 root 文件缓存与快照边界测试，真实 Docker 部署验收包含云端菜单导入、损坏包拒绝与签名程序激活。

官方病毒库公网获取有独立的人工触发工作流 Accept official antivirus database retrieval。它在一次性 Linux runner 调用真实 systemd 更新器、验证官方 CVD/CLD、加载并扫描正常与 EICAR 测试样本。CDN、限流或超时直接失败，不能改用测试库冒充联网成功。它与常规真实引擎的确定性测试分别报告。

能力与未验环境以 capability-status.md 为准。正式签名程序交付不等于生产已部署、跨机验收、云端程序灰度或异地灾难恢复全部完成。
