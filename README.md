# 亿格云 VPN 申请与使用核查 Skill

读取上传文件或 MCP 中的 VPN 申请表，通过亿格云控制台 HTTP 接口查询员工访问统计，按每条申请的生效区间核对实际流量。运行结束默认生成包含有流量、无流量、待确认及未核查记录的中文统计表和 JSON 证据。

也支持不提供申请表，直接查询指定员工最近 N 天的流量。

## 一条命令安装

先安装 Node.js 22.20 或更新版本，在终端执行：

```bash
npx skills add SEKKOO/eagleyun-vpn-activity-audit
```

按提示选择要使用的 AI 编程助手。默认安装到当前项目；安装到 Codex 的全局技能目录可使用：

```bash
npx skills add SEKKOO/eagleyun-vpn-activity-audit --skill eagleyun-vpn-activity-audit -a codex -g -y
```

安装工具及选项见 [skills 官方说明](https://github.com/vercel-labs/skills)。本仓库的技能目录是 [`eagleyun-vpn-activity-audit/`](eagleyun-vpn-activity-audit/)。

## 使用

在支持 Agent Skills 的助手中输入：

```text
使用 $eagleyun-vpn-activity-audit 读取我的 VPN 申请表，核查指定时间范围内每条申请生效期间的流量，并输出统计表。
```

助手会确认申请表来源、查询期间及账号类型。密码通过本地终端隐藏输入；独立子账号登录还需企业标识码。账号必须具有目标企业员工统计的读取权限。

默认统计表前七列为：姓名、申请VPN、申请时间、申请开始时间、申请结束时间、本次查询时间范围、查询时间范围内是否有流量。每条 VPN 申请独立保留，并附访问次数、原始流量、实际核查区间和异常说明。

只查询某位员工时可以输入：

```text
使用 $eagleyun-vpn-activity-audit 查询“示例员工”最近 7 天的零信任流量，时区为 Asia/Shanghai。
```

## 脚本运行环境

- Python 3.10+，以及本地 OpenSSL。
- Python 仅使用标准库；不依赖浏览器自动化、requests、pandas 或 AK/SK。
- CSV／TSV／JSON 可直接作为脚本输入；XLSX 或 MCP 结果由助手提取字段后转换。
- 默认连接正式环境。预发环境是独立配置，可能额外需要统一身份认证；不能直接复用正式环境凭据或会话。

克隆仓库后可以验证登录：

```bash
python3 eagleyun-vpn-activity-audit/scripts/vpn_audit.py check-login --environment production
```

完整命令、输入格式及状态说明见 [执行参考](eagleyun-vpn-activity-audit/references/execution.md)。

## 验证范围

正式环境子账号的独立 HTTP 登录、企业实例发现、员工统计读取及唯一姓名映射已有实测。离线测试覆盖分页、申请区间、身份歧义、空值处理和默认统计表导出：

```bash
python3 eagleyun-vpn-activity-audit/scripts/test_vpn_audit.py
```

控制台内部接口可能随产品版本变化。服务端精确时间端点、生产环境多页数据及实际申请表完整核查仍有待验证的部分，详见 [接口发现记录](eagleyun-vpn-activity-audit/references/api-discovery.md)。查询失败、缺少身份确认或数据覆盖不足时保留待确认状态，不直接判为未使用。

账号、密码和会话令牌不写入技能、日志或导出结果。统计仅用于核查，不自动关闭员工权限或修改审批记录。
