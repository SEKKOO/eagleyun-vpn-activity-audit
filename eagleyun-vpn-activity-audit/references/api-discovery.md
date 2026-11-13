# 接口发现记录

记录日期：2026-11-13，Asia/Shanghai。

## 运行方式

用户明确要求：当前制作阶段识别页面背后的接口，后续运行技能通过接口直接完成登录、时间筛选和员工取数，不常规打开网页。

## 证据与验证级别

以下登录信息来自官方网站公开前端静态代码，尚未用真实凭据完成独立 HTTP 登录。代码证据不等同于统计接口请求捕获或鉴权端到端验证。

- 登录 HTML：`https://console.eagleyun.cn/login`
- HTML 声明的资源目录：`https://cdn.eagleyun.com/user/26.11.12-1/`
- 主包：该目录下的 `umi.js`。
- 登录分包：主包的分包映射声明 `p__Login-v2__index.async.js`。
- 版本及资源路径会变化，应从登录 HTML 和主包映射重新发现，不能将此版本固化为永久依赖。

## 登录接口的静态代码证据

登录页代码调用：

- URL：`https://console.eagleyun.cn/api/anon/usercenter/auth/login`
- HTTP 方法：POST。
- Content-Type：`application/json`。
- 可选 URL 查询参数：`redirect`，代码会进行 URL 编码。
- 主账号 JSON 字段：`account_master: "1"`、`login_name`、`password`。
- 子账号 JSON 字段：`account_master: "0"`、`corp_code`、`login_name`、`password`。
- `login_name` 先 trim，再加密；`password` 直接加密。`corp_code` 在已检查的调用点直接传递。
- 加密帮助函数使用 JSEncrypt：Base64 解码登录 HTML 中 `globalWebConfig.PUBLIC_KEY` 得到 PEM 公钥，设置公钥后调用 `encrypt`。不能把明文用户名／密码直接填入上述加密字段，也不能将固定密文当作可复用凭据。
- 登录请求辅助函数把 `data` 转成 JSON，以 fetch 发出请求并解析 JSON；仅当响应 `code === 200` 时返回 `data`，其他响应按错误处理。
- 登录后调用 `startCheck`，后续检查逻辑已在同一版本的 `274.async.js` 中定位：检查 `need_mfa_login`、`need_force_reset_pwd`、`password_expire` 和 `account_master`；正常路径跳转至 `redirect_url`，没有该字段时使用配置的 SASE_HOST。不能仅凭登录接口返回 HTTP 200 就宣布整个鉴权成功。Cookie、跳转链和跨子域会话仍需真实凭据实测。
- 登录代码包含服务协议接受逻辑，不能为了自动化擅自伪造用户未提供的协议同意。

另有环境读取接口：`GET https://console.eagleyun.cn/api/anon/usercenter/auth/env`。已实际发出匿名读取请求，返回了 JSON；这只能验证该环境接口可访问，不能证明已登录。

公开前端主包和统计页公共分包还确认：通过转发接口读取 `/openApi/v1/spa`，`data` 为企业实例数组；实例字段包括 `ins_id`、`idaas_ins_id`、`corp_code`、`private_model`。主包使用首项作为缺省实例，但附带客户端在多项时要求明确目标，避免自动选错企业。独立客户端目前拒绝未验证的私有模块路由。

2026-11-13 已执行附带客户端的 `inspect-login`：无需浏览器即可获取正式环境公开登录公钥，OpenSSL 可用，输出明确为 `authenticated=false`。这次检查没有提交账号或密码，不构成登录成功证据。

## 通用业务请求封装的静态代码证据

主包中通用请求帮助函数会向 `/console/v1/request` 发出 POST，传递：

- `method`：内部业务方法，转为大写。
- `path`：内部业务路径和查询字符串。
- `body`：业务请求体的 JSON 字符串，未提供对象 body 时为空字符串。

已检查代码还会在外层 URL 附加 `?path=...`，并可能根据 `private_model` 增加后缀；路径中的 `{ins_id}`、`{idaas_ins_id}` 使用实例信息替换。请求拦截器从 `csrf` Cookie 设置 `X-CSRF-TOKEN` 请求头。

已在 Chrome 统计页面实际观察到同类转发请求及 `method/path/body` 请求体。外层 HTTP 方法与 CSRF 逻辑另有公开前端代码证据；尚未独立验证最小必需请求头和完整会话获取链。

## 员工访问统计：已实际捕获

业务页面为 `https://spa.console.eagleyun.cn/report_center/zero_trus_risk`，目标组件为「员工访问统计」。

在用户授权的 Chrome 中，用户完成正式环境子账号登录，页面右上角显示「个人中心·子账号」。打开开发者工具 Network，清空历史请求，再把「员工访问统计」自身的日期从最近 7 天切换到最近 15 天，得到 2 个请求：员工统计与新增员工身份映射。未使用预发环境数据。

### 员工统计请求

捕获到的外层 URL：
`https://spa.console.eagleyun.cn/console/v1/request?path=/api/open/das/ztna/analysis/page_l4_access_employee`

外层为 JSON 转发请求，前端封装使用 POST；实际 Payload 为：

```json
{
  "method": "GET",
  "path": "/api/open/das/ztna/analysis/page_l4_access_employee?sort_list=[{\"sort_field\":\"total_bytes\",\"sort_type\":\"desc\"}]&start_time=1793206694&end_time=1794502694",
  "body": ""
}
```

上述时间仅是抓包样例，运行时替换为用户指定期间。两值相差 1296000 秒，即 15 天，表明相对范围使用秒级时间戳。绝对日期的端点包含规则尚未实测；整日查询需明确业务边界后再决定结束时间，不能自行宣称接口采用某一种包含规则。

成功响应的结构如下（员工 ID 已替换为虚构标识）：

```json
{
  "code": 200,
  "message": "successful",
  "detail": "",
  "data": {
    "page_info": {"current_page": 1, "page_size": 10, "total_num": 2},
    "rows": [
      {"access_count": 5995, "employee_id": "emp_example_a", "request_bytes": 14007658, "response_bytes": 387214750, "total_bytes": 401222408},
      {"access_count": 460, "employee_id": "emp_example_b", "request_bytes": 59500490, "response_bytes": 280673550, "total_bytes": 340174040}
    ]
  }
}
```

两行访问次数分别为 5995、460，总流量按 1024 换算后约为 382.6 MB、324.4 MB，与页面两行一致。流量原始单位为字节，不能只读取页面四舍五入的 MB。

本次正式环境清单请求未显式传页码或 page_size，服务端返回默认第 1 页、每页 10 条。样例总计 2 条，因此此样例完整。后续预发环境中已捕获显式分页请求，详见下节；不能将预发分页样例当作正式环境大列表验证。

### 分页：预发环境已实测

用户切换至新账号，并明确授权从当前页面捕获分页。当前页面为 `https://spa.console.pre.eagleyun.cn/report_center/zero_trus_risk`，右上角为「个人中心·子账号」，员工访问统计为最近 7 天、共 234 条，每页 10 条，共 24 页。

外层 URL 为：
`https://spa.console.pre.eagleyun.cn/console/v1/request?path=/api/open/das/ztna/analysis/page_l4_access_employee`

从第 1 页点员工统计自身的下一页，捕获到内部请求：

```json
{
  "method": "GET",
  "path": "/api/open/das/ztna/analysis/page_l4_access_employee?sort_list=[{\"sort_field\":\"total_bytes\",\"sort_type\":\"desc\"}]&start_time=1793937819&end_time=1794542619&page_num=2&page_size=10",
  "body": ""
}
```

实际响应业务码为 200，`data.page_info` 为：

```json
{"current_page": 2, "page_size": 10, "total_num": 234}
```

再清空网络记录并点击员工统计第 24 页，捕获相同时间、排序条件的请求，内部查询串改为 `page_num=24&page_size=10`。响应业务码为 200，`page_info` 为 `{"current_page":24,"page_size":10,"total_num":234}`，`rows` 中实际返回 4 个员工，页面下一页按钮禁用。随后恢复第 1 页，又捕获 `page_num=1&page_size=10` 的显式请求。

已确认：

- 请求页码字段为 **page_num**，从 **1** 起算；响应页码字段为 **current_page**。
- 每页数量字段为 **page_size**，本次请求和响应均为 10；其他大小及上限未经验证。
- 分页参数放在 JSON 的内部 `path` 查询串，外层 `path` URL 参数仍为不带这些业务查询参数的接口基础路径。
- 时间范围和排序在翻页时保持不变；不能在循环中重新计算「最近 7 天」导致各页窗口不同。
- 以本次响应的 total_num=234 和 page_size=10 计算应取 24 页，末页保留剩余 4 条。正式取数时还应核验累计条数、员工 ID 唯一性及每页响应页号。

此轮只核对了第 1 页请求、第 2 页请求与响应、末页请求与响应，**没有抓取或合并全部 234 名员工**。正式环境大列表及独立 HTTP 客户端中的全量分页仍未实测。技能中默认正式环境域名不因这次预发抓包而更改。

### 与目的地址用量的区别

本页底部「目的地址:端口 访问员工用量」也调用相同内部路径。已捕获此类请求额外带 `dst_domains`、`dst_ports`、`page_size=9`。完整员工清单请求没有这些限制，不能直接复用底部组件请求，否则会漏掉其他地址上的活跃员工。

### 员工身份映射请求

外层也是 `/console/v1/request?path=...`，内部 Payload 为：

```json
{
  "method": "GET",
  "path": "/openApi/v1/idaas/{idaas_ins_id}/search/getNameById?match_type=employee&ids={employee_id}&query_deleted=true",
  "body": ""
}
```

真实抓包使用当前企业的实际实例 ID 和员工 ID；此记录未保存这些固定值。`query_deleted=true` 是本次页面请求实测参数，用于保留历史员工身份可见性。

响应 `data` 为数组，已看到的字段包括：`id`、`match_type`、`name`、`display_name`、`employee_login_name`、`department`（含部门 `id` 和 `name`）、身份源对象等。部分登录名和显示名可以为空。通过 `id` 与统计 `employee_id` 关联；不能把身份源名称当作员工账号，也不能以空登录名或单一同名记录强行匹配申请人。本次只捕获单个 `ids` 值，批量传参格式尚未验证。

## 尚未完成的验证

首次由用户在本地终端执行默认 production、main 的真实登录测试，返回 code=1201012。公开主包的中文错误字典对应「账号/密码错误」，新登录服务模块 `48009` 对应 `credentialsInvalid:1201012`。当时脚本未标注具体请求阶段，不能只凭错误码确定根因。待核对账号所属环境与账号类型，并用已加入阶段诊断的脚本确认阻塞位置。此记录不保存用户提供的账号标识或任何凭据。

后续用户已明确：该账号为正式环境主账号。重新匿名获取正式环境登录 HTML，当前版本仍为 `26.11.12-1`，公钥与此前版本一致。使用官方主包中实际打包的 JSEncrypt 模块与本地合成 RSA 密钥进行了双向互通测试：官方模块能解密 OpenSSL 产生的 PKCS#1 v1.5 密文，OpenSSL 也能解密官方模块产生的密文，均通过；此测试没有使用用户凭据，也不证明服务器登录成功。匿名读取 `auth/list?account_master=1` 返回 code=200，方法列表包含 password。

用户已确认同一凭据在正式环境主账号网页登录成功；当前 Chrome 页面也显示「个人中心·主账号」。首次成功跳转的标签页没有保留登录前网络记录。随后已开启 Keep log，用户报告再次登录成功，但浏览器检查通道无法取得新的登录记录，因此尚未捕获可用于对照的成功登录 POST，不继续反复要求用户网页登录。浏览器此前保留的子账号企业上下文不能用来断定用户先前的账号类型选择有误。

官方登录模块 `48009` 和枚举模块 `23244` 确认主账号为字符串 `"1"`、子账号为 `"0"`；标准密码登录会先查询 `auth/list`，再提交加密字段。附带客户端原先仅对子账号查询登录方式，现已补齐主账号，并在方法不含 password 时停止提交。34 项离线测试通过，包括预查询先于密码提交及密码方式禁用时不提交凭据；这些不证明服务器登录成功。尚无证据确定 1201012 的具体根因，不将其标为已修复；下一步为更新后的独立 HTTP 登录复测。

- 用安全输入的账号密码，在独立 HTTP 客户端中完成登录、跨子域会话、实例发现和 CSRF 后实际调用统计接口。
- 正式环境大列表与独立 HTTP 客户端的全量分页调用；预发环境的 page_num/page_size 及第 2、24 页响应已验证。
- 自定义绝对时间范围的边界语义。
- 主账号独立 HTTP 调用，以及子账号未显示企业标识码时所用的后端企业上下文。

用户后续补充：没有可用的独立开放 API，继续以页面实际使用的内部接口完成实现；已使用用户指定的预发环境新账号捕获分页。新账号必须重新确认企业与可见范围。时间边界在每次使用技能时向用户确认；申请人与接口员工通常同名，按姓名初步匹配，重名再核实。用户已明确「申请时间内」指每条 VPN 申请的「生效开始至生效结束」，据此核查该员工是否使用过 VPN；申请提交时间仅作为展示及追溯信息。

不能将 Chrome 已登录会话中的成功请求描述为独立脚本登录成功。Cookie、Authorization、密码、固定企业实例 ID 不写入此技能。用户后续在 Chrome 操作期间，原生控制工具连续提示用户仍在交互，因此停止继续控制；已捕获的上述 URL、Payload 和响应事实不受影响。

## 后续主账号复测与空值提醒

用户运行更新后的 production/main check-login，返回「员工统计响应结构不正确」。按该版本执行路径，登录状态检查、跳转及受保护的企业实例发现均已通过，失败发生在 code=200 的统计 data 结构校验。用户明确说明当前环境对应统计为空，要求增加空值提醒；本轮未取得原始空响应，具体 null 位于 data 还是 rows 未确认。客户端因此分别处理首个显式 null 响应与分页总数明确为零的 null rows，不自动接受字段缺失或中途空页。41 项离线测试通过，更新后的空值分支仍待在线复测。此记录不保存账号标识或凭据。

## 正式环境子账号独立 HTTP 登录及非空统计验证

2026-11-13 用户完成终端 check-login 后，通过当前聊天的终端读取工具核对最后一次实际执行：用户选择 sub，提供本次企业上下文并以隐藏输入提供密码。脚本输出 environment=production、authenticated=true、instance_confirmed=true、statistics_readable=true、sample_window_seconds=86400、sample_employee_count=3，随后正常返回 shell 提示符。据当前代码路径，该结果说明独立 HTTP 登录、登录状态检查、跳转、受保护的企业实例发现和该 24 小时统计区间的完整性检查均通过。此记录不保存账号、企业标识码、实例 ID 或凭据。

本次为非空数据、3 名员工的区间样例，没有验证多页生产数据、员工姓名映射、实际申请有效期核对、空值提醒分支或服务端时间端点语义。用户本次已要求忽略预发测试，故上述验证只计入正式环境。

## 指定员工最近 7 天直接查询验证

2026-11-13 用户完成 employee-activity 命令后，读取其生成的本地 JSON，确认 production、last_days=7、pagination_complete=true、matched_employee_count=1；查询区间相差精确 604800 秒。目标姓名通过当前企业身份映射唯一关联至统计员工 ID，访问次数及三项流量均为非空整数，请求与响应流量之和等于总流量。未把员工 ID、部门 ID 或凭据写入技能。此次验证不包含申请表有效期比对，server_end_mode 仍为 unverified。
