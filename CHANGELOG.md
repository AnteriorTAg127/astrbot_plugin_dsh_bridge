# Changelog

本文件面向使用者，记录发布版本的可见变更。
开发过程记录（每次改动、测试与调试）在 `开发/changelog.md`，不随仓库发布。

## [0.3.0] - 2026-11-06

通知落地、批量人工审批与管理员判定加固（A 端 R1/R2/R2b）。`LABEL`、密码学套件、AAD、封帧布局、错误码词表与金标准向量均未改变；数据库不加表、不加列，只在既有 `meta` KV 增加两个非 `schema_version` 键。**auto-review 未实现**（v0.4 待设计）；本版提供的是**批量人工审批**，不是自动批准。

### 新增

- **R1 落地会话（UMO）**：`Store.get_meta(key)` / `put_meta(key, value)` 读写既有 `meta` 表，`schema_version` 由 `init()` 独占并拒绝被覆盖。管理员在目标会话执行 `/dsh bind` 写入 `bridge_landing_umo`（值 = `event.unified_msg_origin`）与 `bridge_landing_meta`（平台 id、会话类型、绑定时间、绑定人）；`/dsh unbind` 幂等清除；`/dsh status` 与后台状态页显示当前绑定。入站任务通知的落点解析为：任务 `payload.umo` → **仅**全局 `bridge_landing_umo`；都没有时写 `info` 日志（`reason=no_umo`）、**不发任何消息**，并在任务本地 `error.details.degraded="no_umo"` 记录（不新增线上字段）。任务进入终态 `succeeded` 时清除此前遗留的该标记（只清 `degraded` 键，错误码语义不变）；若成功通知本身仍降级，会重新如实标注。`approval_notify_umo` 的优先级不变，**不会**被落地绑定接管；未显式配置时审批通知仍只落 Web 页。
- **R2 批量人工审批**：新增 `/dsh approve all [n]` 与 `/dsh reject all [n]`（管理员）。默认上限 20，显式 `n` 上限 50；每条都走既有 `ApprovalService.human_decide`（`actor_kind="human"`、`actor=astrbot_admin:<id>`、`channel="im"`），逐条输出 `approval_id`、类型/工具摘要与结果；单条失败（例如已过期）如实报告且不影响其它条。空队列返回明确提示。每条决定的 `decided_reason` 以固定前缀记录来源命令：`source_command=approve_all` / `source_command=reject_all`（附人工理由时为 `source_command=...; reason=...`），可 grep 审计；不新增协议/数据库字段。不新增任何自动批准路径，`agent` 来源仍一律拒绝。
- **R2b 管理员判定加固**：`_is_admin` 不再单独采信 `event.role`，必须同时满足：`sender_id` 非空、事件平台 id 非空且与 UMO 的平台段一致、`sender_id` 命中 `admins_id`。`admins_id` 支持平台限定写法 `"<platform_id>:<sender_id>"`（只匹配该平台实例）；裸 ID 仍保持 AstrBot 的全局语义，但同样要求平台 id 非空且自洽。
- **对端任务错误码宽容**：`task.event.error` 原样落库与展示，不做 §15 错误码白名单校验；对端任务级码（`agent_turn_failed`、`agent_output_missing` 等）不会改变状态判定，`/dsh tasks` 与后台页遇到未知码不会报错。

### 兼容与迁移

- 既有 `/dsh approve <id>` / `/dsh reject <id>` 行为不变；单条与批量共用同一人工决定路径。
- 数据库无结构变更：`bridge_landing_umo` / `bridge_landing_meta` 写入既有 `meta` 表，旧库直接可用；`schema_version` 保持 `3`。
- 行为变更（安全修复）：只把 `event.role` 置为 `admin`、或使用空 `sender_id` / 空平台 / 跨平台同号 id 的调用，不再被判为管理员。既有测试中依赖旧语义的 Event/Host double 已按新语义更新，未放宽任何断言。

### 诚实边界

- **auto-review 未实现**：本轮没有 `policy` / `auto_review_*` / `accept_policy_approvals` 代码或配置；批量审批仍由管理员在 IM 中逐条触发，只是把 N 次点击合成一次命令，**不是**自动批准。
- **落地绑定是单一全局值**：不做多级回退、不做按会话/按授权绑定，也不改写 `approval_notify_umo`。绑定后通知会以真实 IM 消息进入会话，并触发 AstrBot 的所有插件与指令处理器；第三方插件对消息来源的假设风险由部署方评估（v0.3 未消除，见 README「已知限制」）。
- **管理员的平台限定需显式配置**：裸 `admins_id` 条目仍是全局语义（AstrBot 既有约定），无法区分不同平台的同号 id；需要跨平台隔离时请写 `"<platform_id>:<sender_id>"`。平台 id 为 AstrBot 平台实例 id（`event.get_platform_id()`），不是平台类型名。
- 通知仍然只走进程内 `context.send_message`，不扩展 OpenAPI `im` scope；绑定 UMO 的平台实例不在线时按既有 `platform_unreachable` 处理，不消耗唤醒预算。

### 测试

- 新增 `tests/test_v03_admin_and_landing.py`（24 个用例），使用真实 `Store`/`ApprovalService`/`TaskService` + 临时 SQLite，仅 AstrBot 宿主为 double。覆盖：未绑定时零发送、`reason=no_umo` 日志、状态提示、任务本地降级标注与成功后退订；绑定后 `send_text` 的 UMO 逐字等于绑定值、重启（重开 Store）仍保留；非管理员 bind 拒绝且不写库；unbind 幂等；显式 `approval_notify_umo` 仍优先且落地绑定不会自动补位；3 条 pending 的 `approve all` 逐条 allowed-once/human、批量来源命令审计，空队列提示，过期单条失败不影响其它，非管理员零副作用，`agent` actor 仍拒；`agent_turn_failed` / `agent_output_missing` 任务错误码原样落库且状态为 failed；空 sender / 空平台 / 跨平台同号 / 未配置管理员 / 仅 role=admin / UMO 平台不一致均判否，正常裸 ID 与平台限定 ID 均判是，既有管理员指令回归。
- 先红：首轮 **14 failed, 6 passed（3.02s）**；final-gate 小修先红 **2 failed, 22 passed（3.47s）**。实现后 **24 passed（2.73s）**；A 全量单测（不含 `tests/integration`）**510 passed（37.28s）**。先红/后绿原始输出与改动清单见 `开发/v0.3/test/A-umo-batch-admin.md`。
- 为适配安全修复，更新了 `tests/test_session_authz_v02.py` 与 `tests/test_session_id_integrity.py` 的 Event/Host double（补 `get_platform_id()`、给 `admins_id` 配置、非管理员改用不同 sender id），所有原有断言保持不变。

## [0.2.0] - 2026-11-04

会话授权一致性与运维闭环（A 端 R1/R2/R4；R3 已移出 v0.2）。`LABEL`、密码学套件、AAD、封帧布局、错误码词表与金标准向量均未改变；数据库只做加列迁移。

### 新增

- **R1 授权权威实例标识**：`authz_meta.instance_id`（UUIDv4）与 `authz_meta.instance_started_at`（Unix 秒，首次建库时间）在同一条 UPDATE 中一次写入；同一数据库重启两者都不变，换库文件两者都变化。`session.authz` 的 `params` 增加**可选** `instance_id` / `instance_started_at` 且 A 始终携带两者，供对端识别“新权威的更低版本”并拒绝旧实例回放。新增 `tests/fixtures/session_authz_v02.json` 作为两端共享的规范化快照，A 侧用例断言线格式的键集合与类型与它一致。任一端缺少这两个字段时行为与 v0.1 完全一致（仍只按版本单调）。
- **R2 授权体检**：新增管理员指令 `/dsh sessions check [fix]`。在 READY 连接上调用对端 `session.list`（`state=any`、`limit=200`），与本地权威表对账，输出双方一致条数、仅本端有、仅对端有、本地 `version`/`instance_id`（标注「本端」）与对端 `authz_version`。`session.list` 应答没有实例字段，因此体检**不比对实例**。`fix` 在 `_create_lock` 内执行：先体检取对端版本，把本地版本抬到 **`max(本地, 对端) + 1`**（对端 `session.create` 也会抬高它自己的版本，简单 `+1` 仍可能被拒），再用**严格推送**路径重发 `session.authz`（失败抛出并如实报错，不显示成功），最后复检并报告 `after`。无 READY 连接时明确报“无法体检”，**不发送任何请求、无副作用**；对端错误原样透传，传输异常报 `capability_unavailable`。
- **R4 完整任务 ID**：`/dsh tasks` 输出完整 `task_id`（不再截断为 8 位），表头说明可直接用于 `dsh_task_status` / `dsh_select_session`。
- 文档与帮助同步：`/dsh help` 增加体检指令，README 更新指令/工具表、会话治理说明与已知限制。

### 兼容与迁移

- 数据库只加列（`authz_meta.instance_id`、`authz_meta.instance_started_at`），可从 v0.1 数据库直接升级，任务/审批/授权/通知不丢；`session.list`/`session.authz` 语义未变。
- 无参数 `/dsh sessions` 保持原列表语义；`/dsh tasks` 仅改变 ID 展示，不改变生成、幂等或存储。

### 诚实边界

- **体检不能证明 DSH 侧会话真实存在**：`session.list` 只反映对端授权表与活动状态，且没有实例字段（不比对实例）；`state=cold` 只表示对端没有活动 agent，不代表该会话不存在。体检只读对账，`fix` 只抬版并重推快照，不删除/新增授权。
- **实例排序依赖 A 主机时钟单调**：对端要求新实例的 `instance_started_at` 严格更大；若 A 重建数据库时系统时钟显著回拨，新实例会被判为更旧而被拒收。这是故障安全方向，需知情接受。
- **R1 的换实例接受规则生效在对端（B）**：只升级 A 端时，B 仍按 v0.1 的严格版本单调规则处理，A 重建数据库后的推送可能被判 `stale_authz`。本轮 A 侧验证了字段生成、持久化与跨端 fixture 契约，未做真实跨端运行验收。
- **未在 AstrBot 4.29.4 上真实运行验收**；本版本结论来自本机单测（A 486 passed、B 424 passed，2026-11-04），真实宿主/真实网络仍属 `BLOCKED-ENV`。
- **同秒重建**：`instance_started_at` 为秒级，同一秒内重建数据库会使新旧实例取值相等，对端按规则 4 拒收新实例（故障安全方向）；需清理对端 `authz/current` 后再推送，根因修复列入 v0.4（v0.3 未做）。
- **规则 0 可被本地记录丢失重新打开**：B 的 `authz/current` 被删除/损坏后，缓存无身份状态会再次触发一次性升级接受；加固（持久化「曾记录身份」标记）列入 v0.4（v0.3 未做）。

### 测试

- 新增 `tests/test_session_authz_v02.py`（16 个用例），使用真实 `Store`/`SessionService` + 临时 SQLite，仅把活动连接替换为记录型 double。覆盖：同库重启两实例字段不变、新库两者都变化且 version 从 0 起、`snapshot()`/`authz_message()` 携带两字段且键集合/类型等于跨端 fixture、`authz_snapshot()` 同事务读、v0.1 库双列迁移；体检一致/双向差异/过期授权排除/无 READY 会话零请求/对端错误透传与传输异常包装；非管理员 `check`/`fix` 零对端调用；`fix` 对端版本更高时抬到 `peer+1`、严格推送失败如实报错、`fix` 与 `create_peer_session` 并发不丢 grant；同前缀 `task_id` 在 `/dsh tasks` 中可区分。先红 **7 failed, 9 passed（1.71s）**，实现后 **16 passed（1.78s）**，A 全量 **486 passed（34.05s）**，未跑 integration。

## [0.1.0] - 2026-10-30

首个版本。实现 `dsh-bridge/v1` 协议的 A 端（AstrBot 插件），可与 DSH 侧插件建立受控的对等双向通道。

### 新增

- **协议实现**：`jcs_ascii`/`jcs_frame` 规范化、PSK→主密钥、HKDF 方向密钥、ChaCha20-Poly1305 封帧、64 位重放窗口、四步握手（`hello`/`hello_ack`/`auth`/`auth_ack`）与能力协商。
- **三种传输**：WebSocket（ws/wss）、HTTP Webhook、HTTP 长轮询；统一封套与状态码。**载体启动失败**时按配置顺序回退并在状态页留痕；已连上之后因 Webhook 回投探测连续失败触发的降级切换已真实接线（`TransportManager.carrier_degraded()` → `_switch_to_fallback()`），回环用例有通过记录；真实跨机回投与真实网络下的回退仍未验证。
- **对等双向任务**：`task.submit` 立即返回 `accepted`/`pending_approval` + `task_id`；`task.status`/`task.list_open`/`task.cancel`/`task.event`；状态机严格校验。
- **持久化与幂等**：SQLite 存储任务、事件、审批、决策、会话授权、唤醒计数与通知 outbox；`(conn, task_id)` 与 `(conn, m, id)` 幂等；通知至少一次投递 + `notify_id` 去重 + 退避重试。
- **不确定不重放**：执行中断线或提交未确认的任务置 `needs_human`，重启后不自动重跑，由人决定重试/放弃。
- **人工审批与业务决策**：三类审批统一入队；A 侧审批队列内同一 `approval_id` 首个答复生效；超时一律拒绝；Agent 不能代批/代答；`unavailable`/`cancelled` 按拒绝处理。注意：DSH 原生审批在 B 侧是 claim-or-hand-back，本地 UI 与远端人类不会同时对同一请求作答，这与原始需求「双方都能答、先答者胜」**不等价**，该竞争语义仍未满足。
- **跨端提交摘要校验**：`submit_digest` 保证“批准的内容 == 提交的内容”。
- **会话授权**：A 侧为授权权威，`session.list/create/select/manage` 与 `session.authz` 下发；Agent 在配额内创建会话自动授权（`agent_auto` 标记），超配额拒绝；支持一键回收。
- **图片输入**：仅任务显式附件；四类 MIME 白名单、字节/张数/像素上限、魔数与尺寸校验、分块传输与整图摘要；外部 URL 与聊天历史图片一律拒绝。视觉判定读 provider 的 `modalities`，但**只有显式包含 `"image"` 才算支持**：缺失、空列表或格式错误一律 fail-closed；不支持时图片替换为文本占位符并在 `result.degraded` 记 `model_without_vision`。
- **唤醒防循环**：每个根任务自动唤醒链上限 8 次、限速 10 次/分钟，计数持久化；命中即转 `needs_human`。自动唤醒投递前复查会话归档状态，归档会话直接跳过，不发送 IM、不消耗唤醒链/限速预算。
- **依赖声明**：新增 `requirements.txt`，只列出运行时代码实际 import 的第三方库（`aiohttp`、`aiosqlite`、`cryptography`、`httpx`），最低版本对齐宿主 AstrBot 4.29.3 的 `pyproject.toml`。
- **后台状态页**：中文界面四块（连接状态 / 会话授权 / 任务进度与结果 / 决策与审批），不显示任何密钥；写操作要求 Dashboard 登录身份。
- **指令与工具**：`/dsh help|status|tasks|sessions|approve|reject`；LLM 工具 `dsh_submit_task`/`dsh_task_status`/`dsh_list_sessions`/`dsh_create_session`/`dsh_select_session`。

### 修复

- **业务决策超时结算**：真人答复若晚于 `expires_at`，一律返回 `expired` 且不生效；该 pending 行不再由迟到答复自行改成 `expired`，而是留给唯一的超时扫描落定，超时回调最多触发一次，不会因迟到答复抢先改状态而丢失。
- **后台开关文案**：`dashboard_enabled` 仅控制后台后端接口注册；关闭后宿主仍会扫描 `views/bridge/` 入口，页面内对应的后端接口请求会 404。README 与 `_conf_schema.json` 已按此校正。
- **LLM 工具宿主契约（v0.1 热修，不改变版本）**：五个 `dsh_*` 适配器改为真正的 `FunctionTool` 子类，`handler` 指向实例 `__call__`，`handler_module_path` 由宿主 `Context.add_llm_tools` 写入。修复裸类缺少 `handler` 时宿主 `_PermissionGuardedTool`/`PluginManager.load` 触发 `AttributeError` 的问题；保留原有参数、权限/审批与显式 `session_id` 语义。该结论仅在本机 AstrBot 4.29.3 的宿主契约测试中验证，**未在用户报告的 4.29.4 上真实运行验收**，截图只能说明契约一致。
- **初始化局部失败清理**：`initialize` 在 `Store.init` 之后任一步骤失败（含取消）时先 `await terminate()` 再重抛原异常；清理本身失败不掩盖原异常。`terminate` 保持幂等并重置工具注册标记。没有用户失败日志，不能据此宣称所有间歇性 reload 问题均已解决。
- **会话 ID 完整性与选择语义（v0.1 热修，不改变版本）**：`dsh_list_sessions` 与 `/dsh sessions` 改为输出完整 UUID，不再显示 `session_id[:8]`；共享前 8 位的两个授权会话因此可区分，列表中的值可直接用于选择。`dsh_select_session` 仍只接受授权范围内的完整 UUID（不支持前缀、不自动选第一个、未授权/已撤销同码拒绝），但文案与工具描述改为**只校验、不绑定**：pending 任务与审批 `submit_digest` 在人工批准前已落盘，事后改写会改变已批准内容，所以本热修不实现任务绑定，也不谎称已绑定。显式 `session_id` 仍原样进入任务审批门，缺省继续拒绝。
- **Agent 创建不再是本机幽灵会话（v0.1 热修，不改变版本）**：`dsh_create_session` 改为先通过活动连接向对端 `session.create`，**只授权对端返回的 `session_id`**；无 READY 连接、对端超时、`session_create_denied`、`session_quota_exceeded`、`capability_unavailable`、`unknown_message` 等失败一律返回且**不写本地授权**。同一 `request_id` 只往返一次；出站幂等键加方向前缀，与对端选定的入站键隔离（入站键占用该前缀会被拒绝）；管理员撤销后重放同一创建键会失败关闭，不会复活会话。另用对端返回的 `authz_version` 抬高本端版本下限（只增不减），保证随后的权威推送（含撤销）不会被 B 当成 stale 丢弃。入站 `session.create` 仍按原语义惰性本地建会话（AstrBot 按需创建），两条路径代码与注释分开。升级前旧代码留下的授权行不会自动清理，需管理员在状态页撤销。

### 测试

- 金标准向量 §18.6 全部断言、密码学、重放窗口、握手失败分类、路由幂等、传输三件套真实 socket 端到端、任务/通知/审批/会话授权/图片生命周期、宿主身份归属与多模态判定、分层与提权扫描。
- 新增业务决策迟到答复回归：真实过期行 → 迟到真人答复被拒 → 超时扫描 → 再次扫描，断言仅一次 `timed_out` 回调、零人类 choice 回调，且扫描后状态为 `expired`。
- 新增 `tests/test_llm_tool_host_contract.py`：使用真实 `Context.add_llm_tools`、`FunctionToolManager.get_full_tool_set`、`_PermissionGuardedTool`、`FunctionToolExecutor.execute` 覆盖五个工具的参数/事件/显式 session 原样转发、权限拒绝不触达业务方法、重复注册去重、停用保留行后新实例重绑不误归属、真实 `_unbind_plugin` 按模块路径移除、`terminate` 两次、同实例重新 `initialize`、局部失败/取消/清理失败三条异常路径。修复前该文件在真实执行路径稳定复现 `AttributeError: 'DshSubmitTaskTool' object has no attribute 'handler'`。
- 新增 `tests/test_session_id_integrity.py`（6 个用例）：真实 `Store`/`SessionService`/`TaskService`/`ApprovalService` + 真实工具适配器，覆盖两个同前缀授权会话的完整 UUID 展示、`/dsh sessions` 管理员展示、完整 UUID 通过而唯一前缀仍被拒、select 不改写 pending 任务/审批摘要、显式 `session_id` 原样进入审批门、工具描述不声称绑定。修复前 **5 failed, 1 passed（1.20s）**，修复后 **6 passed（0.58s）**。
- 新增 `tests/test_peer_session_creation.py`（22 个用例）：真实 `Store`/`SessionService` + 记录型 live session。覆盖对端 id 才被授权、无 READY 连接/对端超时/拒权/配额/未知消息/传输异常/畸形应答均零授权、同 `request_id` 只往返一次、对端重放复用同一 grant、撤销后重放同一创建键不复活会话、推送版本严格高于对端返回版本、版本下限只增不减、策略/配额先于对端往返拒绝、入站 create 仍本地惰性铸造、入站键不得占用出站命名空间、以及 `main.py` 装配把 live provider 接到 `llm_create_session`。首轮红测为前 20 个用例、**20 failed**（`create_peer_session`/`set_session_provider` 尚不存在）；补充命名空间隔离与撤销重放两个回归后 **22 passed（1.13s）**。
- **当前快照（2026-11-03）**：A 全量单测 **470 passed**（32.32s，含本热修 22 个 peer-first 创建用例）、B **377 passed**（35.03s）、A+B 业务回环 **24 passed**（254.83s）、跨传输 **26 passed**（165.26s）、独立密码学校验 **36/36**；B `tsc -p tsconfig.json --noEmit` exit 0。更早的 394/355、360/348/22 与 295/335、19 PASS / 7 `BLOCKED-IMPL` 记录已经作废，仅存档。真实宿主整机验收仍 `BLOCKED-ENV`；用户环境 4.29.4 未真实运行验收。

### 安全

- 无 TLS 也强制认证握手 + AEAD；`seq` 单写锁保证每方向单调且不复用；重复/越窗/篡改一律断链。
- PSK 从不明文上线；AstrBot OpenAPI Key 仅存在于本进程与本机配置，不入库、不跨端、不写日志、不在界面展示。
- 不使用 `data` 与 `chat:admin` scope；不伪造管理员身份；**不创建/不修改/不触发任何 cron 任务**（避免 `origin=api` 提权面）。
- 管理员在 IM/后台直接下达的命令由 AstrBot 自身权限模型判定，桥接不介入；LLM/Agent 发起的敏感动作必须先经人工批准。

### 已知边界

- **真实环境一律 BLOCKED-ENV**：真实 AstrBot 宿主内的完整装配、真实 IM 平台、真实 OpenAPI/SSE 流、真实 LLM 多模态判定与真实 TLS 均未验证；现有结论只来自单测与回环 socket。
- **本端监听已独立**：`conn_bind_addr`/`conn_bind_port` 与对端 `conn_host`/`conn_port` 已拆分，A 可作 `listen` 或 `connect`；同机多连接仍不得抢同一 `conn_bind_port`。
- **Webhook 已可用，但要求显式双端端点**：`connect` 侧必须显式 `conn_bind_port > 0`，跨机时 `conn_bind_addr` 必须是本机可达地址（`0.0.0.0`/回环会被 `_reachability_problem()` 拒绝）；真实跨机回投仍未验证。A 侧**没有**“对端 == 自己”自检（该保护在 DSH 侧），`listen` 的 `conn_host` 填错会表现为帧回环和探测失败。
- **`connections` 只有第一条生效**，多连接尚未接线。
- **降级回退已接线**：`carrier_degraded()` → `_switch_to_fallback()` 已真实调用并有回环用例；真实跨机 Webhook 探测失败后的回退仍未在真实网络验证。
- **`approval.lookup` §12.7 已实现**：接收端无本地证据时向发起端查询权威证据，查询前后复核会话与已协商能力，持久 `peer_lookup` 镜像并原子消费一次；只有 `approval_evidence_missing` 原样透传，其余远端错误统一 `approval_lookup_failed`。未知/未协商 `peer_caps` 直接拒绝查询。真实宿主内的最终验收仍属 `BLOCKED-ENV`。
- **宿主边界与 main 接线已集成**：`main.py` 的通知渠道过滤、按会话解析 provider、`can_write`、`wake_lock` 与 `bind_peer_caps(session.peer_caps)` 均已真实接线，并有装配回归覆盖。真实宿主整机联调仍属 `BLOCKED-ENV`，不能据此宣称生产可用。
- **原生审批的“先答者胜”未满足**：B 侧实际为 claim-or-hand-back，与原始需求“双方都能答、先答者胜”不等价。
- `approval_notify_channels` 中的 `im` 决定是否尝试 IM 通知；实际发送还要求本机有可用的 IM 平台并配置 `approval_notify_umo`，否则只落 Web 页（这是正常降级，不是失败）。
- 双方都不可达（双 NAT、无公网入口、无隧道）时无法连通，插件只给出可读诊断，不无限重试。
- 首版“DSH 调用 AstrBot 工具”经 A 侧 Agent 会话承载，不提供直连工具 RPC。
- 无 IM 平台的部署中，审批通知只落 Web 页（正常降级）。
- 首版仅支持图片，不做一般文件/音频/视频传输。
