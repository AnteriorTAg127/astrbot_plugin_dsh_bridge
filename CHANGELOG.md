# Changelog

本文件面向使用者，记录发布版本的可见变更。
开发过程记录（每次改动、测试与调试）在 `开发/changelog.md`，不随仓库发布。

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

### 测试

- 金标准向量 §18.6 全部断言、密码学、重放窗口、握手失败分类、路由幂等、传输三件套真实 socket 端到端、任务/通知/审批/会话授权/图片生命周期、宿主身份归属与多模态判定、分层与提权扫描。
- 新增业务决策迟到答复回归：真实过期行 → 迟到真人答复被拒 → 超时扫描 → 再次扫描，断言仅一次 `timed_out` 回调、零人类 choice 回调，且扫描后状态为 `expired`。
- **当前快照（2026-11-01）**：A 全量单测 **427 passed**（28.27s）、B **377 passed**（33.63s）、A+B 业务回环 **24 passed**（248.38s）、跨传输 **26 passed**（160.19s）、独立密码学校验 **36/36**；B `tsc -p tsconfig.json --noEmit` exit 0。更早的 394/355、360/348/22 与 295/335、19 PASS / 7 `BLOCKED-IMPL` 记录已经作废，仅存档。真实宿主整机验收仍 `BLOCKED-ENV`。

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
