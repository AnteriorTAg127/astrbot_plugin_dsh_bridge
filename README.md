# AstrBot ↔ DSH 桥接（astrbot_plugin_dsh_bridge）

在 **AstrBot** 与 **DSH（DeepSeek Harness）** 之间建立受控的**对等双向**通道：任一侧都可以发起任务、也都可以执行任务，并把任务结果、业务决策与人工审批回传。

- **对等**：没有主从。两端使用同一套消息、同一套状态机、同一套密钥派生，差异只有方向密钥与 `side`。
- **加密不依赖 TLS**：无 TLS 时也必须完成 PSK 持有证明握手，之后所有消息走 ChaCha20-Poly1305。**任何模式都不出现 `Authorization: Bearer`、URL 密钥、明文 PSK、明文图片。**
- **不重复执行**：任务 `task_id` 幂等，通知至少一次投递靠 `notify_id` 去重；**执行状态不确定的任务一律转人工，绝不自动重跑**。
- **审批只能人批**：Agent 不能代批、超时一律按拒绝处理。

> 本插件是协议的一端实现。另一端（DSH 插件）在独立仓库
> [`dsh-plugin-astrbot-bridge`](https://github.com/AnteriorTAg127/dsh-plugin-astrbot-bridge)。
> 协议主本 `开发/v0.1/protocol.md` 属于**内部开发工作记录，不随公开仓库/交付包发布**；
> 公开可复核的金标准向量是本仓库 [`tests/fixtures/protocol_vectors_v1.json`](tests/fixtures/protocol_vectors_v1.json)。

**版本状态**：插件 `v0.1.0`（`metadata.yaml` 的 `astrbot_version` 为 `>=4.16,<5`）。对端 DSH 侧插件同为 `0.1.0`，面向 `@deepseek-ai/dsh` **`0.2.1-rc.2`**。本地测试环境为 **AstrBot 4.29.3 / Python 3.12.16**，未在其它 AstrBot 版本上实测。主要功能已实现，但仍有待真实环境验证项（见文末「已知限制与未验证项」）；**当前快照（2026-11-01）**：A 全量单测 **427 passed**、B **377 passed**、A+B 真实 socket 业务回环 **24 passed**、跨传输 **26 passed**、独立密码学校验 **36/36**，B `tsc -p tsconfig.json --noEmit` 通过。**真实 AstrBot 宿主内的整机联调、真实 OpenAPI/SSE 流、真实 IM 平台、真实 LLM 多模态判定与 TLS 均未验证（BLOCKED-ENV）**。部署前请先读文末「测试现状」与「已知限制与未验证项」。用户命令统一写成**单行 PowerShell**；`tests/integration/` 中的跨传输 harness 仅支持 POSIX（依赖 `/proc` 与进程组信号），Windows 原生环境不宣称跑通含 integration 的全量，请改用 WSL 执行（命令仍为单行 PowerShell，见「开发」）。

## 功能

- **三种传输**：WebSocket（ws/wss）、HTTP Webhook、HTTP 长轮询；**载体启动失败**时按配置顺序回退，并在状态页留痕。已连上之后因 Webhook 回投探测连续失败（3 次）触发的降级切换已接线（`TransportManager.carrier_degraded()` → `_switch_to_fallback()`），跨语言回环用例有 PASS 记录；真实跨机回投仍属未验证。
- **对等双向任务**：A→B 与 B→A 完全对称；提交**立即返回** `accepted` / `pending_approval` + `task_id`，结果异步回传。
- **持久化与幂等**：任务、事件、审批、授权、唤醒计数存 SQLite（`data/plugin_data/astrbot_plugin_dsh_bridge/bridge.db`），重启不丢。
- **人工审批与业务决策**：三类审批（业务决策 / 跨端提交 / DSH 原生工具）统一进 A 侧待审批队列；**A 侧队列内**同一审批首个答复生效。DSH 原生审批采用 B 侧 claim-or-hand-back，本地 UI 与远端人类并不会同时对同一请求作答——这与原始需求「双方都能答、先答者胜」**不等价**，该竞争语义仍未实现（见「已知限制与未验证项」）。
- **会话授权治理**：A 侧是授权权威；Agent 在后台授予的**创建配额**内创建会话即自动授权（带审计标记），超配额拒绝；归档会话在 `task.submit` 处按 `session_archived` 拒绝，自动唤醒投递也会跳过归档会话（不再消耗唤醒链/限速预算）。
- **图片输入**：仅任务显式附件，四类 MIME、字节/张数/像素受限，魔数校验；**绝不**抓取任意外部 URL 或聊天历史图片。
- **中文后台页**：连接状态、会话授权、任务进度、审批四块，**不显示任何密钥**。

## 安装

1. 把本目录放到 AstrBot 的 `data/plugins/astrbot_plugin_dsh_bridge/`（或在插件市场搜索安装）。
2. 重启 AstrBot，或在 WebUI 的插件页重载插件。
3. 打开插件配置，按下节填写**连接**与（可选）**OpenAPI**。

依赖：运行时实际 import 的第三方库为 `aiohttp`、`aiosqlite`、`cryptography`、`httpx`，均随 AstrBot 宿主提供；仓库根目录的 `requirements.txt` 按宿主 `pyproject.toml` 的最低版本声明（`aiohttp>=3.11.18`、`aiosqlite>=0.21.0`、`cryptography>=44.0.3`、`httpx>=0.28.1`），供插件市场安装或宿主缺少依赖时使用，正常部署无需手动 `pip install`。插件声明 `astrbot_version: ">=4.16,<5"`，但这些版本下限对应实测的宿主 4.29.3；更早的 4.x 是否可用未实测。

## 配置

配置分四块：连接、本机 OpenAPI、审批与限流、图片，均可在 WebUI 插件配置中编辑。

### 1. 连接（必填，两端必须成对一致）

`connections` 是模板列表，每一项是一条连接：

| 配置项 | 默认 | 说明 |
|---|---|---|
| `conn_id` | `default` | 连接标识（协议里的 `conn`），两端**完全一致**；仅小写字母、数字、`_`、`-` |
| `conn_mode` | `connect` | `connect`（主动连出）或 `listen`（自建端口等待）。**两端必须相反** |
| `conn_transport` | `ws` | 首选传输：`ws` / `webhook` / `longpoll` |
| `conn_transport_fallback` | `["longpoll"]` | 回退顺序（首选载体**启动失败**或 Webhook **回投探测连续 3 次失败**时按序切换） |
| `conn_host` | `127.0.0.1` | **始终是对端**地址（两种 mode 都是）；Webhook/长轮询的回投目标、WS connect 的拨号目标 |
| `conn_port` | `8765` | **始终是对端**端口（两种 mode 都是） |
| `conn_bind_addr` | `0.0.0.0` | **本端**入站监听地址，与 `conn_host` 无关；默认监听**所有网卡**。只许本机访问就填 `127.0.0.1` |
| `conn_bind_port` | `0` | **本端**入站监听端口，与 `conn_port` 无关。`0` 的回退规则见下：listen 侧回落到 `conn_port`，connect 侧由系统分配临时端口；取值范围 `0-65535` |
| `conn_path` | `/dsh-bridge` | 路径前缀，两端一致 |
| `conn_tls_enabled` | `false` | 是否启用 wss/https（不启用也仍然全程加密） |
| `conn_tls_cert_path` / `conn_tls_key_path` | `""` | 仅 listen 侧需要的证书与私钥路径 |
| `conn_tls_fingerprint` | `""` | 对端证书 SHA-256 指纹；填了就强制校验，不匹配即拒绝 |
| `conn_psk_id` / `conn_psk_secret` | `""` | 预共享密钥。**两端一致**；留空则该连接拒绝建立（不会退化为明文） |
| `conn_allow_agent_create` | `true` | 是否允许 Agent 自动创建会话（配额内自动授权） |
| `conn_max_agent_sessions` | `10` | Agent 自动创建会话的数量上限，达到即拒绝，不自动扩容 |

> `_conf_schema.json` 里 `conn_host`/`conn_port` 的 hint 仍写着“listen 侧填本机绑定地址”，那是旧描述；实际行为以本表为准——两种 mode 的 `conn_host`/`conn_port` 都填**对端**，本端入口只看 `conn_bind_addr`/`conn_bind_port`。本次只校正了 `dashboard_enabled` 的说明，未改这两项 hint。

**本端监听 vs 对端回投（当前实现的实际行为，务必分开理解）**

A 侧把两件事拆成了两组字段，不要混用：

| 用途 | 字段 | 实际取值 |
|---|---|---|
| 本端入站监听（起 aiohttp server） | `conn_bind_addr` / `conn_bind_port` | `conn_bind_addr` 默认 `0.0.0.0`（所有网卡）；`conn_bind_port` 为 `0` 时：listen 侧回落成 `conn_port`，connect 侧由内核分配临时端口 |
| 向对端回投/拨号（Webhook `POST /frames`、长轮询 `GET /poll`、WS 拨号） | `conn_host` / `conn_port` | 两者都填**对端**的值，与 mode 无关 |

具体实现位置：`main.py` 的 `_connections()` 读 `conn_bind_addr`/`conn_bind_port` 并原样传入 `SessionConfig`；`bridge/transport/base.py::bind_target()` 决定 bind（显式 `bind_port > 0` 优先，否则 listen 用 `listen_port`、connect 用 `0`），`peer_base_url()` 只用 `conn_host`/`conn_port` 拼对端 URL。

- **跨机部署（ws / longpoll）**：`conn_bind_addr` 可保持默认 `0.0.0.0`（监听本机全部网卡），`conn_host`/`conn_port` 互填对端；`listen` 侧建议显式固定 `conn_bind_port`，否则 `0` 会回落到 `conn_port`（对端端口）作为本端监听端口。
- **跨机部署（webhook）**：两端都必须能被对端 `POST /frames` 到。`conn_bind_addr` 必须填本机实际可达的网卡地址，不能是 `0.0.0.0`/`127.0.0.1`/`::`（会被 `_reachability_problem()` 判为 `webhook_bind_addr_unreachable`）；`connect` 侧还必须显式设置 `conn_bind_port > 0`（`0` 会被判为 `webhook_bind_port_unset`），`listen` 侧也建议显式固定端口。`conn_host`/`conn_port` 仍填对端。
- **同机部署**：两个 `listen` 连接仍然不能占用同一个 `conn_bind_port`（会因端口占用启动失败）；`listen` 想回落到 `conn_port` 就把 `conn_bind_port` 留 `0`，但要确保两个连接的 `conn_port` 不同（`connect` 侧留 `0` 是临时端口，不回落到 `conn_port`）。
- **`listen` 侧的 `conn_host` 必须指向对端**，填成本机地址会让插件把帧回投给自己。A 侧**没有**“对端 == 自己”的启动自检（该保护只在 DSH 侧 `webhook` 载体实现），所以这种错配表现为握手后探测失败/帧回环，而不是启动报错。
- **Webhook 的额外启动校验**：`main.py::_reachability_problem()` 在首选或回退里含 `webhook` 时检查——connect 侧 `conn_bind_port == 0` 直接 `config_error: webhook_bind_port_unset`；对端非本机而 `conn_bind_addr` 仍是回环/通配（`""`、`127.0.0.1`、`localhost`、`::1`、`0.0.0.0`、`::`）则 `config_error: webhook_bind_addr_unreachable`。这是有意的 fail-closed；按上面的写法补全地址/端口即可。

**PSK 必须自行生成，本仓库不含任何真实凭据。** 下面两条都是**一行 PowerShell**，在任意目录执行即可；把输出分别填入两端的 `conn_psk_secret`，`conn_psk_id` 用任意非密钥标识（如 `astrbot-dsh`）：

```powershell
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

```powershell
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"
```

### 2. 本机 OpenAPI（要执行对端任务时才需要）

| 配置项 | 默认 | 说明 |
|---|---|---|
| `openapi_base_url` | `http://127.0.0.1:6185` | 仅供本插件调用本机 AstrBot，**不是**桥接通道 |
| `openapi_api_key` | `""` | 在 WebUI `设置 → OpenAPI` 创建，**只需 `chat`**（发图再加 `file`） |
| `openapi_key_id` | `""` | 该 Key 的 `key_id`（非密钥），用于启动时身份归属自检 |
| `addr_allow_private` | `false` | 是否允许 OpenAPI 地址为 RFC1918 私网；`127.0.0.1` 等本机地址始终允许 |

> **不要**给这个 Key 勾选 `data` 或 `chat:admin`。插件会拒绝使用它们，也不接受“能调通就当身份正确”。
> 若 `openapi_key_id` 与实际 Key 不匹配，插件会记录 `config_invalid` 并**禁用任务执行**，不会降级到更宽的权限。

### 3. 审批与限流

| 配置项 | 默认 | 说明 |
|---|---|---|
| `approval_timeout_seconds` | `1800` | 审批超时；**超时=拒绝**，不会自动批准 |
| `approval_notify_channels` | `["im","web"]` | 期望的通知渠道；只有列表含 `im` 才会尝试 IM 通知，且还需本机有可发送的 IM 平台并配置 `approval_notify_umo`，否则只落 Web 页 |
| `approval_notify_umo` | `""` | 审批通知的 IM 会话 UMO；已随 `_conf_schema.json` 暴露在 WebUI 配置面板，留空则只落 Web 页 |
| `wake_max_chain` | `8` | 每个根任务自动唤醒链上限，达到即转人工 |
| `wake_rate_per_minute` | `10` | 自动唤醒限速（按连接与会话滑动窗口，跨重启保留） |
| `task_retention_days` | `7` | 任务/审批/通知保留期 |
| `heartbeat_interval` | `30` | 无其他出站帧时每 N 秒发一次应用层心跳；连续 2 个周期无入站帧判定断线 |
| `reconnect_max_backoff` | `60` | 指数退避上限（首次 1 秒、逐次翻倍、±20% 抖动） |
| `dashboard_enabled` | `true` | **只**控制是否注册本插件的后台后端接口。关闭后这些 API 不再注册；AstrBot 宿主仍会扫描插件目录里的 `views/bridge/`，入口仍可能出现，但页面内对应的后端接口请求会 404。指令、LLM 工具与任务面仍然可用 |

### 4. 图片

`image_enabled`（默认 `true`）、`image_max_count`（4）、`image_max_bytes`（10 MiB）、`image_total_max_bytes`（20 MiB）、`image_allowed_mime`（png/jpeg/webp/gif）。

超限会**整条任务原子拒绝**，不会部分接收，也不会静默降采样。视觉判定读 AstrBot provider 配置里的 `modalities`，但**只有显式包含 `"image"` 才算支持**：`modalities` 缺失、为空列表或格式不对一律按不支持处理（fail-closed），与宿主自身「未配置即向后兼容接受图片」的行为**相反**。不支持时图片会被替换成文本占位符，并在结果的 `degraded` 里记录 `model_without_vision`，不会静默丢图。这与 DSH 侧「`inputModalities` 缺失即 unknown 并降级」的判定方向一致，但两端的配置来源不同（A 读 `provider_config.modalities`，B 读 `ctx.llm.resolveModelInfo(...).inputModalities`）。

## 传输选择与部署

A 侧已经把「本端监听」与「对端地址」拆成两组字段（`conn_bind_addr`/`conn_bind_port` 与 `conn_host`/`conn_port`），因此三种传输都可以在 A 侧充当 `connect` 或 `listen`。差别只在可达性：

| 传输 | 可达性要求 | A 作 `connect` | A 作 `listen` |
|---|---|---|---|
| `ws` / `wss` | **单向**：发起方能连到监听方 | 可用 | 可用（默认监听 `0.0.0.0`；`conn_bind_port` 为 `0` 时回落到 `conn_port`） |
| `longpoll` | **单向**：connect 侧只需向监听方发 `POST /frames` + `GET /poll` | 可用（无需反向可达） | 可用 |
| `webhook` | **双向**：两端都要能被对端 `POST /frames` 回来 | 可用，但必须显式 `conn_bind_port > 0`；跨机时 `conn_bind_addr` 必须是本机可达网卡地址 | 可用；跨机时 `conn_bind_addr` 必须是本机可达网卡地址，建议显式固定 `conn_bind_port` |

**Webhook 的启动校验**：首选或回退里只要含 `webhook`，`main.py::_reachability_problem()` 就会要求连接配置能表达出可回投端点——`connect` 侧 `conn_bind_port == 0` 直接 `config_error: webhook_bind_port_unset`；对端非本机而 `conn_bind_addr` 仍是 `""`/`127.0.0.1`/`localhost`/`::1`/`0.0.0.0`/`::` 时 `config_error: webhook_bind_addr_unreachable`。这是**有意的 fail-closed**，不是缺陷：把 `conn_bind_addr` 改成本机实际网卡地址、`conn_bind_port` 改成固定端口即可。同机测试时对端是 `127.0.0.1`，`conn_bind_addr` 可以用 `0.0.0.0`，但仍要显式 `conn_bind_port`。

**同机端口规则**：两个 `listen` 连接仍不能占用同一个 `conn_bind_port`；`conn_bind_port` 留 `0` 时 `listen` 回落到 `conn_port`，所以同机两个监听连接要分别给不同的 `conn_port`（或直接显式 bind 端口）。

**A 没有「对端 == 自己」自检**：DSH 侧 webhook 载体有该保护，A 侧没有。`listen` 时 `conn_host` 必须填对端；填成本机会表现为探测失败/帧回环，而不是启动报错。

**跨机写法**：A 的 `conn_host`/`conn_port` 始终填对端；A 自己的入口只在 `conn_bind_addr`/`conn_bind_port`。B 侧用 `peerHost`/`peerPort` 指向 A 的 bind 端点。此前「A 只监听 `127.0.0.1`、Webhook 两种 role 都不可用」的限制**已经不再成立**；Webhook 现在可以跨机使用，但要求两端都配置显式的、彼此可达的 bind 端点。

> 实现位置：`main.py::_connections()` 读取 `conn_bind_addr`/`conn_bind_port` 并原样传入 `SessionConfig`；`bridge/transport/base.py::bind_target()` 决定 bind（显式 `bind_port > 0` 优先，否则 listen 用 `listen_port`、connect 用 `0`），`peer_base_url()` 只用 `conn_host`/`conn_port` 拼对端 URL。`bridge/transport/manager.py` 的 `carrier_degraded()` → `_switch_to_fallback()` 已真实接线。

## 使用

### 指令（IM / WebChat）

| 指令 | 权限 | 说明 |
|---|---|---|
| `/dsh help` | 所有用户 | 帮助 |
| `/dsh status` | 管理员 | 连接、传输、对端版本、最近错误 |
| `/dsh tasks [n]` | 管理员 | 最近任务（`→` 本端发起 / `←` 对端发起） |
| `/dsh sessions` | 管理员 | 会话授权与 Agent 创建配额 |
| `/dsh approve <审批号>` | 管理员 | 批准**一次**（审批号可用前几位） |
| `/dsh reject <审批号> [理由]` | 管理员 | 拒绝 |

### LLM 工具

| 工具 | 说明 |
|---|---|
| `dsh_submit_task` | 提交跨端任务，立即返回 `task_id`（**不会**同步等结果） |
| `dsh_task_status` | 幂等查询任务状态 |
| `dsh_list_sessions` | 列授权范围内的会话（含用途） |
| `dsh_create_session` | 在配额内创建会话（自动授权） |
| `dsh_select_session` | 为任务选择授权会话 |

### 后台状态页

AstrBot 插件详情页 → 打开「bridge」视图。包含四块：

1. **连接状态**：模式、当前/首选传输、回退历史、对端可达性、PSK 与 OpenAPI 是否已配置（只显示“已配置/未配置”）、最近错误。
2. **会话授权**：会话、用途、授权来源（人工 / `agent_auto`）、到期、一键撤销、Agent 配额。
3. **任务进度与结果**：双向任务、状态、结果摘要或错误码、需人工任务的「重试 / 放弃」。
4. **决策与审批**：待审批项（类型、来源端、到期）与待决策项；批准一次 / 拒绝。已被答复的项再操作会提示“已被处理”。

> 写操作要求 **Dashboard 登录身份**。插件作用域 API Key 不能用于审批，避免任意插件 Key 代替人批准。
> 重试会生成**新的 `task_id`**（`meta.retry_of` 指向旧任务），不会重放旧任务。

## 工作流程

```
人/Agent(A) --dsh_submit_task--> A 插件
   |-- 校验参数与图片（MIME/字节/张数/像素）
   |-- 落盘 accepted，立即返回 task_id
   |== AEAD 封帧 ==> B 插件
   |                  |-- 幂等校验 -> 落盘 -> 执行
   |<== task.event（progress/completed/failed）==
   |-- 落盘 -> 状态页可见 -> 唤醒发起会话（链计数 + 限速）
```

- 断线重连后只做 `task.list_open` + `task.status` 对齐，**不重提交**。
- 对端返回 `task_not_found` 或调用超时的任务置 `needs_human`，由人决定重试/放弃。

## 故障排查

| 现象 | 处理 |
|---|---|
| 状态页显示 `config_error` + `psk_not_configured` | 两端 `conn_psk_id` / `conn_psk_secret` 未填或不一致 |
| `psk_mismatch` 一直重连 | 两端 PSK 不一致；确认 `conn_id` 也一致 |
| 连不上且无有效信息 | 检查 `conn_mode` 是否**相反**、端口/路径、防火墙 |
| 启动即报端口占用 / 连接建立不起来 | 同一台机器上有另一个 `listen` 连接占用了同一个 `conn_bind_port`（或未显式设置时回落到同一个 `conn_port`）；每个监听方要各用各的端口 |
| 反向帧回到自己、握手后立刻 `auth_required` / 探测失败 | listen 侧 `conn_host` 填成了本机地址；应填**对端**地址 |
| 配了 `connections` 但只有第一条生效 | 当前版本只为**第一条**连接建立会话，其余条目被忽略（多连接尚未接线） |
| Webhook 握手成功、随后探测失败 | 不是“预期不可用”：检查两端 `conn_bind_addr`/`conn_bind_port` 是否为对端可达的显式端点、`conn_host`/`conn_port` 是否填对端、防火墙是否放行；状态页会记录回退历史与 `carrier_degraded` |
| 任务不执行、日志提示 openapi | `openapi_api_key` / `openapi_key_id` 未配置或归属自检失败 |
| 审批页按钮不可点 | 未以 Dashboard 身份登录；插件作用域 API Key 无审批权 |

> 日志与代码注释为英文，界面文案为中文；日志中不会出现 PSK 或 API Key。

## 已知限制与未验证项

- **真实环境一律 BLOCKED-ENV**：未在真实 AstrBot 宿主进程内跑过完整装配，未接真实 IM 平台，未用真实 OpenAPI/SSE 流执行任务，未用真实 LLM 验证多模态判定，也未验证真实 TLS；以下结论都只能算单测/回环 socket 验证。
- **多连接**：`connections` 只有第一条会建立会话；同机多对端尚未支持。
- **Webhook 可用但要求显式双端端点**：A 已拆出独立的 `conn_bind_addr`/`conn_bind_port`，两种 role 都能跑 Webhook；但必须满足「两端都能被回投」——`connect` 侧显式 `conn_bind_port > 0`，跨机 `conn_bind_addr` 为本机可达地址。真实跨机回投仍未验证，只有回环测试通过。
- **自投保护**：对端地址自检（同端点 fail-closed 拒绝启动）在 DSH 侧实现；A 侧没有该自检，依赖人工把 `conn_host` 填对。
- **审批通知的渠道开关已生效**：`approval_notify_channels` 中含 `im` 时才尝试 IM 通知；实际发送还需本机有可发送的 IM 平台并配置 `approval_notify_umo`，否则只落 Web 页。`approval_notify_umo` 已在 WebUI 配置面板中，可直接填写。
- **main 侧接线已完成**：通知渠道过滤、按会话解析 provider、`can_write` 宿主写能力探测、`wake_lock` 唤醒串行化、`bind_peer_caps(session.peer_caps)` 均已在 `main.py` 真实调用，并有装配回归覆盖。仍须注意这些结论来自单测与回环 socket，真实宿主整机装配仍是 `BLOCKED-ENV`。
- **§12.7 `approval.lookup` 已实现并通过本轮两仓单测与真实 socket 业务回环**：接收端无本地证据时向发起端查询权威证据，查询前后复核会话、持久 `peer_lookup` 镜像并原子消费一次；失败/旧记录/换 sid/查询竞态一律 fail-closed。未知或未协商 `peer_caps` 现在直接拒绝远端查询，不再乐观尝试。真实宿主内的最终稳定验收仍属 `BLOCKED-ENV`。
- **宿主边界已接线，但真实宿主验收未完成**：宿主适配层与 `main.py` 的接线已由单测、业务回环与跨传输用例覆盖；真实 AstrBot/DSH 进程内的整机验收仍以 `BLOCKED-ENV` 记录，不能据此宣称生产可用。
- **原生审批的“先答者胜”未实现**：原始需求要求本地 UI 与远端人类都能作答、先答者胜；B 侧实际采用 claim-or-hand-back（本地或远端二选一），与“先回答者竞争”**不等价**，该需求仍未满足。
- **类型与验收**：没有独立的类型检查门禁；历史跨端快照里的 19 PASS / 7 `BLOCKED-IMPL` 与更早的 295/335 条数字均已过时，只作存档。当前快照为 A 427 / B 377 / business 24 / cross 26 / crypto 36/36（2026-11-01），B `tsc --noEmit` 通过，真实宿主稳定验收仍 `BLOCKED-ENV`。
- **降级回退**：`TransportManager.carrier_degraded()` → `_switch_to_fallback()` 已真实接线，回环用例有通过记录；但真实跨机 Webhook 探测失败后的回退仍未在真实网络验证，不能据此宣称生产可用。
- 双方都不可达（双 NAT、无公网入口、无隧道）时无法连通，插件只给出可读诊断，不无限重试。
- 首版仅支持图片，不做一般文件/音频/视频传输。

## 开发

- **内部工作记录（不随公开包发布）**：协议主本 `开发/v0.1/protocol.md`（`dsh-bridge/v1` + 2026-10-31 的 §12.7 `approval.lookup` 证据契约增补；`LABEL`、密码学套件、AAD 与向量未变，与另一端逐字节一致）、开发规范 `开发/rules.md`、任务拆分 `开发/v0.1/分工.md`、过程记录 `开发/changelog.md`。这些路径只用于内部追溯，公开交付包按「发布与打包」排除 `开发/`。
- **公开金标准向量**：[`tests/fixtures/protocol_vectors_v1.json`](tests/fixtures/protocol_vectors_v1.json)（只读）。A 的 `tests/test_vectors.py` 与 B 的 `tests/vectors.test.mjs` 都以它为跨端共同基准；它随公开仓库与完整包发布。
- 分层（单向依赖）：`transport` → `session` → `app` → `host`，`main.py` 是唯一装配点

### 测试所需宿主依赖

| 依赖 | 要求 | 说明 |
|---|---|---|
| AstrBot 宿主 | 4.29.3（实测） | 运行时第三方库 `aiohttp`、`aiosqlite`、`cryptography`、`httpx` 由宿主提供，本仓库不 vendor |
| Python | 3.12.16（宿主 venv） | 单元/协议测试的 `pytest`、`pytest-asyncio` 来自宿主 dev 依赖 |
| Node.js | `>=22`（实测 `v24.20.0`） | 集成用例的 B 对端 `b_peer.mjs` 使用 |
| 对端 B 仓库 | 与 A 同级的 `dsh-plugin-astrbot-bridge` checkout | 集成用例需要；也可用 `DSH_BRIDGE_B_ROOT` 指定 |
| B 的 `node_modules` | 由真实 DSH 宿主依赖环境提供（指向宿主 `node_modules` 的 junction/链接） | 不是本仓库内容；干净的 `npm install` 不保证复现被测依赖树 |
| POSIX 运行环境 | Linux / macOS，或 Windows 上的 WSL | `tests/integration/cross_transport/` 依赖 `/proc`、进程组与 `SIGKILL`；**Windows 原生不支持该目录** |

集成/回环 harness 读取的环境变量（都有默认值，正常不需要手工设置）：

| 变量 | 默认值 | 作用 |
|---|---|---|
| `DSH_BRIDGE_PYTHON` | `sys.executable`（当前解释器） | 子进程使用的 Python，**优先级最高** |
| `DSH_BRIDGE_B_ROOT` | `A_ROOT/../dsh-plugin-astrbot-bridge` | 对端 B 仓库路径 |
| `DSH_BRIDGE_NODE` | `node` | 启动 `b_peer.mjs` 的 Node 可执行文件 |

以下命令都是**一行 PowerShell**，并且**都在插件目录**（`<你的 AstrBot 目录>\data\plugins\astrbot_plugin_dsh_bridge`）里执行；`..\..\..\.venv` 即 AstrBot 自己的虚拟环境，`..\..\..` 就是 AstrBot 根目录。单元/协议测试可以在 Windows 原生环境执行；**含 `tests/integration/` 的全量只在 POSIX/WSL 上受支持**。

单元/协议测试（**不含** `tests/integration/`，约 1.5 分钟）：

```powershell
Set-Location <你的 AstrBot 目录>\data\plugins\astrbot_plugin_dsh_bridge; & ..\..\..\.venv\Scripts\python.exe -m pytest tests --ignore=tests/integration -o addopts="" -q
```

含跨端集成目录的全量（**POSIX/WSL only**；会起真实回环 socket；2026-11-01 实测 business 4:07.94 + cross 2:38.53）。Windows 原生环境不提供该全量跑法，请改用 WSL 里的 Python 执行。

WSL 侧需要准备一个能 import AstrBot、并装有 `pytest`/`pytest-asyncio` 的 Python；下面同样是一条**单行 PowerShell**，`<WSL 内插件目录>`、`<WSL 内 B 仓库>` 与 `<WSL 内 python>` 按本机替换：

```powershell
wsl.exe bash -lc "cd '<WSL 内插件目录>' && DSH_BRIDGE_PYTHON='<WSL 内 python>' DSH_BRIDGE_B_ROOT='<WSL 内 B 仓库>' '<WSL 内 python>' -m pytest tests -o addopts='' -q"
```

```powershell
Set-Location <你的 AstrBot 目录>\data\plugins\astrbot_plugin_dsh_bridge; & ..\..\..\.venv\Scripts\python.exe -m ruff check .
```

```powershell
Set-Location <你的 AstrBot 目录>\data\plugins\astrbot_plugin_dsh_bridge; & ..\..\..\.venv\Scripts\python.exe -m ruff format . --check
```

用 `uv` 管理环境时，等价的一行（**在 AstrBot 目录**执行）：

```powershell
Set-Location <你的 AstrBot 目录>; uv run pytest data\plugins\astrbot_plugin_dsh_bridge\tests --ignore=data\plugins\astrbot_plugin_dsh_bridge\tests\integration -q
```

> 为什么加 `-o addopts=""`：插件自带的 `pytest.ini` 里 `addopts = -q`，与命令行的 `-q` 叠加后会变成 `-qq`，失败摘要就不再逐条打印失败用例名。

### 测试现状（历史快照，不等于当前验收）

- **2026-11-01 当前快照**：A 全量单测 427 passed（28.27s）；B 全量单测 377 passed / 0 failed（33.63s）；A+B 真实 socket 业务回环 24 passed（248.38s）；跨传输 26 passed（160.19s）；独立密码学校验 36/36 passed；B `tsc -p tsconfig.json --noEmit` exit 0。命令与分项见 `开发/changelog.md`、`开发/v0.1/test/business-roundtrip-results.md`、`开发/v0.1/test/approval-lookup-results.md`。
- **更早的数字已作废**：A 360 / B 348 / business 22（17:35）、295/335、19 PASS / 7 `BLOCKED-IMPL` 等快照均已被取代，只作存档。
- **静态检查**：`ruff format .` 与 `ruff check .` 对整个插件目录通过；B 的 `node --check` 全树通过，`tsc -p tsconfig.json --noEmit` exit 0。
- **仍为 `BLOCKED-ENV`**：真实 AstrBot/DSH 宿主、真实 IM/OpenAPI SSE/TLS 未验证；竞争审批（两侧先答者胜）与 native approval id 竞争偏差仍是未满足项。

## 发布与打包

AstrBot 插件以目录/压缩包分发，本仓库没有 `package.json`，打包规则由 `.gitignore` 与本节的排除清单表达。

**完整包必须包含**：`main.py`、`bridge/`、`views/`、`_conf_schema.json`、`metadata.yaml`、`requirements.txt`、`README.md`、`CHANGELOG.md`、`LICENSE`、`pytest.ini`、`.gitignore`，以及 `tests/` 全树（含 `tests/fixtures/protocol_vectors_v1.json`、`tests/integration/` 与 `tests/integration/independent_crypto/` 源码）。**打压缩包前只排除**：

| 路径 | 原因 |
|---|---|
| `开发/` | 内部开发工作记录（PRD、协议主本、审计与测试报告、过程日志），不随公开包发布 |
| `data/`、`tests/**/data/` | AstrBot 运行期数据（`cmd_config.json`、`t2i_templates/`、`temp/`）与测试运行时生成的副本 |
| `tests/**/_results/` | harness 单次运行产物（如 `last-run.json`），不是源码，也不构成可复现结论 |
| `__pycache__/`、`.pytest_cache/`、`.ruff_cache/`、`*.py[cod]`、`*.log` | 缓存、字节码与日志 |
| `node_modules/`、`node_modules`（含软链/junction） | 依赖链接，不该跟着仓库走 |
| `.git/` | 版本库元数据 |
| `.venv/`、`venv/`、`venv_astrbot/` | 依赖环境 |
| `.env*`、`*.pem`/`*.key`/`*.p12`、`secrets.json`、`credentials.json`、`api_config.json` | 本地凭据 |

> `.git/` 与 `.venv/` 属于「不要打进压缩包」而不是「不该存在」：`.git/` 由 git 自身管理，`.venv/` 已在 `.gitignore` 里。

以上路径都已经在 `.gitignore` 中被忽略（`tests/**/_results/` 也已加入），`git status` 与 `git check-ignore` 可复核；`tests/fixtures/` **不在**排除范围内，它是必须随仓库走的只读协议向量。

> 注意：git 无法把「父目录已被忽略」的路径再单独放行，所以测试夹具请一律放在 `tests/fixtures/`，不要放进任何名为 `data` 的目录。

### 交付归档（完整仓库，不是 npm 包）

给用户的交付物是**完整仓库归档**：必须包含 `tests/`（含 `tests/fixtures/protocol_vectors_v1.json`、`tests/integration/`）、`_conf_schema.json`、`metadata.yaml`、`requirements.txt`、`views/`、`bridge/`、`main.py`、`CHANGELOG.md`、`LICENSE`、`pytest.ini` 与 `.gitignore`。只排除内部开发记录、版本库、本机运行数据、单次运行结果、依赖链接/环境、凭据和缓存；不要用“只打运行时代码”的方式交付。按下列排除后，归档应远小于 16 MiB 的插件上限。

下面是一条**单行 PowerShell**，`<插件目录>` 与输出路径按本机替换：

```powershell
$s='<插件目录>\astrbot_plugin_dsh_bridge'; $d=Join-Path $env:TEMP 'astrbot_plugin_dsh_bridge_delivery'; Remove-Item $d -Recurse -Force -ErrorAction SilentlyContinue; robocopy $s $d /E /XD 开发 .git data _results __pycache__ .pytest_cache .ruff_cache node_modules .venv venv venv_astrbot /XF *.pyc *.pyo *.log *.pem *.key *.p12 secrets.json credentials.json api_config.json .env* | Out-Null; if ($LASTEXITCODE -lt 8) { Compress-Archive -Path (Join-Path $d '*') -DestinationPath '<输出目录>\astrbot_plugin_dsh_bridge-0.1.0.zip' -Force }
```

> `robocopy /XD data` 会同时排除插件根的运行期 `data/`、`tests/data/` 与 `tests/integration/data/`；`/XD _results` 排除 harness 的 `tests/**/_results/`。两者都**不会**排除 `tests/fixtures/`。解包后应能同时看到 `CHANGELOG.md`、`LICENSE`、`pytest.ini`、`.gitignore`、`test_*.py`、`integration/` 与 `fixtures/protocol_vectors_v1.json`，且看不到 `_results/`、`开发/`、`.git/`、`node_modules/`、`.venv/` 或任何密钥文件。

### `tests/integration/independent_crypto/` 的定位

该目录（`verify_actual_crypto.py`、`b_crypto_probe.mjs`）是**开发期的冻结证据校验工具**：它以 `开发/v0.1/vectors.json`、`protocol-freeze.json`、`protocol.md` 和两侧 checkout 为输入，并调用 B 侧 `lib/crypto.js`。源码随完整仓库保留（不删源码、不丢测试），但 `开发/` 不随公开包发布，所以**从公开交付包内不能直接完整运行这个独立 freeze 脚本**。公开可复核的是 `tests/fixtures/protocol_vectors_v1.json`：A 的 `tests/test_vectors.py` 与 B 的 `tests/vectors.test.mjs` 用它验证双端 unit crypto；不要据此宣称冻结脚本在交付包内可完整复现。

## 支持

- [AstrBot 仓库](https://github.com/AstrBotDevs/AstrBot)
- [AstrBot 插件开发文档](https://docs.astrbot.app/dev/star/plugin-new.html)

## 许可证

本仓库的许可证文本见 [`LICENSE`](LICENSE)（GNU AGPL v3 全文）；许可证条款以该文件为准，本 README 不作额外解释。
