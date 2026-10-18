/data1/qiang.wang4/emqx 目录是 v5.8.9 版本的 emqx，参考其代码和功能实现，改写为 rust 代码。注意要选择合适的 rust 框架，以求更好的性能和分布式能力。改写代
码放到 /data1/qiang.wang4/rustmq

已完成：
- MQTT 5 Topic Alias 双向完整语义和 Subscription Identifier 完整语义
- MQTT TLS listener（服务端证书、与普通 TCP listener 并存）
- MQTT mTLS（可选客户端证书强制校验、受信 CA 配置）
- MQTT WebSocket listener（默认 `/mqtt`、EMQX 兼容子协议、二进制 MQTT 帧、控制帧和优雅关闭）
- MQTT QUIC 基础 listener（Quinn、TLS 1.3、ALPN `mqtt`、单个双向控制流、idle timeout 和优雅关闭）
- MQTT QUIC mTLS（可选客户端证书强制校验、受信 CA 配置、缺失/不可信证书握手拒绝）
- MQTT QUIC 并行 PUBLISH 数据流（默认/可配置 10 条双向流、CONNECT 后激活、QoS 0/1/2、独立帧解析和流级故障隔离）
- MQTT QUIC 订阅/投递流亲和（同客户端同主题多流独立订阅和投递、流内 QoS ACK/重试、跨流 UNSUBSCRIBE 隔离、流关闭自动清理）
- MQTT QUIC 0-RTT 与连接迁移（TLS 会话恢复、握手前控制/数据流、握手后同流续传、客户端 UDP 地址切换后会话/流连续；mTLS 强制等待完整握手）
- MQTT 5 Enhanced Authentication（可插拔认证 Provider/跨轮 Cache/Principal 边界、内置 SASL `PLAIN`、初始多轮认证、在线重认证、15 秒绝对认证超时、TCP/TLS/WebSocket/QUIC 共享状态机与 QUIC 数据流认证门控）
- 静态 ACL/授权（启动时编译的有序 first-match 规则、Principal/ClientId、主题过滤器/精确主题/安全模板、QoS/retain 约束、连接级有界缓存、no-match 与 ignore/disconnect 策略、TCP/TLS/WebSocket/QUIC 控制及数据流统一执行、Will 与 Session 主体隔离）
- 单节点进程重启持久化（可选 redb schema v2、Session/Control Subscription、retained、出站 QoS 1/2 inflight phase、离线队列、active/pending Will、绝对过期时间、Principal 隔离、优雅关闭刷盘与 SIGKILL 恢复；QUIC 数据流及入站 QoS 2 状态保持临时态）
- EMQX 风格核心 `/api/v5` 管理 API（独立 Basic API Key、public status、clients 查询/行政踢出、在线订阅管理、publish/bulk、retained 管理、nodes/stats/metrics、稳定分页/资源上限、持久 mutation 与 MQTT 5 `0x98` 行政断开）

仍未实现的主要功能：
- 完整 EMQX `/api/v5` 高级兼容（Bearer、API Key CRUD、ban enforcement、多节点 RPC、OpenAPI/config API、完整 client/metrics 字段和高级 queue/cache 管理）
- 真实 OpenRaft/RocksDB 多节点集群
- 规则引擎、连接器和 Dashboard