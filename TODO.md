/data1/qiang.wang4/emqx 目录是 v5.8.9 版本的 emqx，参考其代码和功能实现，改写为 rust 代码。注意要选择合适的 rust 框架，以求更好的性能和分布式能力。改写代
码放到 /data1/qiang.wang4/rustmq

已完成：
- MQTT 5 Topic Alias 双向完整语义和 Subscription Identifier 完整语义
- MQTT TLS listener（服务端证书、与普通 TCP listener 并存）
- MQTT mTLS（可选客户端证书强制校验、受信 CA 配置）
- MQTT WebSocket listener（默认 `/mqtt`、EMQX 兼容子协议、二进制 MQTT 帧、控制帧和优雅关闭）
- MQTT QUIC 基础 listener（Quinn、TLS 1.3、ALPN `mqtt`、单个双向控制流、idle timeout 和优雅关闭）

仍未实现的主要功能：
- EMQX QUIC 多数据流、0-RTT、客户端证书认证和显式连接迁移语义
- Enhanced Authentication、ACL/授权
- 进程重启后的会话、retained、inflight、离线队列和 pending Will 持久化
- 完整 EMQX /api/v5 管理 API
- 真实 OpenRaft/RocksDB 多节点集群
- 规则引擎、连接器和 Dashboard