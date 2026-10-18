use std::{
    collections::{hash_map::DefaultHasher, HashMap, VecDeque},
    hash::{Hash, Hasher},
    sync::{
        atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering},
        Arc, Mutex, MutexGuard,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use dashmap::{mapref::entry::Entry, DashMap};
use serde::Serialize;
use tokio::sync::{mpsc, oneshot};

const CLIENT_LOCK_SHARDS: usize = 64;
const ADMIN_DISCONNECT_TIMEOUT: Duration = Duration::from_secs(5);

use crate::{
    authorization::{AuthorizationEngine, SubscriptionAuthorization},
    config::{Config, PersistenceConfig},
    persistence::{
        open_store, DurableStore, PersistentActiveWill, PersistentInflight,
        PersistentInflightPhase, PersistentPendingWill, PersistentPublish,
        PersistentQueuedDelivery, PersistentRetained, PersistentSession, PersistentSubscription,
        PersistentSubscriptionOptions, PersistentWillMessage, StoreOperation, StoreSnapshot,
    },
    protocol::{Packet, Publish, Will},
    topic::{bucket_for_filter, bucket_for_topic, parse_filter, topic_matches},
};

#[derive(Clone, Debug)]
pub enum Outbound {
    Packet(Packet),
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum DeliveryTarget {
    #[default]
    Control,
    Data {
        connection: u64,
        stream: u64,
    },
}

#[derive(Debug)]
pub(crate) struct AdministrativeDisconnect {
    completion: oneshot::Sender<()>,
}

impl AdministrativeDisconnect {
    pub(crate) fn complete(self) {
        let _ = self.completion.send(());
    }
}

#[derive(Clone)]
struct ClientHandle {
    token: u64,
    sender: mpsc::Sender<Outbound>,
    disconnect: mpsc::Sender<()>,
    administrative_disconnect: mpsc::Sender<AdministrativeDisconnect>,
}

#[derive(Clone)]
struct DataStreamHandle {
    sender: mpsc::Sender<Outbound>,
    disconnect: mpsc::Sender<()>,
}

#[derive(Clone, Debug)]
struct SubscriptionEntry {
    client_id: String,
    target: DeliveryTarget,
    filter: String,
    options: SubscriptionOptions,
    shared_group: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SubscriptionOptions {
    pub qos: u8,
    pub no_local: bool,
    pub retain_as_published: bool,
    pub retain_handling: u8,
    pub subscription_identifier: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct ConnectionOptions {
    pub clean_start: bool,
    pub expiry_interval: u32,
    pub receive_maximum: u16,
    pub will: Option<Will>,
}

#[derive(Clone, Debug)]
struct ActiveWill {
    generation: u64,
    owner: u64,
    will: Will,
}

#[derive(Clone, Debug, Default)]
struct Session {
    principal: Option<String>,
    online: bool,
    online_generation: Option<u64>,
    last_alive_epoch_ms: u64,
    expiry_interval: u32,
    expires_at: Option<Instant>,
    active_will: Option<ActiveWill>,
    receive_maximum: usize,
    subscriptions: HashMap<SubscriptionKey, SubscriptionOptions>,
    inflight: VecDeque<InflightEntry>,
    offline_queue: VecDeque<QueuedDelivery>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct SubscriptionKey {
    target: DeliveryTarget,
    filter: String,
}

#[derive(Clone, Debug)]
struct InflightEntry {
    publish: Publish,
    target: DeliveryTarget,
    phase: InflightPhase,
    sent_on_connection: bool,
    last_sent: Instant,
}

#[derive(Clone, Debug)]
struct QueuedDelivery {
    publish: Publish,
    target: DeliveryTarget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InflightPhase {
    Ack,
    Rec,
    Comp,
}

#[derive(Default)]
pub struct Metrics {
    pub accepted: AtomicU64,
    pub connected: AtomicU64,
    pub published: AtomicU64,
    pub delivered: AtomicU64,
    pub dropped: AtomicU64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Status {
    pub version: &'static str,
    pub connections: usize,
    pub sessions: usize,
    pub subscriptions: usize,
    pub retained: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct ClientSnapshot {
    pub clientid: String,
    pub username: Option<String>,
    pub node: String,
    pub connected: bool,
    pub online: bool,
    pub last_alive_epoch_ms: u64,
    pub expiry_interval: u32,
    pub subscriptions_cnt: usize,
    pub inflight_cnt: usize,
    pub mqueue_len: usize,
    pub receive_maximum: usize,
    pub durable: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct SubscriptionSnapshot {
    pub clientid: String,
    pub topic: String,
    pub qos: u8,
    pub nl: bool,
    pub rap: bool,
    pub rh: u8,
    pub durable: bool,
    pub target: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct RetainedSnapshot {
    pub topic: String,
    pub qos: u8,
    pub payload_size: usize,
    pub expires_at_epoch_ms: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct RetainedDetailSnapshot {
    pub summary: RetainedSnapshot,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
pub struct MetricsSnapshot {
    pub connections_accepted: u64,
    pub connections: u64,
    pub messages_published: u64,
    pub messages_delivered: u64,
    pub messages_dropped: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct StatsSnapshot {
    pub connections: usize,
    pub sessions: usize,
    pub subscriptions: usize,
    pub retained: usize,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PublishOutcome {
    pub matched: usize,
    pub accepted: usize,
    pub retained: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotLimitExceeded;

struct BrokerInner {
    clients: DashMap<String, ClientHandle>,
    client_locks: [Mutex<()>; CLIENT_LOCK_SHARDS],
    data_streams: DashMap<(String, u64, u64), DataStreamHandle>,
    sessions: DashMap<String, Session>,
    subscription_buckets: DashMap<String, Vec<SubscriptionEntry>>,
    retained: DashMap<String, Publish>,
    shared_cursor: DashMap<String, AtomicU64>,
    connection_token: AtomicU64,
    outbound_packet_id: AtomicU16,
    inflight_limit: usize,
    offline_queue_limit: usize,
    pending_wills: Mutex<HashMap<String, PendingWill>>,
    will_generation: AtomicU64,
    revision: AtomicU64,
    store: Arc<dyn DurableStore>,
    shutting_down: AtomicBool,
    will_execution: Mutex<()>,
    metrics: Metrics,
}

#[derive(Clone)]
struct PendingWill {
    generation: u64,
    will: Will,
    principal: Option<String>,
    fire_at_epoch_ms: u64,
    firing: bool,
}

#[derive(Clone)]
pub struct Broker {
    inner: Arc<BrokerInner>,
}

impl Default for Broker {
    fn default() -> Self {
        Self::new()
    }
}

impl Broker {
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(32, 1024)
    }

    #[must_use]
    pub fn with_limits(inflight_limit: usize, offline_queue_limit: usize) -> Self {
        let (store, snapshot) = open_store(&PersistenceConfig::default())
            .expect("disabled persistence store initialization cannot fail");
        Self::from_store(
            inflight_limit,
            offline_queue_limit,
            store,
            snapshot
                .maximum_revision
                .checked_add(1)
                .expect("disabled persistence revision cannot overflow"),
        )
    }

    pub fn open(config: &Config) -> Result<Self> {
        let authorization = AuthorizationEngine::compile(&config.authorization)
            .context("compile authorization for persistence recovery")?;
        Self::with_persistence(
            config.mqtt.inflight_limit,
            config.mqtt.offline_queue_limit,
            &config.persistence,
            Some(&authorization),
        )
    }

    pub fn with_persistence(
        inflight_limit: usize,
        offline_queue_limit: usize,
        config: &PersistenceConfig,
        authorization: Option<&Arc<AuthorizationEngine>>,
    ) -> Result<Self> {
        let (store, snapshot) = open_store(config)?;
        let next_revision = snapshot
            .maximum_revision
            .checked_add(1)
            .context("persistence revision namespace is exhausted")?;
        let broker = Self::from_store(inflight_limit, offline_queue_limit, store, next_revision);
        broker.recover(snapshot, authorization)?;
        broker.flush()?;
        Ok(broker)
    }

    fn from_store(
        inflight_limit: usize,
        offline_queue_limit: usize,
        store: Arc<dyn DurableStore>,
        next_revision: u64,
    ) -> Self {
        Self {
            inner: Arc::new(BrokerInner {
                clients: DashMap::new(),
                client_locks: std::array::from_fn(|_| Mutex::new(())),
                data_streams: DashMap::new(),
                sessions: DashMap::new(),
                subscription_buckets: DashMap::new(),
                retained: DashMap::new(),
                shared_cursor: DashMap::new(),
                connection_token: AtomicU64::new(1),
                outbound_packet_id: AtomicU16::new(1),
                inflight_limit: inflight_limit.max(1),
                offline_queue_limit,
                pending_wills: Mutex::new(HashMap::new()),
                will_generation: AtomicU64::new(1),
                revision: AtomicU64::new(next_revision),
                store,
                shutting_down: AtomicBool::new(false),
                will_execution: Mutex::new(()),
                metrics: Metrics::default(),
            }),
        }
    }

    fn client_lock(&self, client_id: &str) -> MutexGuard<'_, ()> {
        let mut hasher = DefaultHasher::new();
        client_id.hash(&mut hasher);
        let shard = usize::try_from(hasher.finish() % CLIENT_LOCK_SHARDS as u64)
            .expect("client lock shard fits usize");
        self.inner.client_locks[shard]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn flush(&self) -> Result<()> {
        self.inner
            .store
            .flush()
            .context("flush durable broker state")
    }

    pub fn prepare_shutdown(&self) -> Result<()> {
        self.inner.shutting_down.store(true, Ordering::SeqCst);
        let _will_guard = self
            .inner
            .will_execution
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.flush()
    }

    #[must_use]
    pub fn persistence_enabled(&self) -> bool {
        self.inner.store.is_enabled()
    }

    fn next_revision(&self) -> u64 {
        self.inner
            .revision
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |revision| {
                revision.checked_add(1)
            })
            .unwrap_or_else(|_| {
                tracing::error!("persistence revision namespace exhausted; aborting fail-closed");
                std::process::abort();
            })
    }

    fn next_will_generation(&self) -> u64 {
        self.inner
            .will_generation
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |generation| {
                generation.checked_add(1)
            })
            .unwrap_or_else(|_| {
                tracing::error!("Will generation namespace exhausted; aborting fail-closed");
                std::process::abort();
            })
    }

    fn apply_store(&self, operations: Vec<StoreOperation>) {
        if let Err(error) = self.inner.store.apply(operations) {
            tracing::error!(%error, "durable broker mutation failed; aborting fail-closed");
            std::process::abort();
        }
    }

    fn persist_current_session(&self, client_id: &str) {
        let now = Self::now_epoch_ms();
        let operation = self.inner.sessions.get_mut(client_id).map(|mut session| {
            if session.online {
                session.last_alive_epoch_ms = now;
            }
            let revision = self.next_revision();
            StoreOperation::PutSession {
                client_id: client_id.to_owned(),
                record: Self::persistent_session(client_id, &session, revision),
            }
        });
        if let Some(operation) = operation {
            self.apply_store(vec![operation]);
        }
    }

    fn clear_session(&self, client_id: &str, cancel_pending: bool) -> Option<PendingWill> {
        let (session_revision, active_will, principal) =
            match self.inner.sessions.entry(client_id.to_owned()) {
                Entry::Occupied(entry) => {
                    let revision = self.next_revision();
                    let session = entry.remove();
                    (revision, session.active_will, session.principal)
                }
                Entry::Vacant(entry) => {
                    let revision = self.next_revision();
                    drop(entry);
                    (revision, None, None)
                }
            };
        for mut bucket in self.inner.subscription_buckets.iter_mut() {
            bucket.retain(|entry| entry.client_id != client_id);
        }
        let mut converted_active = false;
        let pending = {
            let mut wills = self
                .inner
                .pending_wills
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if cancel_pending {
                wills.remove(client_id)
            } else if let Some(pending) = wills.get(client_id).cloned() {
                Some(pending)
            } else {
                active_will.map(|active| {
                    converted_active = true;
                    let pending = PendingWill {
                        generation: active.generation,
                        will: active.will,
                        principal,
                        fire_at_epoch_ms: Self::now_epoch_ms(),
                        firing: false,
                    };
                    wills.insert(client_id.to_owned(), pending.clone());
                    pending
                })
            }
        };
        let mut operations = vec![StoreOperation::DeleteSession {
            client_id: client_id.to_owned(),
            revision: session_revision,
        }];
        if cancel_pending {
            operations.push(StoreOperation::DeleteWill {
                client_id: client_id.to_owned(),
                revision: self.next_revision(),
            });
        } else if converted_active {
            let pending = pending.as_ref().expect("converted active Will is pending");
            operations.push(StoreOperation::PutWill {
                client_id: client_id.to_owned(),
                record: PersistentPendingWill {
                    client_id: client_id.to_owned(),
                    revision: self.next_revision(),
                    generation: pending.generation,
                    principal: pending.principal.clone(),
                    will: Self::persistent_will(&pending.will),
                    fire_at_epoch_ms: pending.fire_at_epoch_ms,
                    firing: false,
                },
            });
        }
        self.apply_store(operations);
        pending
    }

    fn persistent_session(client_id: &str, session: &Session, revision: u64) -> PersistentSession {
        PersistentSession {
            client_id: client_id.to_owned(),
            revision,
            principal: session.principal.clone(),
            online: session.online,
            online_generation: session.online_generation,
            last_alive_epoch_ms: session.last_alive_epoch_ms,
            expiry_interval: session.expiry_interval,
            expires_at_epoch_ms: session.expires_at.map(Self::instant_to_epoch_ms),
            active_will: session
                .active_will
                .as_ref()
                .map(|active| PersistentActiveWill {
                    generation: active.generation,
                    owner: active.owner,
                    will: Self::persistent_will(&active.will),
                }),
            receive_maximum: session.receive_maximum,
            subscriptions: session
                .subscriptions
                .iter()
                .filter(|(key, _)| key.target == DeliveryTarget::Control)
                .map(|(key, options)| PersistentSubscription {
                    filter: key.filter.clone(),
                    options: PersistentSubscriptionOptions {
                        qos: options.qos,
                        no_local: options.no_local,
                        retain_as_published: options.retain_as_published,
                        retain_handling: options.retain_handling,
                        subscription_identifier: options.subscription_identifier,
                    },
                })
                .collect(),
            inflight: session
                .inflight
                .iter()
                .filter(|entry| entry.target == DeliveryTarget::Control)
                .map(|entry| PersistentInflight {
                    publish: Self::persistent_publish(&entry.publish),
                    phase: match entry.phase {
                        InflightPhase::Ack => PersistentInflightPhase::Ack,
                        InflightPhase::Rec => PersistentInflightPhase::Rec,
                        InflightPhase::Comp => PersistentInflightPhase::Comp,
                    },
                })
                .collect(),
            offline_queue: session
                .offline_queue
                .iter()
                .filter(|delivery| delivery.target == DeliveryTarget::Control)
                .map(|delivery| PersistentQueuedDelivery {
                    publish: Self::persistent_publish(&delivery.publish),
                })
                .collect(),
        }
    }

    fn persistent_publish(publish: &Publish) -> PersistentPublish {
        PersistentPublish {
            dup: publish.dup,
            qos: publish.qos,
            retain: publish.retain,
            topic: publish.topic.clone(),
            packet_id: publish.packet_id,
            payload: publish.payload.to_vec(),
            expires_at_epoch_ms: publish.expires_at.map(Self::instant_to_epoch_ms),
            subscription_identifiers: publish.subscription_identifiers.clone(),
        }
    }

    fn restore_publish(
        publish: PersistentPublish,
        preserve_expired: bool,
    ) -> Result<Option<Publish>> {
        let expired = publish
            .expires_at_epoch_ms
            .is_some_and(|deadline| deadline <= Self::now_epoch_ms());
        if expired && !preserve_expired {
            return Ok(None);
        }
        let expires_at = publish
            .expires_at_epoch_ms
            .map(Self::epoch_ms_to_instant)
            .transpose()?;
        Ok(Some(Publish {
            dup: publish.dup,
            qos: publish.qos,
            retain: publish.retain,
            topic: publish.topic,
            packet_id: publish.packet_id,
            payload: publish.payload.into(),
            expires_at,
            subscription_identifiers: publish.subscription_identifiers,
            topic_alias: None,
        }))
    }

    fn persistent_will(will: &Will) -> PersistentWillMessage {
        PersistentWillMessage {
            topic: will.topic.clone(),
            payload: will.payload.to_vec(),
            qos: will.qos,
            retain: will.retain,
            delay_interval: will.delay_interval,
            message_expiry_interval: will.message_expiry_interval,
        }
    }

    fn restore_will(will: PersistentWillMessage) -> Result<Will> {
        if will.qos > 2 {
            bail!("invalid persisted Will QoS {}", will.qos);
        }
        Ok(Will {
            topic: will.topic,
            payload: will.payload.into(),
            qos: will.qos,
            retain: will.retain,
            delay_interval: will.delay_interval,
            message_expiry_interval: will.message_expiry_interval,
        })
    }

    fn now_epoch_ms() -> u64 {
        u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        )
        .unwrap_or(u64::MAX)
    }

    fn instant_to_epoch_ms(deadline: Instant) -> u64 {
        Self::now_epoch_ms().saturating_add(
            u64::try_from(
                deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis(),
            )
            .unwrap_or(u64::MAX),
        )
    }

    fn epoch_ms_to_instant(deadline: u64) -> Result<Instant> {
        Instant::now()
            .checked_add(Duration::from_millis(
                deadline.saturating_sub(Self::now_epoch_ms()),
            ))
            .context("persisted epoch deadline exceeds the monotonic clock range")
    }

    fn epoch_add_seconds(epoch_ms: u64, seconds: u32) -> Result<u64> {
        epoch_ms
            .checked_add(
                u64::from(seconds)
                    .checked_mul(1_000)
                    .context("persisted deadline interval overflow")?,
            )
            .context("persisted epoch deadline overflow")
    }

    fn recover(
        &self,
        snapshot: StoreSnapshot,
        authorization: Option<&Arc<AuthorizationEngine>>,
    ) -> Result<()> {
        let StoreSnapshot {
            sessions,
            retained,
            wills,
            maximum_revision: _,
        } = snapshot;
        for (client_id, record) in &sessions {
            if record.active_will.is_some() && wills.contains_key(client_id) {
                bail!("persisted session {client_id} has both active and pending Will state");
            }
        }

        let now_epoch_ms = Self::now_epoch_ms();
        let mut maximum_generation = 0_u64;
        let mut overdue = Vec::new();
        for (client_id, mut record) in sessions {
            let was_online = record.online;
            let crash_expiry_epoch_ms = if was_online {
                match record.expiry_interval {
                    0 => Some(record.last_alive_epoch_ms),
                    u32::MAX => None,
                    seconds => Some(Self::epoch_add_seconds(
                        record.last_alive_epoch_ms,
                        seconds,
                    )?),
                }
            } else {
                record.expires_at_epoch_ms
            };

            let mut operations = Vec::new();
            if let Some(active) = record.active_will.take() {
                maximum_generation = maximum_generation.max(active.generation);
                let will = Self::restore_will(active.will)?;
                let mut fire_at_epoch_ms =
                    Self::epoch_add_seconds(record.last_alive_epoch_ms, will.delay_interval)?;
                if let Some(expiry) = crash_expiry_epoch_ms {
                    fire_at_epoch_ms = fire_at_epoch_ms.min(expiry);
                }
                let pending = PendingWill {
                    generation: active.generation,
                    will: will.clone(),
                    principal: record.principal.clone(),
                    fire_at_epoch_ms,
                    firing: false,
                };
                self.inner
                    .pending_wills
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(client_id.clone(), pending);
                operations.push(StoreOperation::PutWill {
                    client_id: client_id.clone(),
                    record: PersistentPendingWill {
                        client_id: client_id.clone(),
                        revision: self.next_revision(),
                        generation: active.generation,
                        principal: record.principal.clone(),
                        will: Self::persistent_will(&will),
                        fire_at_epoch_ms,
                        firing: false,
                    },
                });
                if fire_at_epoch_ms <= now_epoch_ms {
                    overdue.push((client_id.clone(), active.generation));
                } else {
                    self.arm_pending_will(client_id.clone(), active.generation, fire_at_epoch_ms);
                }
            }

            let expired = crash_expiry_epoch_ms.is_some_and(|deadline| deadline <= now_epoch_ms);
            if record.expiry_interval == 0 || expired {
                operations.push(StoreOperation::DeleteSession {
                    client_id: client_id.clone(),
                    revision: self.next_revision(),
                });
                self.apply_store(operations);
                continue;
            }

            let mut pruned = was_online;
            let mut subscriptions = HashMap::new();
            for subscription in record.subscriptions {
                let options = SubscriptionOptions {
                    qos: subscription.options.qos,
                    no_local: subscription.options.no_local,
                    retain_as_published: subscription.options.retain_as_published,
                    retain_handling: subscription.options.retain_handling,
                    subscription_identifier: subscription.options.subscription_identifier,
                };
                let allowed = authorization.is_none_or(|engine| {
                    engine
                        .session(record.principal.clone(), client_id.clone())
                        .authorize_subscribe(&subscription.filter, options.qos)
                        == SubscriptionAuthorization::Allow
                });
                if allowed {
                    subscriptions.insert(
                        SubscriptionKey {
                            target: DeliveryTarget::Control,
                            filter: subscription.filter,
                        },
                        options,
                    );
                } else {
                    pruned = true;
                }
            }
            let mut inflight = VecDeque::new();
            for entry in record.inflight {
                let phase = match entry.phase {
                    PersistentInflightPhase::Ack => InflightPhase::Ack,
                    PersistentInflightPhase::Rec => InflightPhase::Rec,
                    PersistentInflightPhase::Comp => InflightPhase::Comp,
                };
                let preserve_expired = phase == InflightPhase::Comp;
                if let Some(publish) = Self::restore_publish(entry.publish, preserve_expired)? {
                    inflight.push_back(InflightEntry {
                        publish,
                        target: DeliveryTarget::Control,
                        phase,
                        sent_on_connection: false,
                        last_sent: Instant::now(),
                    });
                } else {
                    pruned = true;
                }
            }
            let mut offline_queue = VecDeque::new();
            for entry in record.offline_queue {
                if let Some(publish) = Self::restore_publish(entry.publish, false)? {
                    offline_queue.push_back(QueuedDelivery {
                        publish,
                        target: DeliveryTarget::Control,
                    });
                } else {
                    pruned = true;
                }
            }
            let expires_at = crash_expiry_epoch_ms
                .map(Self::epoch_ms_to_instant)
                .transpose()?;
            self.inner.sessions.insert(
                client_id.clone(),
                Session {
                    principal: record.principal,
                    online: false,
                    online_generation: None,
                    last_alive_epoch_ms: record.last_alive_epoch_ms,
                    expiry_interval: record.expiry_interval,
                    expires_at,
                    active_will: None,
                    receive_maximum: record.receive_maximum,
                    subscriptions,
                    inflight,
                    offline_queue,
                },
            );
            self.rebuild_control_buckets_for_session(&client_id)?;
            if pruned {
                let session = self
                    .inner
                    .sessions
                    .get(&client_id)
                    .context("recovered session disappeared")?;
                operations.push(StoreOperation::PutSession {
                    client_id: client_id.clone(),
                    record: Self::persistent_session(&client_id, &session, self.next_revision()),
                });
            }
            self.apply_store(operations);
        }
        for (topic, record) in retained {
            if record.publish.payload.is_empty() {
                self.apply_store(vec![StoreOperation::DeleteRetained {
                    topic,
                    revision: self.next_revision(),
                }]);
                continue;
            }
            if let Some(publish) = Self::restore_publish(record.publish, false)? {
                self.inner.retained.insert(topic, publish);
            } else {
                self.apply_store(vec![StoreOperation::DeleteRetained {
                    topic,
                    revision: self.next_revision(),
                }]);
            }
        }
        for (client_id, record) in wills {
            maximum_generation = maximum_generation.max(record.generation);
            let pending = PendingWill {
                generation: record.generation,
                will: Self::restore_will(record.will)?,
                principal: record.principal,
                fire_at_epoch_ms: record.fire_at_epoch_ms,
                firing: record.firing,
            };
            self.inner
                .pending_wills
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(client_id.clone(), pending);
            if record.firing || record.fire_at_epoch_ms <= now_epoch_ms {
                overdue.push((client_id, record.generation));
            } else {
                self.arm_pending_will(client_id, record.generation, record.fire_at_epoch_ms);
            }
        }
        let next_generation = maximum_generation
            .checked_add(1)
            .context("persisted Will generation namespace is exhausted")?
            .max(1);
        self.inner
            .will_generation
            .store(next_generation, Ordering::Relaxed);
        for (client_id, generation) in overdue {
            self.force_fire_pending_will(&client_id, generation, true);
        }
        Ok(())
    }

    fn rebuild_control_buckets_for_session(&self, client_id: &str) -> Result<()> {
        let entries = self
            .inner
            .sessions
            .get(client_id)
            .map(|session| {
                session
                    .subscriptions
                    .iter()
                    .filter(|(key, _)| key.target == DeliveryTarget::Control)
                    .map(|(key, options)| (key.filter.clone(), *options))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for (filter, options) in entries {
            let parsed = parse_filter(&filter)?;
            self.inner
                .subscription_buckets
                .entry(bucket_for_filter(&filter))
                .or_default()
                .push(SubscriptionEntry {
                    client_id: client_id.to_owned(),
                    target: DeliveryTarget::Control,
                    filter: parsed.filter,
                    options,
                    shared_group: parsed.shared_group,
                });
        }
        Ok(())
    }

    fn arm_pending_will(&self, client_id: String, generation: u64, fire_at_epoch_ms: u64) {
        let broker = self.clone();
        let delay = Duration::from_millis(fire_at_epoch_ms.saturating_sub(Self::now_epoch_ms()));
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            broker.fire_pending_will(&client_id, generation);
        });
    }

    fn fire_pending_will(&self, client_id: &str, generation: u64) {
        self.force_fire_pending_will(client_id, generation, false);
    }

    fn force_fire_pending_will(&self, client_id: &str, generation: u64, force: bool) {
        let _will_guard = self
            .inner
            .will_execution
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.inner.shutting_down.load(Ordering::SeqCst) {
            return;
        }
        let pending = self
            .inner
            .pending_wills
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(client_id)
            .filter(|pending| pending.generation == generation)
            .cloned();
        let Some(mut pending) = pending else {
            return;
        };
        if !force && !pending.firing && pending.fire_at_epoch_ms > Self::now_epoch_ms() {
            self.arm_pending_will(client_id.to_owned(), generation, pending.fire_at_epoch_ms);
            return;
        }
        if !pending.firing {
            pending.firing = true;
            let revision = {
                let mut wills = self
                    .inner
                    .pending_wills
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let Some(current) = wills.get_mut(client_id) else {
                    return;
                };
                if current.generation != generation {
                    return;
                }
                current.firing = true;
                self.next_revision()
            };
            self.apply_store(vec![StoreOperation::PutWill {
                client_id: client_id.to_owned(),
                record: PersistentPendingWill {
                    client_id: client_id.to_owned(),
                    revision,
                    generation,
                    principal: pending.principal.clone(),
                    will: Self::persistent_will(&pending.will),
                    fire_at_epoch_ms: pending.fire_at_epoch_ms,
                    firing: true,
                },
            }]);
        }
        self.publish_will(client_id, pending.will);
        let revision = {
            let mut wills = self
                .inner
                .pending_wills
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if wills
                .get(client_id)
                .is_some_and(|current| current.generation == generation && current.firing)
            {
                let revision = self.next_revision();
                wills.remove(client_id);
                Some(revision)
            } else {
                None
            }
        };
        if let Some(revision) = revision {
            self.apply_store(vec![StoreOperation::DeleteWill {
                client_id: client_id.to_owned(),
                revision,
            }]);
        }
    }

    #[must_use]
    pub fn metrics(&self) -> &Metrics {
        &self.inner.metrics
    }

    pub fn register(
        &self,
        client_id: &str,
        clean: bool,
        sender: mpsc::Sender<Outbound>,
        disconnect: mpsc::Sender<()>,
    ) -> (u64, bool) {
        let expiry_interval = if clean { 0 } else { u32::MAX };
        self.register_with_expiry(
            client_id,
            ConnectionOptions {
                clean_start: clean,
                expiry_interval,
                receive_maximum: u16::MAX,
                will: None,
            },
            sender,
            disconnect,
        )
    }

    pub fn register_with_expiry(
        &self,
        client_id: &str,
        options: ConnectionOptions,
        sender: mpsc::Sender<Outbound>,
        disconnect: mpsc::Sender<()>,
    ) -> (u64, bool) {
        self.register_authorized_with_expiry(client_id, None, options, sender, disconnect)
    }

    pub fn register_authorized_with_expiry(
        &self,
        client_id: &str,
        principal: Option<&str>,
        options: ConnectionOptions,
        sender: mpsc::Sender<Outbound>,
        disconnect: mpsc::Sender<()>,
    ) -> (u64, bool) {
        let (administrative_disconnect, _receiver) = mpsc::channel(1);
        self.register_authorized_with_admin(
            client_id,
            principal,
            options,
            sender,
            disconnect,
            administrative_disconnect,
        )
    }

    pub(crate) fn register_authorized_with_admin(
        &self,
        client_id: &str,
        principal: Option<&str>,
        options: ConnectionOptions,
        sender: mpsc::Sender<Outbound>,
        disconnect: mpsc::Sender<()>,
        administrative_disconnect: mpsc::Sender<AdministrativeDisconnect>,
    ) -> (u64, bool) {
        let _client_guard = self.client_lock(client_id);
        let ConnectionOptions {
            clean_start,
            expiry_interval,
            receive_maximum,
            will,
        } = options;
        let principal = principal.map(str::to_owned);
        self.remove_if_expired_locked(client_id);
        let owner_changed = self
            .inner
            .sessions
            .get(client_id)
            .is_some_and(|session| session.principal != principal);
        if owner_changed {
            self.clear_session(client_id, true);
        } else if clean_start {
            if let Some(pending) = self.clear_session(client_id, false) {
                if pending.principal == principal {
                    self.force_fire_pending_will(client_id, pending.generation, true);
                } else {
                    self.take_pending_will(client_id);
                }
            }
        } else {
            self.take_pending_will(client_id);
            let active = self
                .inner
                .sessions
                .get(client_id)
                .and_then(|session| session.active_will.clone());
            if let Some(active) = active.filter(|active| active.will.delay_interval == 0) {
                self.publish_will(client_id, active.will);
            }
        }
        let session_present = !clean_start && self.inner.sessions.contains_key(client_id);
        let token = self
            .inner
            .connection_token
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |token| {
                token.checked_add(1)
            })
            .unwrap_or_else(|_| {
                tracing::error!("connection generation exhausted; aborting fail-closed");
                std::process::abort();
            });
        let active_will = will.clone().map(|will| ActiveWill {
            generation: self.next_will_generation(),
            owner: token,
            will,
        });
        self.inner
            .sessions
            .entry(client_id.to_owned())
            .or_insert_with(|| Session {
                principal: principal.clone(),
                online: true,
                online_generation: Some(token),
                last_alive_epoch_ms: Self::now_epoch_ms(),
                expiry_interval,
                expires_at: None,
                active_will: active_will.clone(),
                receive_maximum: usize::from(receive_maximum),
                subscriptions: HashMap::new(),
                inflight: VecDeque::new(),
                offline_queue: VecDeque::new(),
            });
        if let Some(mut session) = self.inner.sessions.get_mut(client_id) {
            session.principal.clone_from(&principal);
            session.online = true;
            session.online_generation = Some(token);
            session.last_alive_epoch_ms = Self::now_epoch_ms();
            session.expiry_interval = expiry_interval;
            session.expires_at = None;
            session.active_will = active_will;
            session.receive_maximum = usize::from(receive_maximum);
            for entry in &mut session.inflight {
                entry.sent_on_connection = false;
            }
        }
        self.persist_current_session(client_id);
        if let Some(old) = self.inner.clients.insert(
            client_id.to_owned(),
            ClientHandle {
                token,
                sender,
                disconnect,
                administrative_disconnect,
            },
        ) {
            self.remove_data_streams_for_connection(client_id, old.token);
            let _ = old.disconnect.try_send(());
        } else {
            self.inner.metrics.connected.fetch_add(1, Ordering::Relaxed);
        }
        self.replay_session(client_id);
        (token, session_present)
    }

    pub fn disconnect_current(&self, client_id: &str, token: u64) -> bool {
        self.inner
            .clients
            .get(client_id)
            .is_some_and(|handle| handle.token == token && handle.disconnect.try_send(()).is_ok())
    }

    pub fn unregister(&self, client_id: &str, token: u64) -> bool {
        self.finalize_connection(client_id, token, true, false, false)
    }

    pub fn disconnect_normally(&self, client_id: &str, token: u64) -> bool {
        self.finalize_connection(client_id, token, false, false, false)
    }

    pub fn finalize_connection(
        &self,
        client_id: &str,
        token: u64,
        publish_will: bool,
        force_will_immediately: bool,
        discard_session: bool,
    ) -> bool {
        let _client_guard = self.client_lock(client_id);
        let is_current = self
            .inner
            .clients
            .get(client_id)
            .is_some_and(|handle| handle.token == token);
        if !is_current {
            return false;
        }
        self.remove_data_streams_for_connection(client_id, token);
        self.inner.clients.remove(client_id);
        self.inner.metrics.connected.fetch_sub(1, Ordering::Relaxed);

        let now_epoch_ms = Self::now_epoch_ms();
        let mut active_will = None;
        let mut expiry_interval = None;
        let mut session_principal = None;
        let mut operations = Vec::new();
        if discard_session {
            if let Some((_, session)) = self.inner.sessions.remove(client_id) {
                active_will = session.active_will.filter(|active| active.owner == token);
                session_principal = session.principal;
            }
            for mut bucket in self.inner.subscription_buckets.iter_mut() {
                bucket.retain(|entry| entry.client_id != client_id);
            }
            operations.push(StoreOperation::DeleteSession {
                client_id: client_id.to_owned(),
                revision: self.next_revision(),
            });
        } else if let Some(mut session) = self.inner.sessions.get_mut(client_id) {
            for entry in &mut session.inflight {
                entry.sent_on_connection = false;
            }
            session.online = false;
            session.online_generation = None;
            session.last_alive_epoch_ms = now_epoch_ms;
            session_principal.clone_from(&session.principal);
            active_will = session
                .active_will
                .take()
                .filter(|active| active.owner == token);
            expiry_interval = Some(session.expiry_interval);
            session.expires_at = match session.expiry_interval {
                0 | u32::MAX => None,
                seconds => Some(
                    Instant::now()
                        .checked_add(Duration::from_secs(u64::from(seconds)))
                        .unwrap_or_else(|| {
                            tracing::error!(
                                "session expiry exceeds monotonic clock; aborting fail-closed"
                            );
                            std::process::abort();
                        }),
                ),
            };
        }

        if !discard_session {
            match expiry_interval {
                Some(0) => {
                    self.inner.sessions.remove(client_id);
                    for mut bucket in self.inner.subscription_buckets.iter_mut() {
                        bucket.retain(|entry| entry.client_id != client_id);
                    }
                    operations.push(StoreOperation::DeleteSession {
                        client_id: client_id.to_owned(),
                        revision: self.next_revision(),
                    });
                }
                Some(_) => {
                    if let Some(session) = self.inner.sessions.get(client_id) {
                        operations.push(StoreOperation::PutSession {
                            client_id: client_id.to_owned(),
                            record: Self::persistent_session(
                                client_id,
                                &session,
                                self.next_revision(),
                            ),
                        });
                    }
                }
                None => {}
            }
        }

        if discard_session {
            self.inner
                .pending_wills
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(client_id);
        }

        let pending_to_arm = if publish_will {
            active_will.map(|active| {
                let delay = if force_will_immediately {
                    0
                } else {
                    expiry_interval.map_or(active.will.delay_interval, |expiry| {
                        if expiry == u32::MAX {
                            active.will.delay_interval
                        } else {
                            active.will.delay_interval.min(expiry)
                        }
                    })
                };
                let fire_at_epoch_ms =
                    Self::epoch_add_seconds(now_epoch_ms, delay).unwrap_or_else(|error| {
                        tracing::error!(%error, "Will deadline overflow; aborting fail-closed");
                        std::process::abort();
                    });
                let pending = PendingWill {
                    generation: active.generation,
                    will: active.will.clone(),
                    principal: session_principal.clone(),
                    fire_at_epoch_ms,
                    firing: false,
                };
                self.inner
                    .pending_wills
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(client_id.to_owned(), pending.clone());
                operations.push(StoreOperation::PutWill {
                    client_id: client_id.to_owned(),
                    record: PersistentPendingWill {
                        client_id: client_id.to_owned(),
                        revision: self.next_revision(),
                        generation: pending.generation,
                        principal: pending.principal.clone(),
                        will: Self::persistent_will(&pending.will),
                        fire_at_epoch_ms,
                        firing: false,
                    },
                });
                (active.generation, fire_at_epoch_ms)
            })
        } else {
            None
        };
        if discard_session && pending_to_arm.is_none() {
            operations.push(StoreOperation::DeleteWill {
                client_id: client_id.to_owned(),
                revision: self.next_revision(),
            });
        }
        self.apply_store(operations);
        if let Some((generation, fire_at_epoch_ms)) = pending_to_arm {
            if fire_at_epoch_ms <= Self::now_epoch_ms() {
                self.force_fire_pending_will(client_id, generation, true);
            } else {
                self.arm_pending_will(client_id.to_owned(), generation, fire_at_epoch_ms);
            }
        }
        true
    }

    pub fn register_data_stream(
        &self,
        client_id: &str,
        connection: u64,
        stream: u64,
        sender: mpsc::Sender<Outbound>,
        disconnect: mpsc::Sender<()>,
    ) -> bool {
        let is_current = self
            .inner
            .clients
            .get(client_id)
            .is_some_and(|handle| handle.token == connection);
        if is_current {
            self.inner.data_streams.insert(
                (client_id.to_owned(), connection, stream),
                DataStreamHandle { sender, disconnect },
            );
        }
        is_current
    }

    pub fn unregister_data_stream(&self, client_id: &str, connection: u64, stream: u64) {
        let target = DeliveryTarget::Data { connection, stream };
        self.inner
            .data_streams
            .remove(&(client_id.to_owned(), connection, stream));
        self.remove_target_state(client_id, target);
    }

    fn remove_data_streams_for_connection(&self, client_id: &str, connection: u64) {
        let streams: Vec<u64> = self
            .inner
            .data_streams
            .iter()
            .filter_map(|entry| {
                let (entry_client, entry_connection, stream) = entry.key();
                (entry_client == client_id && *entry_connection == connection).then_some(*stream)
            })
            .collect();
        for stream in &streams {
            self.inner
                .data_streams
                .remove(&(client_id.to_owned(), connection, *stream));
        }
        for stream in streams {
            self.remove_target_state(client_id, DeliveryTarget::Data { connection, stream });
        }
    }

    fn remove_target_state(&self, client_id: &str, target: DeliveryTarget) {
        for mut bucket in self.inner.subscription_buckets.iter_mut() {
            bucket.retain(|entry| !(entry.client_id == client_id && entry.target == target));
        }
        let mut removed = 0_u64;
        if let Some(mut session) = self.inner.sessions.get_mut(client_id) {
            session.subscriptions.retain(|key, _| key.target != target);
            session.inflight.retain(|entry| {
                let keep = entry.target != target;
                removed = removed.saturating_add(u64::from(!keep));
                keep
            });
            session.offline_queue.retain(|entry| {
                let keep = entry.target != target;
                removed = removed.saturating_add(u64::from(!keep));
                keep
            });
        }
        if removed > 0 {
            self.inner
                .metrics
                .dropped
                .fetch_add(removed, Ordering::Relaxed);
        }
        self.activate_replayable(client_id);
        self.promote_queued(client_id);
    }

    pub fn schedule_will(&self, client_id: &str, will: Will, session_expiry: u32) {
        self.schedule_authorized_will(client_id, None, will, session_expiry);
    }

    pub fn schedule_authorized_will(
        &self,
        client_id: &str,
        principal: Option<&str>,
        will: Will,
        session_expiry: u32,
    ) {
        let delay = if session_expiry == u32::MAX {
            will.delay_interval
        } else {
            will.delay_interval.min(session_expiry)
        };
        let generation = self.next_will_generation();
        let fire_at_epoch_ms =
            Self::epoch_add_seconds(Self::now_epoch_ms(), delay).unwrap_or_else(|error| {
                tracing::error!(%error, "Will deadline overflow; aborting fail-closed");
                std::process::abort();
            });
        self.persist_pending_will(
            client_id,
            principal.map(str::to_owned),
            generation,
            will,
            fire_at_epoch_ms,
        );
        if delay == 0 {
            self.force_fire_pending_will(client_id, generation, true);
        } else {
            self.arm_pending_will(client_id.to_owned(), generation, fire_at_epoch_ms);
        }
    }

    fn persist_pending_will(
        &self,
        client_id: &str,
        principal: Option<String>,
        generation: u64,
        will: Will,
        fire_at_epoch_ms: u64,
    ) {
        let pending = PendingWill {
            generation,
            will: will.clone(),
            principal: principal.clone(),
            fire_at_epoch_ms,
            firing: false,
        };
        self.inner
            .pending_wills
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(client_id.to_owned(), pending);
        self.apply_store(vec![StoreOperation::PutWill {
            client_id: client_id.to_owned(),
            record: PersistentPendingWill {
                client_id: client_id.to_owned(),
                revision: self.next_revision(),
                generation,
                principal,
                will: Self::persistent_will(&will),
                fire_at_epoch_ms,
                firing: false,
            },
        }]);
    }

    fn take_pending_will(&self, client_id: &str) -> Option<PendingWill> {
        let (pending, revision) = {
            let mut wills = self
                .inner
                .pending_wills
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if wills.contains_key(client_id) {
                let revision = self.next_revision();
                (wills.remove(client_id), Some(revision))
            } else {
                (None, None)
            }
        };
        if let Some(revision) = revision {
            self.apply_store(vec![StoreOperation::DeleteWill {
                client_id: client_id.to_owned(),
                revision,
            }]);
        }
        pending
    }

    fn publish_will(&self, client_id: &str, will: Will) {
        let expires_at = will
            .message_expiry_interval
            .map(|seconds| Instant::now() + Duration::from_secs(u64::from(seconds)));
        self.publish_from(
            Some(client_id),
            Publish {
                dup: false,
                qos: will.qos,
                retain: will.retain,
                topic: will.topic,
                packet_id: None,
                payload: will.payload,
                expires_at,
                subscription_identifiers: Vec::new(),
                topic_alias: None,
            },
        );
    }

    pub fn set_session_expiry(&self, client_id: &str, expiry_interval: u32) {
        let changed = if let Some(mut session) = self.inner.sessions.get_mut(client_id) {
            if !session.online {
                false
            } else {
                session.expiry_interval = expiry_interval;
                true
            }
        } else {
            false
        };
        if changed {
            self.persist_current_session(client_id);
        }
    }

    fn remove_if_expired(&self, client_id: &str) {
        let _client_guard = self.client_lock(client_id);
        self.remove_if_expired_locked(client_id);
    }

    fn remove_if_expired_locked(&self, client_id: &str) {
        let revision = match self.inner.sessions.entry(client_id.to_owned()) {
            Entry::Occupied(entry)
                if entry
                    .get()
                    .expires_at
                    .is_some_and(|deadline| deadline <= Instant::now()) =>
            {
                let revision = self.next_revision();
                entry.remove();
                Some(revision)
            }
            Entry::Occupied(_) | Entry::Vacant(_) => None,
        };
        if let Some(revision) = revision {
            for mut bucket in self.inner.subscription_buckets.iter_mut() {
                bucket.retain(|entry| entry.client_id != client_id);
            }
            self.apply_store(vec![StoreOperation::DeleteSession {
                client_id: client_id.to_owned(),
                revision,
            }]);
        }
    }

    fn remove_expired_sessions(&self) {
        let now = Instant::now();
        let expired: Vec<String> = self
            .inner
            .sessions
            .iter()
            .filter_map(|session| {
                session
                    .expires_at
                    .is_some_and(|deadline| deadline <= now)
                    .then(|| session.key().clone())
            })
            .collect();
        for client_id in expired {
            self.remove_if_expired(&client_id);
        }
    }

    pub fn subscribe(&self, client_id: &str, filter: &str, qos: u8) -> Result<Vec<Publish>> {
        self.subscribe_with_options(
            client_id,
            filter,
            SubscriptionOptions {
                qos,
                ..SubscriptionOptions::default()
            },
        )
    }

    pub fn subscribe_with_options(
        &self,
        client_id: &str,
        filter: &str,
        options: SubscriptionOptions,
    ) -> Result<Vec<Publish>> {
        self.subscribe_with_target(client_id, DeliveryTarget::Control, filter, options)
    }

    pub fn subscribe_with_target(
        &self,
        client_id: &str,
        target: DeliveryTarget,
        filter: &str,
        options: SubscriptionOptions,
    ) -> Result<Vec<Publish>> {
        self.remove_expired_retained();
        if options.qos > 2 || options.retain_handling > 2 {
            bail!("invalid subscription QoS");
        }
        let parsed = parse_filter(filter)?;
        if parsed.shared_group.is_some() && options.no_local {
            bail!("No Local is forbidden for shared subscriptions");
        }
        let Some(mut session) = self.inner.sessions.get_mut(client_id) else {
            bail!("unknown session");
        };
        let subscription_key = SubscriptionKey {
            target,
            filter: filter.to_owned(),
        };
        let is_new = !session.subscriptions.contains_key(&subscription_key);
        session.subscriptions.insert(subscription_key, options);
        drop(session);
        if target == DeliveryTarget::Control {
            self.persist_current_session(client_id);
        }

        let bucket_key = bucket_for_filter(filter);
        let mut bucket = self
            .inner
            .subscription_buckets
            .entry(bucket_key)
            .or_default();
        bucket.retain(|entry| {
            !(entry.client_id == client_id
                && entry.target == target
                && entry.filter == parsed.filter
                && entry.shared_group == parsed.shared_group)
        });
        let is_shared = parsed.shared_group.is_some();
        bucket.push(SubscriptionEntry {
            client_id: client_id.to_owned(),
            target,
            filter: parsed.filter.clone(),
            options,
            shared_group: parsed.shared_group,
        });
        drop(bucket);

        if options.retain_handling == 2 || options.retain_handling == 1 && !is_new || is_shared {
            return Ok(Vec::new());
        }

        Ok(self
            .inner
            .retained
            .iter()
            .filter(|item| topic_matches(&parsed.filter, item.key()))
            .map(|item| {
                let mut publish = item.value().clone();
                publish.qos = publish.qos.min(options.qos).min(2);
                publish.retain = true;
                publish.packet_id = None;
                publish.subscription_identifiers =
                    options.subscription_identifier.into_iter().collect();
                publish.topic_alias = None;
                publish
            })
            .collect())
    }

    pub fn unsubscribe(&self, client_id: &str, filter: &str) {
        self.unsubscribe_target(client_id, DeliveryTarget::Control, filter);
    }

    pub fn unsubscribe_target(
        &self,
        client_id: &str,
        target: DeliveryTarget,
        filter: &str,
    ) -> bool {
        let mut removed = false;
        if let Some(mut session) = self.inner.sessions.get_mut(client_id) {
            removed = session
                .subscriptions
                .remove(&SubscriptionKey {
                    target,
                    filter: filter.to_owned(),
                })
                .is_some();
        }
        if removed && target == DeliveryTarget::Control {
            self.persist_current_session(client_id);
        }
        let Ok(parsed) = parse_filter(filter) else {
            return false;
        };
        let key = bucket_for_filter(filter);
        if let Some(mut bucket) = self.inner.subscription_buckets.get_mut(&key) {
            bucket.retain(|entry| {
                !(entry.client_id == client_id
                    && entry.target == target
                    && entry.filter == parsed.filter
                    && entry.shared_group == parsed.shared_group)
            });
        }
        removed
    }

    pub fn publish(&self, publish: Publish) -> PublishOutcome {
        self.publish_from(None, publish)
    }

    pub fn publish_from(&self, publisher: Option<&str>, publish: Publish) -> PublishOutcome {
        self.remove_expired_sessions();
        self.inner.metrics.published.fetch_add(1, Ordering::Relaxed);
        let mut retained = false;
        if publish.retain {
            if publish.payload.is_empty() || publish.is_expired() {
                let revision = match self.inner.retained.entry(publish.topic.clone()) {
                    Entry::Occupied(entry) => {
                        let revision = self.next_revision();
                        entry.remove();
                        revision
                    }
                    Entry::Vacant(entry) => {
                        let revision = self.next_revision();
                        drop(entry);
                        revision
                    }
                };
                self.apply_store(vec![StoreOperation::DeleteRetained {
                    topic: publish.topic.clone(),
                    revision,
                }]);
            } else {
                retained = true;
                let revision = match self.inner.retained.entry(publish.topic.clone()) {
                    Entry::Occupied(mut entry) => {
                        let revision = self.next_revision();
                        entry.insert(publish.clone());
                        revision
                    }
                    Entry::Vacant(entry) => {
                        let revision = self.next_revision();
                        entry.insert(publish.clone());
                        revision
                    }
                };
                self.apply_store(vec![StoreOperation::PutRetained {
                    topic: publish.topic.clone(),
                    record: PersistentRetained {
                        revision,
                        publish: Self::persistent_publish(&publish),
                    },
                }]);
            }
        }
        if publish.is_expired() {
            self.inner.metrics.dropped.fetch_add(1, Ordering::Relaxed);
            return PublishOutcome {
                retained,
                ..PublishOutcome::default()
            };
        }

        let topic_bucket = bucket_for_topic(&publish.topic).to_owned();
        let mut normal: HashMap<(String, DeliveryTarget), (SubscriptionOptions, Vec<u32>)> =
            HashMap::new();
        let mut shared: HashMap<(String, String), Vec<SubscriptionEntry>> = HashMap::new();
        for bucket_key in [topic_bucket.as_str(), "*"] {
            let Some(bucket) = self.inner.subscription_buckets.get(bucket_key) else {
                continue;
            };
            for entry in bucket.iter() {
                if !topic_matches(&entry.filter, &publish.topic)
                    || entry.options.no_local && publisher == Some(entry.client_id.as_str())
                {
                    continue;
                }
                if let Some(group) = &entry.shared_group {
                    if !self.target_is_online(&entry.client_id, entry.target) {
                        continue;
                    }
                    shared
                        .entry((group.clone(), entry.filter.clone()))
                        .or_default()
                        .push(entry.clone());
                } else {
                    normal
                        .entry((entry.client_id.clone(), entry.target))
                        .and_modify(|(existing, identifiers)| {
                            existing.qos = existing.qos.max(entry.options.qos);
                            existing.retain_as_published |= entry.options.retain_as_published;
                            if let Some(identifier) = entry.options.subscription_identifier {
                                identifiers.push(identifier);
                            }
                        })
                        .or_insert_with(|| {
                            (
                                entry.options,
                                entry.options.subscription_identifier.into_iter().collect(),
                            )
                        });
                }
            }
        }
        let matched = normal.len() + shared.len();
        let mut accepted = 0;
        for ((client_id, target), (options, mut identifiers)) in normal {
            identifiers.sort_unstable();
            identifiers.dedup();
            accepted +=
                usize::from(self.deliver(&client_id, target, &publish, options, identifiers));
        }
        for ((group, filter), candidates) in shared {
            let key = format!("{group}\0{filter}");
            let cursor = self
                .inner
                .shared_cursor
                .entry(key)
                .or_insert_with(|| AtomicU64::new(0));
            let cursor_value = cursor.fetch_add(1, Ordering::Relaxed);
            let candidate_count =
                u64::try_from(candidates.len()).expect("candidate count fits u64");
            let index = usize::try_from(cursor_value % candidate_count)
                .expect("modulo candidate count fits usize");
            let selected = &candidates[index];
            accepted += usize::from(
                self.deliver(
                    &selected.client_id,
                    selected.target,
                    &publish,
                    selected.options,
                    selected
                        .options
                        .subscription_identifier
                        .into_iter()
                        .collect(),
                ),
            );
        }
        PublishOutcome {
            matched,
            accepted,
            retained,
        }
    }

    fn deliver(
        &self,
        client_id: &str,
        target: DeliveryTarget,
        publish: &Publish,
        options: SubscriptionOptions,
        subscription_identifiers: Vec<u32>,
    ) -> bool {
        if publish.is_expired() {
            return false;
        }
        let qos = publish.qos.min(options.qos).min(2);
        let outgoing = Publish {
            dup: false,
            qos,
            retain: options.retain_as_published && publish.retain,
            topic: publish.topic.clone(),
            packet_id: None,
            payload: publish.payload.clone(),
            expires_at: publish.expires_at,
            subscription_identifiers,
            topic_alias: None,
        };
        if qos == 0 {
            self.send_qos0(client_id, target, outgoing)
        } else {
            self.send_or_queue_qos1(client_id, target, outgoing)
        }
    }

    pub fn deliver_prepared(&self, client_id: &str, publish: Publish) {
        self.deliver_prepared_target(client_id, DeliveryTarget::Control, publish);
    }

    pub fn deliver_prepared_target(
        &self,
        client_id: &str,
        target: DeliveryTarget,
        publish: Publish,
    ) {
        if publish.is_expired() {
            self.inner.metrics.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if publish.qos == 0 {
            self.send_qos0(client_id, target, publish);
        } else {
            self.send_or_queue_qos1(client_id, target, publish);
        }
    }

    fn send_qos0(&self, client_id: &str, target: DeliveryTarget, publish: Publish) -> bool {
        if publish.is_expired() {
            self.inner.metrics.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        if self.try_send_packet_target(client_id, target, Packet::Publish(publish)) {
            self.inner.metrics.delivered.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            self.inner.metrics.dropped.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    fn send_or_queue_qos1(
        &self,
        client_id: &str,
        target: DeliveryTarget,
        mut publish: Publish,
    ) -> bool {
        if publish.is_expired() {
            self.inner.metrics.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let online = self.target_is_online(client_id, target);
        let mut packet_to_send = None;
        let mut queued = false;
        let mut dropped = false;
        if let Some(mut session) = self.inner.sessions.get_mut(client_id) {
            let active_publishes = Self::active_publish_count(&session);
            if online
                && session.inflight.len() < self.inner.inflight_limit
                && active_publishes < session.receive_maximum
            {
                let packet_id = self.next_available_packet_id(&session);
                publish.packet_id = Some(packet_id);
                let phase = if publish.qos == 2 {
                    InflightPhase::Rec
                } else {
                    InflightPhase::Ack
                };
                session.inflight.push_back(InflightEntry {
                    publish: publish.clone(),
                    target,
                    phase,
                    sent_on_connection: true,
                    last_sent: Instant::now(),
                });
                packet_to_send = Some(Packet::Publish(publish));
            } else if self.inner.offline_queue_limit > 0
                && (target == DeliveryTarget::Control && (online || session.expiry_interval != 0)
                    || target != DeliveryTarget::Control && online)
            {
                publish.packet_id = None;
                if session.offline_queue.len() == self.inner.offline_queue_limit {
                    session.offline_queue.pop_front();
                    dropped = true;
                }
                session
                    .offline_queue
                    .push_back(QueuedDelivery { publish, target });
                queued = true;
            } else {
                dropped = true;
            }
        } else {
            dropped = true;
        }
        if target == DeliveryTarget::Control && self.inner.sessions.contains_key(client_id) {
            self.persist_current_session(client_id);
        }
        if dropped {
            self.inner.metrics.dropped.fetch_add(1, Ordering::Relaxed);
        }
        packet_to_send.is_some_and(|packet| self.send_first_delivery(client_id, target, packet))
            || queued
    }

    fn target_is_online(&self, client_id: &str, target: DeliveryTarget) -> bool {
        match target {
            DeliveryTarget::Control => self.inner.clients.contains_key(client_id),
            DeliveryTarget::Data { connection, stream } => {
                self.inner
                    .data_streams
                    .contains_key(&(client_id.to_owned(), connection, stream))
            }
        }
    }

    fn try_send_packet_target(
        &self,
        client_id: &str,
        target: DeliveryTarget,
        packet: Packet,
    ) -> bool {
        match target {
            DeliveryTarget::Control => {
                let Some(client) = self.inner.clients.get(client_id) else {
                    return false;
                };
                if client.sender.try_send(Outbound::Packet(packet)).is_ok() {
                    true
                } else {
                    let _ = client.disconnect.try_send(());
                    false
                }
            }
            DeliveryTarget::Data { connection, stream } => self
                .inner
                .data_streams
                .get(&(client_id.to_owned(), connection, stream))
                .is_some_and(|handle| {
                    if handle.sender.try_send(Outbound::Packet(packet)).is_ok() {
                        true
                    } else {
                        let _ = handle.disconnect.try_send(());
                        false
                    }
                }),
        }
    }

    fn send_first_delivery(&self, client_id: &str, target: DeliveryTarget, packet: Packet) -> bool {
        if self.try_send_packet_target(client_id, target, packet) {
            self.inner.metrics.delivered.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    pub fn puback(&self, client_id: &str, packet_id: u16) {
        self.puback_target(client_id, DeliveryTarget::Control, packet_id);
    }

    pub fn puback_target(&self, client_id: &str, target: DeliveryTarget, packet_id: u16) {
        let mut removed = false;
        if let Some(mut session) = self.inner.sessions.get_mut(client_id) {
            if let Some(index) = session.inflight.iter().position(|entry| {
                entry.target == target
                    && entry.publish.packet_id == Some(packet_id)
                    && entry.phase == InflightPhase::Ack
            }) {
                session.inflight.remove(index);
                removed = true;
            }
        }
        if removed && target == DeliveryTarget::Control {
            self.persist_current_session(client_id);
        }
        if removed {
            self.activate_replayable(client_id);
            self.promote_queued(client_id);
        }
    }

    pub fn pubrec(&self, client_id: &str, packet_id: u16) -> bool {
        self.pubrec_target(client_id, DeliveryTarget::Control, packet_id)
    }

    pub fn pubrec_target(&self, client_id: &str, target: DeliveryTarget, packet_id: u16) -> bool {
        let mut found = false;
        let mut released_publish_slot = false;
        if let Some(mut session) = self.inner.sessions.get_mut(client_id) {
            if let Some(entry) = session
                .inflight
                .iter_mut()
                .find(|entry| entry.target == target && entry.publish.packet_id == Some(packet_id))
            {
                match entry.phase {
                    InflightPhase::Rec => {
                        entry.phase = InflightPhase::Comp;
                        entry.last_sent = Instant::now();
                        found = true;
                        released_publish_slot = true;
                    }
                    InflightPhase::Comp => {
                        entry.last_sent = Instant::now();
                        found = true;
                    }
                    InflightPhase::Ack => {}
                }
            }
        }
        if found && target == DeliveryTarget::Control {
            self.persist_current_session(client_id);
        }
        if found {
            self.try_send_packet_target(client_id, target, Packet::PubRel(packet_id));
        }
        if released_publish_slot {
            self.activate_replayable(client_id);
            self.promote_queued(client_id);
        }
        found
    }

    pub fn pubcomp(&self, client_id: &str, packet_id: u16) {
        self.pubcomp_target(client_id, DeliveryTarget::Control, packet_id);
    }

    pub fn pubcomp_target(&self, client_id: &str, target: DeliveryTarget, packet_id: u16) {
        let mut removed = false;
        if let Some(mut session) = self.inner.sessions.get_mut(client_id) {
            if let Some(index) = session.inflight.iter().position(|entry| {
                entry.target == target
                    && entry.publish.packet_id == Some(packet_id)
                    && entry.phase == InflightPhase::Comp
            }) {
                session.inflight.remove(index);
                removed = true;
            }
        }
        if removed && target == DeliveryTarget::Control {
            self.persist_current_session(client_id);
        }
        if removed {
            self.activate_replayable(client_id);
            self.promote_queued(client_id);
        }
    }

    pub fn retry_due(&self, client_id: &str, interval: Duration) {
        let removed = self.remove_expired_deliveries(client_id);
        if removed > 0 {
            self.inner.metrics.dropped.fetch_add(
                u64::try_from(removed).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
            self.activate_replayable(client_id);
            self.promote_queued(client_id);
        }
        let now = Instant::now();
        let packets: Vec<(DeliveryTarget, Packet)> = self
            .inner
            .sessions
            .get_mut(client_id)
            .map(|mut session| {
                session
                    .inflight
                    .iter_mut()
                    .filter(|entry| {
                        entry.sent_on_connection && now.duration_since(entry.last_sent) >= interval
                    })
                    .map(|entry| {
                        entry.last_sent = now;
                        let packet = match entry.phase {
                            InflightPhase::Ack | InflightPhase::Rec => {
                                let mut publish = entry.publish.clone();
                                publish.dup = true;
                                Packet::Publish(publish)
                            }
                            InflightPhase::Comp => Packet::PubRel(
                                entry
                                    .publish
                                    .packet_id
                                    .expect("inflight publish has packet id"),
                            ),
                        };
                        (entry.target, packet)
                    })
                    .collect()
            })
            .unwrap_or_default();
        for (target, packet) in packets {
            self.try_send_packet_target(client_id, target, packet);
        }
    }

    fn replay_session(&self, client_id: &str) {
        let removed = self.remove_expired_deliveries(client_id);
        if removed > 0 {
            self.inner.metrics.dropped.fetch_add(
                u64::try_from(removed).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
        }
        self.activate_replayable(client_id);
        self.promote_queued(client_id);
    }

    fn activate_replayable(&self, client_id: &str) {
        let packets: Vec<(DeliveryTarget, Packet)> = self
            .inner
            .sessions
            .get_mut(client_id)
            .map(|mut session| {
                let now = Instant::now();
                let mut active_publishes = Self::active_publish_count(&session);
                let receive_maximum = session.receive_maximum;
                let mut packets = Vec::new();
                for entry in &mut session.inflight {
                    if entry.sent_on_connection {
                        continue;
                    }
                    match entry.phase {
                        InflightPhase::Ack | InflightPhase::Rec
                            if active_publishes < receive_maximum =>
                        {
                            entry.sent_on_connection = true;
                            entry.last_sent = now;
                            active_publishes += 1;
                            let mut publish = entry.publish.clone();
                            publish.dup = true;
                            packets.push((entry.target, Packet::Publish(publish)));
                        }
                        InflightPhase::Comp => {
                            entry.sent_on_connection = true;
                            entry.last_sent = now;
                            packets.push((
                                entry.target,
                                Packet::PubRel(
                                    entry
                                        .publish
                                        .packet_id
                                        .expect("inflight publish has packet id"),
                                ),
                            ));
                        }
                        InflightPhase::Ack | InflightPhase::Rec => {}
                    }
                }
                packets
            })
            .unwrap_or_default();
        for (target, packet) in packets {
            self.try_send_packet_target(client_id, target, packet);
        }
    }

    fn promote_queued(&self, client_id: &str) {
        let mut packets: Vec<(DeliveryTarget, Packet)> = Vec::new();
        let mut expired = 0_u64;
        if let Some(mut session) = self.inner.sessions.get_mut(client_id) {
            let mut active_publishes = Self::active_publish_count(&session);
            while session.inflight.len() < self.inner.inflight_limit
                && active_publishes < session.receive_maximum
            {
                let delivery = loop {
                    let Some(candidate) = session.offline_queue.pop_front() else {
                        break None;
                    };
                    if candidate.publish.is_expired() {
                        expired = expired.saturating_add(1);
                    } else {
                        break Some(candidate);
                    }
                };
                let Some(mut delivery) = delivery else {
                    break;
                };
                let target = delivery.target;
                let publish = &mut delivery.publish;
                let packet_id = self.next_available_packet_id(&session);
                publish.packet_id = Some(packet_id);
                let phase = if publish.qos == 2 {
                    InflightPhase::Rec
                } else {
                    InflightPhase::Ack
                };
                session.inflight.push_back(InflightEntry {
                    publish: publish.clone(),
                    target,
                    phase,
                    sent_on_connection: true,
                    last_sent: Instant::now(),
                });
                active_publishes += 1;
                packets.push((target, Packet::Publish(publish.clone())));
            }
        }
        if !packets.is_empty() || expired > 0 {
            self.persist_current_session(client_id);
        }
        if expired > 0 {
            self.inner
                .metrics
                .dropped
                .fetch_add(expired, Ordering::Relaxed);
        }
        for (target, packet) in packets {
            self.send_first_delivery(client_id, target, packet);
        }
    }

    fn next_available_packet_id(&self, session: &Session) -> u16 {
        loop {
            let packet_id = self.next_packet_id();
            if !session
                .inflight
                .iter()
                .any(|entry| entry.publish.packet_id == Some(packet_id))
            {
                return packet_id;
            }
        }
    }

    fn active_publish_count(session: &Session) -> usize {
        session
            .inflight
            .iter()
            .filter(|entry| {
                entry.sent_on_connection
                    && matches!(entry.phase, InflightPhase::Ack | InflightPhase::Rec)
            })
            .count()
    }

    fn remove_expired_deliveries(&self, client_id: &str) -> usize {
        let mut removed = 0;
        if let Some(mut session) = self.inner.sessions.get_mut(client_id) {
            session.inflight.retain(|entry| {
                let keep = entry.phase == InflightPhase::Comp || !entry.publish.is_expired();
                removed += usize::from(!keep);
                keep
            });
            session.offline_queue.retain(|delivery| {
                let keep = !delivery.publish.is_expired();
                removed += usize::from(!keep);
                keep
            });
        }
        if removed > 0 {
            self.persist_current_session(client_id);
        }
        removed
    }

    fn remove_expired_retained(&self) {
        let expired: Vec<String> = self
            .inner
            .retained
            .iter()
            .filter_map(|message| message.is_expired().then(|| message.key().clone()))
            .collect();
        for topic in expired {
            let revision = match self.inner.retained.entry(topic.clone()) {
                Entry::Occupied(entry) if entry.get().is_expired() => {
                    let revision = self.next_revision();
                    entry.remove();
                    Some(revision)
                }
                Entry::Occupied(_) | Entry::Vacant(_) => None,
            };
            if let Some(revision) = revision {
                self.apply_store(vec![StoreOperation::DeleteRetained { topic, revision }]);
            }
        }
    }

    fn next_packet_id(&self) -> u16 {
        loop {
            let id = self
                .inner
                .outbound_packet_id
                .fetch_add(1, Ordering::Relaxed);
            if id != 0 {
                return id;
            }
        }
    }

    pub fn clients_snapshot_bounded(
        &self,
        node: &str,
        maximum: usize,
        mut matches: impl FnMut(&str, Option<&str>, bool) -> bool,
    ) -> std::result::Result<Vec<ClientSnapshot>, SnapshotLimitExceeded> {
        self.remove_expired_sessions();
        let mut snapshots = Vec::new();
        for session in &self.inner.sessions {
            if !matches(session.key(), session.principal.as_deref(), session.online) {
                continue;
            }
            if snapshots.len() == maximum {
                return Err(SnapshotLimitExceeded);
            }
            snapshots.push(ClientSnapshot {
                clientid: session.key().clone(),
                username: session.principal.clone(),
                node: node.to_owned(),
                connected: session.online,
                online: session.online,
                last_alive_epoch_ms: session.last_alive_epoch_ms,
                expiry_interval: session.expiry_interval,
                subscriptions_cnt: session.subscriptions.len(),
                inflight_cnt: session.inflight.len(),
                mqueue_len: session.offline_queue.len(),
                receive_maximum: session.receive_maximum,
                durable: session.expiry_interval != 0,
            });
        }
        snapshots.sort_by(|left, right| left.clientid.cmp(&right.clientid));
        Ok(snapshots)
    }

    #[must_use]
    pub fn get_client(&self, client_id: &str, node: &str) -> Option<ClientSnapshot> {
        self.remove_if_expired(client_id);
        self.inner
            .sessions
            .get(client_id)
            .map(|session| ClientSnapshot {
                clientid: client_id.to_owned(),
                username: session.principal.clone(),
                node: node.to_owned(),
                connected: session.online,
                online: session.online,
                last_alive_epoch_ms: session.last_alive_epoch_ms,
                expiry_interval: session.expiry_interval,
                subscriptions_cnt: session.subscriptions.len(),
                inflight_cnt: session.inflight.len(),
                mqueue_len: session.offline_queue.len(),
                receive_maximum: session.receive_maximum,
                durable: session.expiry_interval != 0,
            })
    }

    pub fn subscriptions_snapshot_bounded(
        &self,
        maximum: usize,
        mut matches: impl FnMut(&str, &str, SubscriptionOptions, bool, &'static str) -> bool,
    ) -> std::result::Result<Vec<SubscriptionSnapshot>, SnapshotLimitExceeded> {
        self.remove_expired_sessions();
        let mut snapshots = Vec::new();
        for session in &self.inner.sessions {
            for (key, options) in &session.subscriptions {
                let durable = key.target == DeliveryTarget::Control && session.expiry_interval != 0;
                let target = match key.target {
                    DeliveryTarget::Control => "control",
                    DeliveryTarget::Data { .. } => "quic_data",
                };
                if !matches(session.key(), &key.filter, *options, durable, target) {
                    continue;
                }
                if snapshots.len() == maximum {
                    return Err(SnapshotLimitExceeded);
                }
                snapshots.push(SubscriptionSnapshot {
                    clientid: session.key().clone(),
                    topic: key.filter.clone(),
                    qos: options.qos,
                    nl: options.no_local,
                    rap: options.retain_as_published,
                    rh: options.retain_handling,
                    durable,
                    target,
                });
            }
        }
        snapshots.sort_by(|left, right| {
            (&left.clientid, &left.topic, left.target).cmp(&(
                &right.clientid,
                &right.topic,
                right.target,
            ))
        });
        Ok(snapshots)
    }

    #[must_use]
    pub fn client_subscriptions(&self, client_id: &str) -> Option<Vec<SubscriptionSnapshot>> {
        self.remove_if_expired(client_id);
        let session = self.inner.sessions.get(client_id)?;
        let mut snapshots = session
            .subscriptions
            .iter()
            .map(|(key, options)| SubscriptionSnapshot {
                clientid: client_id.to_owned(),
                topic: key.filter.clone(),
                qos: options.qos,
                nl: options.no_local,
                rap: options.retain_as_published,
                rh: options.retain_handling,
                durable: key.target == DeliveryTarget::Control && session.expiry_interval != 0,
                target: match key.target {
                    DeliveryTarget::Control => "control",
                    DeliveryTarget::Data { .. } => "quic_data",
                },
            })
            .collect::<Vec<_>>();
        snapshots
            .sort_by(|left, right| (&left.topic, left.target).cmp(&(&right.topic, right.target)));
        Some(snapshots)
    }

    pub fn retained_snapshot_bounded(
        &self,
        maximum: usize,
        mut matches: impl FnMut(&str) -> bool,
    ) -> std::result::Result<Vec<RetainedSnapshot>, SnapshotLimitExceeded> {
        self.remove_expired_retained();
        let mut snapshots = Vec::new();
        for message in &self.inner.retained {
            if !matches(message.key()) {
                continue;
            }
            if snapshots.len() == maximum {
                return Err(SnapshotLimitExceeded);
            }
            snapshots.push(RetainedSnapshot {
                topic: message.key().clone(),
                qos: message.qos,
                payload_size: message.payload.len(),
                expires_at_epoch_ms: message.expires_at.map(Self::instant_to_epoch_ms),
            });
        }
        snapshots.sort_by(|left, right| left.topic.cmp(&right.topic));
        Ok(snapshots)
    }

    #[must_use]
    pub fn get_retained(&self, topic: &str) -> Option<RetainedDetailSnapshot> {
        self.remove_expired_retained();
        self.inner.retained.get(topic).map(|message| {
            let summary = RetainedSnapshot {
                topic: topic.to_owned(),
                qos: message.qos,
                payload_size: message.payload.len(),
                expires_at_epoch_ms: message.expires_at.map(Self::instant_to_epoch_ms),
            };
            RetainedDetailSnapshot {
                summary,
                payload: message.payload.to_vec(),
            }
        })
    }

    #[must_use]
    pub fn metrics_snapshot(&self) -> MetricsSnapshot {
        let metrics = &self.inner.metrics;
        MetricsSnapshot {
            connections_accepted: metrics.accepted.load(Ordering::Relaxed),
            connections: metrics.connected.load(Ordering::Relaxed),
            messages_published: metrics.published.load(Ordering::Relaxed),
            messages_delivered: metrics.delivered.load(Ordering::Relaxed),
            messages_dropped: metrics.dropped.load(Ordering::Relaxed),
        }
    }

    #[must_use]
    pub fn stats(&self) -> StatsSnapshot {
        self.remove_expired_sessions();
        self.remove_expired_retained();
        StatsSnapshot {
            connections: self.inner.clients.len(),
            sessions: self.inner.sessions.len(),
            subscriptions: self
                .inner
                .sessions
                .iter()
                .map(|session| session.subscriptions.len())
                .sum(),
            retained: self.inner.retained.len(),
        }
    }

    pub async fn kick_or_delete_client(&self, client_id: &str) -> Result<bool> {
        let completion = {
            let _client_guard = self.client_lock(client_id);
            if let Some(client) = self.inner.clients.get(client_id) {
                let session_matches = self.inner.sessions.get(client_id).is_some_and(|session| {
                    session.online && session.online_generation == Some(client.token)
                });
                if !session_matches {
                    bail!("online client has no matching session generation");
                }
                let (completion, receiver) = oneshot::channel();
                client
                    .administrative_disconnect
                    .try_send(AdministrativeDisconnect { completion })
                    .map_err(|error| {
                        anyhow::anyhow!("enqueue administrative disconnect: {error}")
                    })?;
                Some(receiver)
            } else {
                let Some(session) = self.inner.sessions.get(client_id) else {
                    return Ok(false);
                };
                if session.online || session.online_generation.is_some() {
                    bail!("online session has no matching client handle");
                }
                drop(session);
                self.clear_session(client_id, true);
                None
            }
        };
        if let Some(completion) = completion {
            tokio::time::timeout(ADMIN_DISCONNECT_TIMEOUT, completion)
                .await
                .map_err(|_| anyhow::anyhow!("administrative disconnect timed out"))?
                .map_err(|_| {
                    anyhow::anyhow!("connection closed before administrative disconnect completed")
                })?;
        }
        Ok(true)
    }

    pub fn admin_subscribe(
        &self,
        client_id: &str,
        filter: &str,
        options: SubscriptionOptions,
    ) -> Result<SubscriptionSnapshot> {
        let _client_guard = self.client_lock(client_id);
        let Some(client) = self.inner.clients.get(client_id) else {
            bail!("unknown online session");
        };
        let generation = client.token;
        drop(client);
        let durable = self
            .inner
            .sessions
            .get(client_id)
            .filter(|session| session.online && session.online_generation == Some(generation))
            .map(|session| session.expiry_interval != 0)
            .context("unknown online session")?;
        let retained = self.subscribe_with_options(client_id, filter, options)?;
        for publish in retained {
            self.deliver_prepared(client_id, publish);
        }
        Ok(SubscriptionSnapshot {
            clientid: client_id.to_owned(),
            topic: filter.to_owned(),
            qos: options.qos,
            nl: options.no_local,
            rap: options.retain_as_published,
            rh: options.retain_handling,
            durable,
            target: "control",
        })
    }

    pub fn admin_unsubscribe(&self, client_id: &str, filter: &str) -> Result<bool> {
        parse_filter(filter)?;
        let _client_guard = self.client_lock(client_id);
        let Some(client) = self.inner.clients.get(client_id) else {
            bail!("unknown online session");
        };
        let generation = client.token;
        drop(client);
        if !self
            .inner
            .sessions
            .get(client_id)
            .is_some_and(|session| session.online && session.online_generation == Some(generation))
        {
            bail!("unknown online session");
        }
        Ok(self.unsubscribe_target(client_id, DeliveryTarget::Control, filter))
    }

    pub fn delete_retained(&self, topic: &str) -> bool {
        let revision = match self.inner.retained.entry(topic.to_owned()) {
            Entry::Occupied(entry) => {
                let revision = self.next_revision();
                entry.remove();
                revision
            }
            Entry::Vacant(_) => return false,
        };
        self.apply_store(vec![StoreOperation::DeleteRetained {
            topic: topic.to_owned(),
            revision,
        }]);
        true
    }

    pub fn clear_retained(&self) {
        let topics: Vec<_> = self
            .inner
            .retained
            .iter()
            .map(|message| message.key().clone())
            .collect();
        let mut operations = Vec::with_capacity(topics.len());
        for topic in topics {
            if let Entry::Occupied(entry) = self.inner.retained.entry(topic.clone()) {
                let revision = self.next_revision();
                entry.remove();
                operations.push(StoreOperation::DeleteRetained { topic, revision });
            }
        }
        if !operations.is_empty() {
            self.apply_store(operations);
        }
    }

    #[must_use]
    pub fn status(&self) -> Status {
        self.remove_expired_sessions();
        self.remove_expired_retained();
        Status {
            version: env!("CARGO_PKG_VERSION"),
            connections: self.inner.clients.len(),
            sessions: self.inner.sessions.len(),
            subscriptions: self
                .inner
                .subscription_buckets
                .iter()
                .map(|bucket| bucket.len())
                .sum(),
            retained: self.inner.retained.len(),
        }
    }

    #[must_use]
    pub fn prometheus(&self) -> String {
        let metrics = &self.inner.metrics;
        format!(
            concat!(
                "# TYPE rustmq_connections_accepted_total counter\n",
                "rustmq_connections_accepted_total {}\n",
                "# TYPE rustmq_connections gauge\n",
                "rustmq_connections {}\n",
                "# TYPE rustmq_messages_published_total counter\n",
                "rustmq_messages_published_total {}\n",
                "# TYPE rustmq_messages_delivered_total counter\n",
                "rustmq_messages_delivered_total {}\n",
                "# TYPE rustmq_messages_dropped_total counter\n",
                "rustmq_messages_dropped_total {}\n"
            ),
            metrics.accepted.load(Ordering::Relaxed),
            metrics.connected.load(Ordering::Relaxed),
            metrics.published.load(Ordering::Relaxed),
            metrics.delivered.load(Ordering::Relaxed),
            metrics.dropped.load(Ordering::Relaxed),
        )
    }
}
