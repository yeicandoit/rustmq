use std::{
    collections::{HashMap, VecDeque},
    sync::{
        atomic::{AtomicU16, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use anyhow::{bail, Result};
use dashmap::DashMap;
use serde::Serialize;
use tokio::sync::mpsc;

use crate::{
    protocol::{Packet, Publish, Will},
    topic::{bucket_for_filter, bucket_for_topic, parse_filter, topic_matches},
};

#[derive(Clone, Debug)]
pub enum Outbound {
    Packet(Packet),
}

#[derive(Clone)]
struct ClientHandle {
    token: u64,
    sender: mpsc::Sender<Outbound>,
    disconnect: mpsc::Sender<()>,
    will: Option<Will>,
}

#[derive(Clone, Debug)]
struct SubscriptionEntry {
    client_id: String,
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

#[derive(Clone, Debug, Default)]
struct Session {
    expiry_interval: u32,
    expires_at: Option<Instant>,
    receive_maximum: usize,
    subscriptions: HashMap<String, SubscriptionOptions>,
    inflight: VecDeque<InflightEntry>,
    offline_queue: VecDeque<Publish>,
}

#[derive(Clone, Debug)]
struct InflightEntry {
    publish: Publish,
    phase: InflightPhase,
    sent_on_connection: bool,
    last_sent: Instant,
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

struct BrokerInner {
    clients: DashMap<String, ClientHandle>,
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
    metrics: Metrics,
}

struct PendingWill {
    generation: u64,
    will: Will,
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
        Self {
            inner: Arc::new(BrokerInner {
                clients: DashMap::new(),
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
                metrics: Metrics::default(),
            }),
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
        let ConnectionOptions {
            clean_start,
            expiry_interval,
            receive_maximum,
            will,
        } = options;
        let pending_will = self.take_pending_will(client_id);
        if clean_start {
            if let Some(will) = pending_will {
                self.publish_will(client_id, will);
            }
        }
        self.remove_if_expired(client_id);
        if clean_start {
            self.remove_session(client_id);
        }
        let session_present = !clean_start && self.inner.sessions.contains_key(client_id);
        self.inner
            .sessions
            .entry(client_id.to_owned())
            .or_insert_with(|| Session {
                expiry_interval,
                expires_at: None,
                receive_maximum: usize::from(receive_maximum),
                subscriptions: HashMap::new(),
                inflight: VecDeque::new(),
                offline_queue: VecDeque::new(),
            });
        if let Some(mut session) = self.inner.sessions.get_mut(client_id) {
            session.expiry_interval = expiry_interval;
            session.expires_at = None;
            session.receive_maximum = usize::from(receive_maximum);
            for entry in &mut session.inflight {
                entry.sent_on_connection = false;
            }
        }
        let token = self.inner.connection_token.fetch_add(1, Ordering::Relaxed);
        if let Some(old) = self.inner.clients.insert(
            client_id.to_owned(),
            ClientHandle {
                token,
                sender,
                disconnect,
                will,
            },
        ) {
            if let Some(will) = old.will {
                if clean_start || will.delay_interval == 0 {
                    self.publish_will(client_id, will);
                }
            }
            let _ = old.disconnect.try_send(());
        } else {
            self.inner.metrics.connected.fetch_add(1, Ordering::Relaxed);
        }
        self.replay_session(client_id);
        (token, session_present)
    }

    pub fn unregister(&self, client_id: &str, token: u64) -> bool {
        let is_current = self
            .inner
            .clients
            .get(client_id)
            .is_some_and(|handle| handle.token == token);
        if !is_current {
            return false;
        }
        self.inner.clients.remove(client_id);
        self.inner.metrics.connected.fetch_sub(1, Ordering::Relaxed);
        if let Some(mut session) = self.inner.sessions.get_mut(client_id) {
            for entry in &mut session.inflight {
                entry.sent_on_connection = false;
            }
        }
        let expiry_interval = self
            .inner
            .sessions
            .get(client_id)
            .map(|session| session.expiry_interval);
        match expiry_interval {
            Some(0) => self.remove_session(client_id),
            Some(u32::MAX) => {}
            Some(seconds) => {
                if let Some(mut session) = self.inner.sessions.get_mut(client_id) {
                    session.expires_at =
                        Some(Instant::now() + Duration::from_secs(u64::from(seconds)));
                }
            }
            None => {}
        }
        true
    }

    pub fn schedule_will(&self, client_id: &str, will: Will, session_expiry: u32) {
        let delay = if session_expiry == u32::MAX {
            will.delay_interval
        } else {
            will.delay_interval.min(session_expiry)
        };
        if delay == 0 {
            self.publish_will(client_id, will);
            return;
        }
        let generation = self.inner.will_generation.fetch_add(1, Ordering::Relaxed);
        {
            let mut pending = self
                .inner
                .pending_wills
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            pending.insert(client_id.to_owned(), PendingWill { generation, will });
        }
        let broker = self.clone();
        let client_id = client_id.to_owned();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(u64::from(delay))).await;
            if let Some(will) = broker.take_pending_will_generation(&client_id, generation) {
                broker.publish_will(&client_id, will);
            }
        });
    }

    fn take_pending_will(&self, client_id: &str) -> Option<Will> {
        self.inner
            .pending_wills
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(client_id)
            .map(|pending| pending.will)
    }

    fn take_pending_will_generation(&self, client_id: &str, generation: u64) -> Option<Will> {
        let mut pending = self
            .inner
            .pending_wills
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if pending
            .get(client_id)
            .is_some_and(|will| will.generation == generation)
        {
            pending.remove(client_id).map(|will| will.will)
        } else {
            None
        }
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
        if let Some(mut session) = self.inner.sessions.get_mut(client_id) {
            session.expiry_interval = expiry_interval;
        }
    }

    fn remove_if_expired(&self, client_id: &str) {
        let expired = self
            .inner
            .sessions
            .get(client_id)
            .and_then(|session| session.expires_at)
            .is_some_and(|deadline| deadline <= Instant::now());
        if expired {
            self.remove_session(client_id);
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
            self.remove_session(&client_id);
        }
    }

    fn remove_session(&self, client_id: &str) {
        self.inner.sessions.remove(client_id);
        for mut bucket in self.inner.subscription_buckets.iter_mut() {
            bucket.retain(|entry| entry.client_id != client_id);
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
        let is_new = !session.subscriptions.contains_key(filter);
        session.subscriptions.insert(filter.to_owned(), options);
        drop(session);

        let bucket_key = bucket_for_filter(filter);
        let mut bucket = self
            .inner
            .subscription_buckets
            .entry(bucket_key)
            .or_default();
        bucket.retain(|entry| {
            !(entry.client_id == client_id
                && entry.filter == parsed.filter
                && entry.shared_group == parsed.shared_group)
        });
        let is_shared = parsed.shared_group.is_some();
        bucket.push(SubscriptionEntry {
            client_id: client_id.to_owned(),
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
        if let Some(mut session) = self.inner.sessions.get_mut(client_id) {
            session.subscriptions.remove(filter);
        }
        let Ok(parsed) = parse_filter(filter) else {
            return;
        };
        let key = bucket_for_filter(filter);
        if let Some(mut bucket) = self.inner.subscription_buckets.get_mut(&key) {
            bucket.retain(|entry| {
                !(entry.client_id == client_id
                    && entry.filter == parsed.filter
                    && entry.shared_group == parsed.shared_group)
            });
        }
    }

    pub fn publish(&self, publish: Publish) {
        self.publish_from(None, publish);
    }

    pub fn publish_from(&self, publisher: Option<&str>, publish: Publish) {
        self.remove_expired_sessions();
        self.inner.metrics.published.fetch_add(1, Ordering::Relaxed);
        if publish.retain {
            if publish.payload.is_empty() || publish.is_expired() {
                self.inner.retained.remove(&publish.topic);
            } else {
                self.inner
                    .retained
                    .insert(publish.topic.clone(), publish.clone());
            }
        }
        if publish.is_expired() {
            self.inner.metrics.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }

        let topic_bucket = bucket_for_topic(&publish.topic).to_owned();
        let mut normal: HashMap<String, (SubscriptionOptions, Vec<u32>)> = HashMap::new();
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
                    if !self.inner.clients.contains_key(&entry.client_id) {
                        continue;
                    }
                    shared
                        .entry((group.clone(), entry.filter.clone()))
                        .or_default()
                        .push(entry.clone());
                } else {
                    normal
                        .entry(entry.client_id.clone())
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
        for (client_id, (options, mut identifiers)) in normal {
            identifiers.sort_unstable();
            identifiers.dedup();
            self.deliver(&client_id, &publish, options, identifiers);
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
            self.deliver(
                &selected.client_id,
                &publish,
                selected.options,
                selected
                    .options
                    .subscription_identifier
                    .into_iter()
                    .collect(),
            );
        }
    }

    fn deliver(
        &self,
        client_id: &str,
        publish: &Publish,
        options: SubscriptionOptions,
        subscription_identifiers: Vec<u32>,
    ) {
        if publish.is_expired() {
            return;
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
            self.send_qos0(client_id, outgoing);
        } else {
            self.send_or_queue_qos1(client_id, outgoing);
        }
    }

    pub fn deliver_prepared(&self, client_id: &str, publish: Publish) {
        if publish.is_expired() {
            self.inner.metrics.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if publish.qos == 0 {
            self.send_qos0(client_id, publish);
        } else {
            self.send_or_queue_qos1(client_id, publish);
        }
    }

    fn send_qos0(&self, client_id: &str, publish: Publish) {
        if publish.is_expired() {
            self.inner.metrics.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let Some(client) = self.inner.clients.get(client_id) else {
            return;
        };
        if client
            .sender
            .try_send(Outbound::Packet(Packet::Publish(publish)))
            .is_ok()
        {
            self.inner.metrics.delivered.fetch_add(1, Ordering::Relaxed);
        } else {
            self.inner.metrics.dropped.fetch_add(1, Ordering::Relaxed);
            let _ = client.disconnect.try_send(());
        }
    }

    fn send_or_queue_qos1(&self, client_id: &str, mut publish: Publish) {
        if publish.is_expired() {
            self.inner.metrics.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let online = self.inner.clients.contains_key(client_id);
        let mut packet_to_send = None;
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
                    phase,
                    sent_on_connection: true,
                    last_sent: Instant::now(),
                });
                packet_to_send = Some(Packet::Publish(publish));
            } else if (online || session.expiry_interval != 0) && self.inner.offline_queue_limit > 0
            {
                publish.packet_id = None;
                if session.offline_queue.len() == self.inner.offline_queue_limit {
                    session.offline_queue.pop_front();
                    dropped = true;
                }
                session.offline_queue.push_back(publish);
            } else {
                dropped = true;
            }
        } else {
            dropped = true;
        }
        if dropped {
            self.inner.metrics.dropped.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(packet) = packet_to_send {
            self.send_first_delivery(client_id, packet);
        }
    }

    fn try_send_packet(&self, client_id: &str, packet: Packet) -> bool {
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

    fn send_first_delivery(&self, client_id: &str, packet: Packet) {
        if self.try_send_packet(client_id, packet) {
            self.inner.metrics.delivered.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn puback(&self, client_id: &str, packet_id: u16) {
        let mut removed = false;
        if let Some(mut session) = self.inner.sessions.get_mut(client_id) {
            if let Some(index) = session.inflight.iter().position(|entry| {
                entry.publish.packet_id == Some(packet_id) && entry.phase == InflightPhase::Ack
            }) {
                session.inflight.remove(index);
                removed = true;
            }
        }
        if removed {
            self.activate_replayable(client_id);
            self.promote_queued(client_id);
        }
    }

    pub fn pubrec(&self, client_id: &str, packet_id: u16) -> bool {
        let mut found = false;
        let mut released_publish_slot = false;
        if let Some(mut session) = self.inner.sessions.get_mut(client_id) {
            if let Some(entry) = session
                .inflight
                .iter_mut()
                .find(|entry| entry.publish.packet_id == Some(packet_id))
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
        if found {
            self.try_send_packet(client_id, Packet::PubRel(packet_id));
        }
        if released_publish_slot {
            self.activate_replayable(client_id);
            self.promote_queued(client_id);
        }
        found
    }

    pub fn pubcomp(&self, client_id: &str, packet_id: u16) {
        let mut removed = false;
        if let Some(mut session) = self.inner.sessions.get_mut(client_id) {
            if let Some(index) = session.inflight.iter().position(|entry| {
                entry.publish.packet_id == Some(packet_id) && entry.phase == InflightPhase::Comp
            }) {
                session.inflight.remove(index);
                removed = true;
            }
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
        let packets: Vec<Packet> = self
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
                        match entry.phase {
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
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        for packet in packets {
            self.try_send_packet(client_id, packet);
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
        let packets: Vec<Packet> = self
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
                            packets.push(Packet::Publish(publish));
                        }
                        InflightPhase::Comp => {
                            entry.sent_on_connection = true;
                            entry.last_sent = now;
                            packets.push(Packet::PubRel(
                                entry
                                    .publish
                                    .packet_id
                                    .expect("inflight publish has packet id"),
                            ));
                        }
                        InflightPhase::Ack | InflightPhase::Rec => {}
                    }
                }
                packets
            })
            .unwrap_or_default();
        for packet in packets {
            self.try_send_packet(client_id, packet);
        }
    }

    fn promote_queued(&self, client_id: &str) {
        let mut packets = Vec::new();
        let mut expired = 0_u64;
        if let Some(mut session) = self.inner.sessions.get_mut(client_id) {
            let mut active_publishes = Self::active_publish_count(&session);
            while session.inflight.len() < self.inner.inflight_limit
                && active_publishes < session.receive_maximum
            {
                let mut publish = loop {
                    let Some(candidate) = session.offline_queue.pop_front() else {
                        break None;
                    };
                    if candidate.is_expired() {
                        expired = expired.saturating_add(1);
                    } else {
                        break Some(candidate);
                    }
                };
                let Some(mut publish) = publish.take() else {
                    break;
                };
                let packet_id = self.next_available_packet_id(&session);
                publish.packet_id = Some(packet_id);
                let phase = if publish.qos == 2 {
                    InflightPhase::Rec
                } else {
                    InflightPhase::Ack
                };
                session.inflight.push_back(InflightEntry {
                    publish: publish.clone(),
                    phase,
                    sent_on_connection: true,
                    last_sent: Instant::now(),
                });
                active_publishes += 1;
                packets.push(Packet::Publish(publish));
            }
        }
        if expired > 0 {
            self.inner
                .metrics
                .dropped
                .fetch_add(expired, Ordering::Relaxed);
        }
        for packet in packets {
            self.send_first_delivery(client_id, packet);
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
            session.offline_queue.retain(|publish| {
                let keep = !publish.is_expired();
                removed += usize::from(!keep);
                keep
            });
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
            self.inner.retained.remove(&topic);
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
