use std::{
    collections::HashMap,
    net::IpAddr,
    str::FromStr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use anyhow::Result;
use arc_swap::ArcSwap;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use dashmap::DashMap;
use ipnet::IpNet;
use regex::Regex;

use crate::persistence::{DurableStore, PersistentBan, StoreOperation};

pub const MAX_BANS: usize = 10_000;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BanKind {
    ClientId,
    Username,
    PeerHost,
    ClientIdRegex,
    UsernameRegex,
    PeerHostNetwork,
}

impl BanKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClientId => "clientid",
            Self::Username => "username",
            Self::PeerHost => "peerhost",
            Self::ClientIdRegex => "clientid_re",
            Self::UsernameRegex => "username_re",
            Self::PeerHostNetwork => "peerhost_net",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "clientid" => Some(Self::ClientId),
            "username" => Some(Self::Username),
            "peerhost" => Some(Self::PeerHost),
            "clientid_re" => Some(Self::ClientIdRegex),
            "username_re" => Some(Self::UsernameRegex),
            "peerhost_net" => Some(Self::PeerHostNetwork),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct BanView {
    pub kind: BanKind,
    pub who: String,
    pub by: String,
    pub reason: String,
    pub at_epoch_s: u64,
    pub until_epoch_s: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct NewBan {
    pub kind: BanKind,
    pub who: String,
    pub by: String,
    pub reason: String,
    pub at_epoch_s: u64,
    pub until_epoch_s: Option<u64>,
}

#[derive(Clone)]
struct BanRecord {
    view: BanView,
    revision: u64,
}

impl BanRecord {
    fn from_persistent(record: PersistentBan) -> Self {
        Self {
            view: BanView {
                kind: BanKind::parse(&record.kind).expect("validated persisted ban kind"),
                who: record.who,
                by: record.by,
                reason: record.reason,
                at_epoch_s: record.at_epoch_s,
                until_epoch_s: record.until_epoch_s,
            },
            revision: record.revision,
        }
    }

    fn persistent(&self) -> PersistentBan {
        PersistentBan {
            kind: self.view.kind.as_str().to_owned(),
            who: self.view.who.clone(),
            revision: self.revision,
            by: self.view.by.clone(),
            reason: self.view.reason.clone(),
            at_epoch_s: self.view.at_epoch_s,
            until_epoch_s: self.view.until_epoch_s,
        }
    }

    fn active_at(&self, now_epoch_s: u64) -> bool {
        self.view
            .until_epoch_s
            .is_none_or(|until| until > now_epoch_s)
    }
}

struct RegexRule {
    record: Arc<BanRecord>,
    pattern: Regex,
}

struct NetworkRule {
    record: Arc<BanRecord>,
    network: IpNet,
}

#[derive(Default)]
struct RuleSnapshot {
    client_ids: Vec<RegexRule>,
    usernames: Vec<RegexRule>,
    peer_networks: Vec<NetworkRule>,
}

#[derive(Debug)]
pub enum BanError {
    InvalidKind,
    InvalidWho(String),
    AlreadyExists,
    Capacity,
    NotFound,
    Unavailable,
}

struct BanCatalogInner {
    by_id: DashMap<String, Arc<BanRecord>>,
    client_ids: DashMap<String, Arc<BanRecord>>,
    usernames: DashMap<String, Arc<BanRecord>>,
    peer_hosts: DashMap<IpAddr, Arc<BanRecord>>,
    rules: ArcSwap<RuleSnapshot>,
    mutation: Mutex<()>,
    revision: AtomicU64,
    store: Arc<dyn DurableStore>,
}

#[derive(Clone)]
pub struct BanCatalog {
    inner: Arc<BanCatalogInner>,
}

impl BanCatalog {
    pub fn from_snapshot(
        records: HashMap<String, PersistentBan>,
        store: Arc<dyn DurableStore>,
        next_revision: u64,
    ) -> Self {
        let catalog = Self {
            inner: Arc::new(BanCatalogInner {
                by_id: DashMap::with_capacity(records.len()),
                client_ids: DashMap::new(),
                usernames: DashMap::new(),
                peer_hosts: DashMap::new(),
                rules: ArcSwap::from_pointee(RuleSnapshot::default()),
                mutation: Mutex::new(()),
                revision: AtomicU64::new(next_revision),
                store,
            }),
        };
        for (id, record) in records {
            let record = Arc::new(BanRecord::from_persistent(record));
            catalog.install_exact(&record);
            catalog.inner.by_id.insert(id, record);
        }
        catalog.rebuild_rules();
        catalog
    }

    pub fn create(
        &self,
        request: NewBan,
        now_epoch_s: u64,
    ) -> std::result::Result<BanView, BanError> {
        if request
            .until_epoch_s
            .is_some_and(|until| until <= now_epoch_s)
        {
            return Err(BanError::InvalidWho(
                "Cannot create an expired banned entry".to_owned(),
            ));
        }
        if request.at_epoch_s > i64::MAX as u64
            || request
                .until_epoch_s
                .is_some_and(|until| until > i64::MAX as u64)
        {
            return Err(BanError::InvalidWho(
                "ban timestamps exceed the supported RFC 3339 range".to_owned(),
            ));
        }
        let who = normalize_who(request.kind, &request.who)?;
        let id = ban_storage_key(request.kind, &who);
        let _guard = self
            .inner
            .mutation
            .lock()
            .map_err(|_| BanError::Unavailable)?;
        if self
            .inner
            .by_id
            .get(&id)
            .is_some_and(|record| record.active_at(now_epoch_s))
        {
            return Err(BanError::AlreadyExists);
        }
        if self.inner.by_id.len() >= MAX_BANS && !self.inner.by_id.contains_key(&id) {
            return Err(BanError::Capacity);
        }
        let record = Arc::new(BanRecord {
            view: BanView {
                kind: request.kind,
                who,
                by: request.by,
                reason: request.reason,
                at_epoch_s: request.at_epoch_s,
                until_epoch_s: request.until_epoch_s,
            },
            revision: self.next_revision(),
        });
        self.persist(vec![StoreOperation::PutBan {
            id: id.clone(),
            record: record.persistent(),
        }])?;
        if let Some(old) = self.inner.by_id.insert(id, Arc::clone(&record)) {
            self.remove_exact(&old);
        }
        self.install_exact(&record);
        self.rebuild_rules();
        Ok(record.view.clone())
    }

    pub fn delete(&self, kind: BanKind, who: &str) -> std::result::Result<(), BanError> {
        let who = normalize_who(kind, who)?;
        let id = ban_storage_key(kind, &who);
        let _guard = self
            .inner
            .mutation
            .lock()
            .map_err(|_| BanError::Unavailable)?;
        let record = self
            .inner
            .by_id
            .get(&id)
            .map(|record| Arc::clone(&record))
            .ok_or(BanError::NotFound)?;
        self.persist(vec![StoreOperation::DeleteBan {
            id: id.clone(),
            revision: self.next_revision(),
        }])?;
        self.remove_exact(&record);
        self.inner.by_id.remove(&id);
        self.rebuild_rules();
        Ok(())
    }

    pub fn clear(&self) -> std::result::Result<(), BanError> {
        let _guard = self
            .inner
            .mutation
            .lock()
            .map_err(|_| BanError::Unavailable)?;
        let ids: Vec<_> = self
            .inner
            .by_id
            .iter()
            .map(|item| item.key().clone())
            .collect();
        let operations = ids
            .iter()
            .map(|id| StoreOperation::DeleteBan {
                id: id.clone(),
                revision: self.next_revision(),
            })
            .collect();
        self.persist(operations)?;
        self.inner.by_id.clear();
        self.inner.client_ids.clear();
        self.inner.usernames.clear();
        self.inner.peer_hosts.clear();
        self.inner.rules.store(Arc::new(RuleSnapshot::default()));
        Ok(())
    }

    pub fn list(&self, now_epoch_s: u64) -> std::result::Result<Vec<BanView>, BanError> {
        self.purge_expired(now_epoch_s)?;
        let mut records: Vec<_> = self
            .inner
            .by_id
            .iter()
            .map(|record| record.view.clone())
            .collect();
        records.sort_unstable_by(|left, right| {
            left.kind
                .as_str()
                .cmp(right.kind.as_str())
                .then_with(|| left.who.cmp(&right.who))
        });
        Ok(records)
    }

    #[must_use]
    pub fn is_banned(
        &self,
        client_id: &str,
        username: Option<&str>,
        peer_host: IpAddr,
        now_epoch_s: u64,
    ) -> bool {
        if self
            .inner
            .client_ids
            .get(client_id)
            .is_some_and(|record| record.active_at(now_epoch_s))
            || username.is_some_and(|username| {
                self.inner
                    .usernames
                    .get(username)
                    .is_some_and(|record| record.active_at(now_epoch_s))
            })
            || self
                .inner
                .peer_hosts
                .get(&peer_host)
                .is_some_and(|record| record.active_at(now_epoch_s))
        {
            return true;
        }
        let rules = self.inner.rules.load();
        rules
            .client_ids
            .iter()
            .any(|rule| rule.record.active_at(now_epoch_s) && rule.pattern.is_match(client_id))
            || username.is_some_and(|username| {
                rules.usernames.iter().any(|rule| {
                    rule.record.active_at(now_epoch_s) && rule.pattern.is_match(username)
                })
            })
            || rules
                .peer_networks
                .iter()
                .any(|rule| rule.record.active_at(now_epoch_s) && rule.network.contains(&peer_host))
    }

    fn purge_expired(&self, now_epoch_s: u64) -> std::result::Result<(), BanError> {
        let _guard = self
            .inner
            .mutation
            .lock()
            .map_err(|_| BanError::Unavailable)?;
        let expired: Vec<_> = self
            .inner
            .by_id
            .iter()
            .filter(|record| {
                record
                    .view
                    .until_epoch_s
                    .is_some_and(|until| until <= now_epoch_s)
            })
            .map(|record| (record.key().clone(), Arc::clone(&record)))
            .collect();
        if expired.is_empty() {
            return Ok(());
        }
        let operations = expired
            .iter()
            .map(|(id, _)| StoreOperation::DeleteBan {
                id: id.clone(),
                revision: self.next_revision(),
            })
            .collect();
        self.persist(operations)?;
        for (id, record) in expired {
            self.remove_exact(&record);
            self.inner.by_id.remove(&id);
        }
        self.rebuild_rules();
        Ok(())
    }

    fn install_exact(&self, record: &Arc<BanRecord>) {
        match record.view.kind {
            BanKind::ClientId => {
                self.inner
                    .client_ids
                    .insert(record.view.who.clone(), Arc::clone(record));
            }
            BanKind::Username => {
                self.inner
                    .usernames
                    .insert(record.view.who.clone(), Arc::clone(record));
            }
            BanKind::PeerHost => {
                let host = record.view.who.parse().expect("validated peerhost ban");
                self.inner.peer_hosts.insert(host, Arc::clone(record));
            }
            BanKind::ClientIdRegex | BanKind::UsernameRegex | BanKind::PeerHostNetwork => {}
        }
    }

    fn remove_exact(&self, record: &BanRecord) {
        match record.view.kind {
            BanKind::ClientId => {
                self.inner.client_ids.remove(&record.view.who);
            }
            BanKind::Username => {
                self.inner.usernames.remove(&record.view.who);
            }
            BanKind::PeerHost => {
                if let Ok(host) = record.view.who.parse::<IpAddr>() {
                    self.inner.peer_hosts.remove(&host);
                }
            }
            BanKind::ClientIdRegex | BanKind::UsernameRegex | BanKind::PeerHostNetwork => {}
        }
    }

    fn rebuild_rules(&self) {
        let mut snapshot = RuleSnapshot::default();
        for record in self.inner.by_id.iter() {
            match record.view.kind {
                BanKind::ClientIdRegex => snapshot.client_ids.push(RegexRule {
                    record: Arc::clone(&record),
                    pattern: Regex::new(&record.view.who).expect("validated clientid regex"),
                }),
                BanKind::UsernameRegex => snapshot.usernames.push(RegexRule {
                    record: Arc::clone(&record),
                    pattern: Regex::new(&record.view.who).expect("validated username regex"),
                }),
                BanKind::PeerHostNetwork => snapshot.peer_networks.push(NetworkRule {
                    record: Arc::clone(&record),
                    network: record.view.who.parse().expect("validated peerhost network"),
                }),
                BanKind::ClientId | BanKind::Username | BanKind::PeerHost => {}
            }
        }
        self.inner.rules.store(Arc::new(snapshot));
    }

    fn next_revision(&self) -> u64 {
        self.inner
            .revision
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |revision| {
                revision.checked_add(1)
            })
            .unwrap_or_else(|_| {
                tracing::error!("ban revision namespace exhausted; aborting fail-closed");
                std::process::abort();
            })
    }

    fn persist(&self, operations: Vec<StoreOperation>) -> std::result::Result<(), BanError> {
        self.inner
            .store
            .apply_immediate(operations)
            .map_err(|error| {
                tracing::error!(%error, "durable ban mutation failed");
                BanError::Unavailable
            })
    }
}

pub fn normalize_who(kind: BanKind, who: &str) -> std::result::Result<String, BanError> {
    if who.is_empty() && !matches!(kind, BanKind::ClientId | BanKind::Username) {
        return Err(BanError::InvalidWho(
            "who must not be empty for this ban kind".to_owned(),
        ));
    }
    if who.as_bytes().contains(&0) {
        return Err(BanError::InvalidWho("who must not contain NUL".to_owned()));
    }
    match kind {
        BanKind::ClientId | BanKind::Username => Ok(who.to_owned()),
        BanKind::PeerHost => IpAddr::from_str(who)
            .map(|address| address.to_string())
            .map_err(|_| BanError::InvalidWho("bad peerhost".to_owned())),
        BanKind::ClientIdRegex | BanKind::UsernameRegex => Regex::new(who)
            .map(|_| who.to_owned())
            .map_err(|error| BanError::InvalidWho(format!("invalid regular expression: {error}"))),
        BanKind::PeerHostNetwork => IpNet::from_str(who)
            .map(|network| network.trunc().to_string())
            .map_err(|_| BanError::InvalidWho("bad peerhost network".to_owned())),
    }
}

#[must_use]
pub fn ban_storage_key(kind: BanKind, who: &str) -> String {
    format!(
        "{}:{}",
        kind.as_str(),
        URL_SAFE_NO_PAD.encode(who.as_bytes())
    )
}

#[must_use]
pub fn valid_ban_storage_key(id: &str) -> bool {
    let Some((kind, encoded_who)) = id.split_once(':') else {
        return false;
    };
    let Some(kind) = BanKind::parse(kind) else {
        return false;
    };
    let Ok(who) = URL_SAFE_NO_PAD.decode(encoded_who) else {
        return false;
    };
    let Ok(who) = std::str::from_utf8(&who) else {
        return false;
    };
    normalize_who(kind, who)
        .is_ok_and(|normalized| normalized == who && ban_storage_key(kind, &normalized) == id)
}

pub fn validate_persistent_ban(record: &PersistentBan) -> Result<()> {
    let kind = BanKind::parse(&record.kind)
        .ok_or_else(|| anyhow::anyhow!("invalid persisted ban kind"))?;
    let normalized = normalize_who(kind, &record.who)
        .map_err(|error| anyhow::anyhow!("invalid persisted ban who: {error:?}"))?;
    anyhow::ensure!(
        normalized == record.who,
        "persisted ban who is not canonical"
    );
    anyhow::ensure!(
        record.revision > 0 && record.revision < u64::MAX,
        "unsafe ban revision"
    );
    anyhow::ensure!(
        record.at_epoch_s <= i64::MAX as u64
            && record
                .until_epoch_s
                .is_none_or(|epoch| epoch <= i64::MAX as u64),
        "invalid ban timestamp"
    );
    Ok(())
}
