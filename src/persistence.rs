use std::{
    collections::HashMap,
    fs,
    sync::{mpsc, Arc, Mutex},
    thread,
};

use anyhow::{bail, Context, Result};
use redb::{Database, Durability, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
use tokio::runtime::RuntimeFlavor;

use crate::{config::PersistenceConfig, topic::parse_filter};

pub const SCHEMA_VERSION: u32 = 2;

const SESSIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("sessions");
const RETAINED: TableDefinition<&str, &[u8]> = TableDefinition::new("retained");
const WILLS: TableDefinition<&str, &[u8]> = TableDefinition::new("wills");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
const SCHEMA_KEY: &str = "schema_version";
const SESSION_REVISION_PREFIX: &str = "revision/session/";
const RETAINED_REVISION_PREFIX: &str = "revision/retained/";
const WILL_REVISION_PREFIX: &str = "revision/will/";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PersistentSubscriptionOptions {
    pub qos: u8,
    pub no_local: bool,
    pub retain_as_published: bool,
    pub retain_handling: u8,
    pub subscription_identifier: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PersistentSubscription {
    pub filter: String,
    pub options: PersistentSubscriptionOptions,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PersistentPublish {
    pub dup: bool,
    pub qos: u8,
    pub retain: bool,
    pub topic: String,
    pub packet_id: Option<u16>,
    pub payload: Vec<u8>,
    pub expires_at_epoch_ms: Option<u64>,
    pub subscription_identifiers: Vec<u32>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistentInflightPhase {
    Ack,
    Rec,
    Comp,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PersistentInflight {
    pub publish: PersistentPublish,
    pub phase: PersistentInflightPhase,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PersistentQueuedDelivery {
    pub publish: PersistentPublish,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PersistentWillMessage {
    pub topic: String,
    pub payload: Vec<u8>,
    pub qos: u8,
    pub retain: bool,
    pub delay_interval: u32,
    pub message_expiry_interval: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PersistentActiveWill {
    pub generation: u64,
    pub owner: u64,
    pub will: PersistentWillMessage,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PersistentSession {
    pub client_id: String,
    pub revision: u64,
    pub principal: Option<String>,
    pub online: bool,
    pub online_generation: Option<u64>,
    pub last_alive_epoch_ms: u64,
    pub expiry_interval: u32,
    pub expires_at_epoch_ms: Option<u64>,
    pub active_will: Option<PersistentActiveWill>,
    pub receive_maximum: usize,
    pub subscriptions: Vec<PersistentSubscription>,
    pub inflight: Vec<PersistentInflight>,
    pub offline_queue: Vec<PersistentQueuedDelivery>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PersistentRetained {
    pub revision: u64,
    pub publish: PersistentPublish,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PersistentPendingWill {
    pub client_id: String,
    pub revision: u64,
    pub generation: u64,
    pub principal: Option<String>,
    pub will: PersistentWillMessage,
    pub fire_at_epoch_ms: u64,
    pub firing: bool,
}

#[derive(Default)]
pub struct StoreSnapshot {
    pub sessions: HashMap<String, PersistentSession>,
    pub retained: HashMap<String, PersistentRetained>,
    pub wills: HashMap<String, PersistentPendingWill>,
    pub maximum_revision: u64,
}

#[derive(Clone, Debug)]
pub enum StoreOperation {
    PutSession {
        client_id: String,
        record: PersistentSession,
    },
    DeleteSession {
        client_id: String,
        revision: u64,
    },
    PutRetained {
        topic: String,
        record: PersistentRetained,
    },
    DeleteRetained {
        topic: String,
        revision: u64,
    },
    PutWill {
        client_id: String,
        record: PersistentPendingWill,
    },
    DeleteWill {
        client_id: String,
        revision: u64,
    },
}

impl StoreOperation {
    fn revision(&self) -> u64 {
        match self {
            Self::PutSession { record, .. } => record.revision,
            Self::DeleteSession { revision, .. }
            | Self::DeleteRetained { revision, .. }
            | Self::DeleteWill { revision, .. } => *revision,
            Self::PutRetained { record, .. } => record.revision,
            Self::PutWill { record, .. } => record.revision,
        }
    }

    fn revision_key(&self) -> String {
        match self {
            Self::PutSession { client_id, .. } | Self::DeleteSession { client_id, .. } => {
                format!("{SESSION_REVISION_PREFIX}{client_id}")
            }
            Self::PutRetained { topic, .. } | Self::DeleteRetained { topic, .. } => {
                format!("{RETAINED_REVISION_PREFIX}{topic}")
            }
            Self::PutWill { client_id, .. } | Self::DeleteWill { client_id, .. } => {
                format!("{WILL_REVISION_PREFIX}{client_id}")
            }
        }
    }
}

pub trait DurableStore: Send + Sync {
    fn apply(&self, operations: Vec<StoreOperation>) -> Result<()>;
    fn flush(&self) -> Result<()>;
    fn is_enabled(&self) -> bool;
}

#[derive(Default)]
struct DisabledStore;

impl DurableStore for DisabledStore {
    fn apply(&self, _operations: Vec<StoreOperation>) -> Result<()> {
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        Ok(())
    }

    fn is_enabled(&self) -> bool {
        false
    }
}

type CommandAck = mpsc::SyncSender<std::result::Result<(), String>>;

enum StoreCommand {
    AtomicBatch {
        operations: Vec<StoreOperation>,
        ack: Option<CommandAck>,
    },
    Flush(CommandAck),
    Shutdown(CommandAck),
}

struct WriterStore {
    sender: mpsc::SyncSender<StoreCommand>,
    sync: bool,
    thread: Mutex<Option<thread::JoinHandle<()>>>,
}

impl WriterStore {
    fn blocking_boundary<T>(operation: impl FnOnce() -> T) -> T {
        if tokio::runtime::Handle::try_current()
            .is_ok_and(|handle| handle.runtime_flavor() == RuntimeFlavor::MultiThread)
        {
            tokio::task::block_in_place(operation)
        } else {
            operation()
        }
    }

    fn send_with_ack(&self, command: impl FnOnce(CommandAck) -> StoreCommand) -> Result<()> {
        let (ack, receiver) = mpsc::sync_channel(1);
        let command = command(ack);
        Self::blocking_boundary(|| {
            self.sender
                .send(command)
                .context("persistence writer stopped")?;
            receiver
                .recv()
                .context("persistence writer stopped before acknowledging command")?
                .map_err(anyhow::Error::msg)
        })
    }
}

impl DurableStore for WriterStore {
    fn apply(&self, operations: Vec<StoreOperation>) -> Result<()> {
        if operations.is_empty() {
            return Ok(());
        }
        if self.sync {
            self.send_with_ack(|ack| StoreCommand::AtomicBatch {
                operations,
                ack: Some(ack),
            })
        } else {
            Self::blocking_boundary(|| {
                self.sender
                    .send(StoreCommand::AtomicBatch {
                        operations,
                        ack: None,
                    })
                    .context("persistence writer stopped")
            })
        }
    }

    fn flush(&self) -> Result<()> {
        self.send_with_ack(StoreCommand::Flush)
    }

    fn is_enabled(&self) -> bool {
        true
    }
}

impl Drop for WriterStore {
    fn drop(&mut self) {
        let (ack, receiver) = mpsc::sync_channel(1);
        Self::blocking_boundary(|| {
            if self.sender.send(StoreCommand::Shutdown(ack)).is_ok() {
                let _ = receiver.recv();
            }
        });
        if let Some(handle) = self
            .thread
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            let _ = handle.join();
        }
    }
}

pub fn open_store(config: &PersistenceConfig) -> Result<(Arc<dyn DurableStore>, StoreSnapshot)> {
    if config.writer_queue_capacity == 0 {
        bail!("persistence writer_queue_capacity must be greater than zero");
    }
    if config.path.as_os_str().is_empty() {
        bail!("persistence path must not be empty");
    }
    if !config.enabled {
        return Ok((Arc::new(DisabledStore), StoreSnapshot::default()));
    }
    if let Some(parent) = config
        .path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("create persistence directory {}", parent.display()))?;
    }

    let database = Database::create(&config.path)
        .with_context(|| format!("open persistence database {}", config.path.display()))?;
    initialize_schema(&database)?;
    let mut snapshot = load_snapshot(&database)?;
    let revisions = load_revisions(&database)?;
    validate_snapshot(&snapshot, &revisions)?;
    if let Some(maximum) = revisions.values().copied().max() {
        snapshot.maximum_revision = snapshot.maximum_revision.max(maximum);
    }
    if snapshot.maximum_revision == u64::MAX {
        bail!("persistence revision namespace is exhausted");
    }
    let (sender, receiver) = mpsc::sync_channel(config.writer_queue_capacity);
    let sync = config.sync;
    let handle = thread::Builder::new()
        .name("rustmq-persistence".to_owned())
        .spawn(move || writer_loop(database, receiver, revisions, sync))
        .context("spawn persistence writer")?;
    Ok((
        Arc::new(WriterStore {
            sender,
            sync,
            thread: Mutex::new(Some(handle)),
        }),
        snapshot,
    ))
}

fn initialize_schema(database: &Database) -> Result<()> {
    let mut transaction = database.begin_write().context("begin schema transaction")?;
    transaction.set_durability(Durability::Immediate);
    {
        let sessions = transaction
            .open_table(SESSIONS)
            .context("open sessions table")?;
        let retained = transaction
            .open_table(RETAINED)
            .context("open retained table")?;
        let wills = transaction.open_table(WILLS).context("open wills table")?;
        let mut meta = transaction.open_table(META).context("open meta table")?;
        let stored_schema = meta
            .get(SCHEMA_KEY)
            .context("read persistence schema version")?
            .map(|version| version.value().to_vec());
        match stored_schema {
            Some(version) => {
                let stored: u32 = serde_json::from_slice(&version)
                    .context("decode persistence schema version")?;
                if stored != SCHEMA_VERSION {
                    bail!(
                        "unsupported persistence schema version {stored}; expected {SCHEMA_VERSION}"
                    );
                }
            }
            None => {
                if !sessions.is_empty()?
                    || !retained.is_empty()?
                    || !wills.is_empty()?
                    || !meta.is_empty()?
                {
                    bail!("persistence database has records but no schema version");
                }
                let encoded = serde_json::to_vec(&SCHEMA_VERSION)?;
                meta.insert(SCHEMA_KEY, encoded.as_slice())?;
            }
        }
    }
    transaction.commit().context("commit schema transaction")
}

fn load_snapshot(database: &Database) -> Result<StoreSnapshot> {
    let transaction = database
        .begin_read()
        .context("begin persistence snapshot")?;
    let mut snapshot = StoreSnapshot::default();
    {
        let table = transaction
            .open_table(SESSIONS)
            .context("read sessions table")?;
        for item in table.iter().context("iterate sessions table")? {
            let (key, value) = item.context("read session record")?;
            let record: PersistentSession = serde_json::from_slice(value.value())
                .with_context(|| format!("decode session record {}", key.value()))?;
            snapshot.maximum_revision = snapshot.maximum_revision.max(record.revision);
            snapshot.sessions.insert(key.value().to_owned(), record);
        }
    }
    {
        let table = transaction
            .open_table(RETAINED)
            .context("read retained table")?;
        for item in table.iter().context("iterate retained table")? {
            let (key, value) = item.context("read retained record")?;
            let record: PersistentRetained = serde_json::from_slice(value.value())
                .with_context(|| format!("decode retained record {}", key.value()))?;
            snapshot.maximum_revision = snapshot.maximum_revision.max(record.revision);
            snapshot.retained.insert(key.value().to_owned(), record);
        }
    }
    {
        let table = transaction.open_table(WILLS).context("read wills table")?;
        for item in table.iter().context("iterate wills table")? {
            let (key, value) = item.context("read pending Will record")?;
            let record: PersistentPendingWill = serde_json::from_slice(value.value())
                .with_context(|| format!("decode pending Will record {}", key.value()))?;
            snapshot.maximum_revision = snapshot.maximum_revision.max(record.revision);
            snapshot.wills.insert(key.value().to_owned(), record);
        }
    }
    Ok(snapshot)
}

fn load_revisions(database: &Database) -> Result<HashMap<String, u64>> {
    let transaction = database.begin_read().context("begin revision snapshot")?;
    let table = transaction.open_table(META).context("read meta table")?;
    let mut revisions = HashMap::new();
    for item in table.iter().context("iterate meta table")? {
        let (key, value) = item.context("read revision record")?;
        let key = key.value();
        if key == SCHEMA_KEY {
            continue;
        }
        validate_revision_key(key)?;
        let revision: u64 = serde_json::from_slice(value.value())
            .with_context(|| format!("decode revision record {key}"))?;
        if revision == 0 || revision == u64::MAX {
            bail!("persistence database contains an unsafe revision for {key}");
        }
        revisions.insert(key.to_owned(), revision);
    }
    Ok(revisions)
}

fn validate_revision_key(key: &str) -> Result<()> {
    if let Some(client_id) = key
        .strip_prefix(SESSION_REVISION_PREFIX)
        .or_else(|| key.strip_prefix(WILL_REVISION_PREFIX))
    {
        validate_client_id(client_id)
    } else if let Some(topic) = key.strip_prefix(RETAINED_REVISION_PREFIX) {
        validate_topic_name(topic)
    } else {
        bail!("unknown persistence meta key {key}")
    }
}

fn validate_snapshot(snapshot: &StoreSnapshot, revisions: &HashMap<String, u64>) -> Result<()> {
    for (client_id, record) in &snapshot.sessions {
        validate_record_revision(
            &format!("{SESSION_REVISION_PREFIX}{client_id}"),
            record.revision,
            revisions,
        )?;
        validate_session(client_id, record)?;
    }
    for (topic, record) in &snapshot.retained {
        validate_record_revision(
            &format!("{RETAINED_REVISION_PREFIX}{topic}"),
            record.revision,
            revisions,
        )?;
        validate_topic_name(topic)?;
        if record.publish.topic != *topic {
            bail!("persisted retained key/topic mismatch for {topic}");
        }
        validate_publish(&record.publish, "retained publish")?;
    }
    for (client_id, record) in &snapshot.wills {
        validate_record_revision(
            &format!("{WILL_REVISION_PREFIX}{client_id}"),
            record.revision,
            revisions,
        )?;
        validate_client_id(client_id)?;
        if record.client_id != *client_id {
            bail!("persisted Will key/client mismatch for {client_id}");
        }
        validate_generation(record.generation, "pending Will generation")?;
        validate_will(&record.will)?;
    }
    Ok(())
}

fn validate_record_revision(
    key: &str,
    record_revision: u64,
    revisions: &HashMap<String, u64>,
) -> Result<()> {
    if record_revision == 0
        || record_revision == u64::MAX
        || revisions.get(key) != Some(&record_revision)
    {
        bail!("persistence record/revision mismatch for {key}");
    }
    Ok(())
}

fn validate_session(client_id: &str, record: &PersistentSession) -> Result<()> {
    validate_client_id(client_id)?;
    if record.client_id != client_id {
        bail!("persisted session key/client mismatch for {client_id}");
    }
    if record.last_alive_epoch_ms == 0 {
        bail!("persisted session {client_id} has zero last-alive time");
    }
    match (
        record.online,
        record.online_generation,
        record.expires_at_epoch_ms,
    ) {
        (true, Some(generation), None) => {
            validate_generation(generation, "online session generation")?;
        }
        (false, None, Some(_))
            if record.expiry_interval != 0 && record.expiry_interval != u32::MAX => {}
        (false, None, None) if record.expiry_interval == u32::MAX => {}
        _ => bail!("persisted session {client_id} has an invalid online/expiry/deadline state"),
    }
    if record.receive_maximum == 0 {
        bail!("persisted session {client_id} has zero receive maximum");
    }
    match (&record.active_will, record.online_generation) {
        (Some(active), Some(owner)) if record.online => {
            validate_generation(active.generation, "active Will generation")?;
            if active.owner != owner {
                bail!("persisted session {client_id} has an active Will owner mismatch");
            }
            validate_will(&active.will)?;
        }
        (None, _) => {}
        _ => bail!("offline persisted session {client_id} contains an active Will"),
    }
    for subscription in &record.subscriptions {
        parse_filter(&subscription.filter).with_context(|| {
            format!("persisted session {client_id} has an invalid topic filter")
        })?;
        let options = &subscription.options;
        if options.qos > 2
            || options.retain_handling > 2
            || options.subscription_identifier == Some(0)
        {
            bail!("persisted session {client_id} has invalid subscription options");
        }
    }
    for inflight in &record.inflight {
        validate_publish(&inflight.publish, "inflight publish")?;
        let packet_id = inflight.publish.packet_id;
        if packet_id.is_none() || packet_id == Some(0) {
            bail!("persisted session {client_id} has inflight state without a packet id");
        }
        let valid_phase = matches!(
            (inflight.phase, inflight.publish.qos),
            (PersistentInflightPhase::Ack, 1)
                | (
                    PersistentInflightPhase::Rec | PersistentInflightPhase::Comp,
                    2
                )
        );
        if !valid_phase {
            bail!("persisted session {client_id} has an invalid QoS/inflight phase");
        }
    }
    for queued in &record.offline_queue {
        validate_publish(&queued.publish, "queued publish")?;
        if queued.publish.packet_id.is_some() || !matches!(queued.publish.qos, 1 | 2) {
            bail!("persisted session {client_id} has invalid queued delivery state");
        }
    }
    Ok(())
}

fn validate_publish(publish: &PersistentPublish, context: &str) -> Result<()> {
    validate_topic_name(&publish.topic).with_context(|| format!("invalid {context} topic"))?;
    if publish.qos > 2
        || publish.packet_id == Some(0)
        || publish.subscription_identifiers.contains(&0)
    {
        bail!("invalid {context} QoS, packet id, or subscription identifier");
    }
    Ok(())
}

fn validate_will(will: &PersistentWillMessage) -> Result<()> {
    validate_topic_name(&will.topic).context("invalid persisted Will topic")?;
    if will.qos > 2 {
        bail!("invalid persisted Will QoS {}", will.qos);
    }
    Ok(())
}

fn validate_generation(generation: u64, context: &str) -> Result<()> {
    if generation == 0 || generation == u64::MAX {
        bail!("unsafe {context}");
    }
    Ok(())
}

fn validate_client_id(client_id: &str) -> Result<()> {
    if client_id.is_empty() || client_id.as_bytes().contains(&0) {
        bail!("invalid empty or NUL-containing persisted client id");
    }
    Ok(())
}

fn validate_topic_name(topic: &str) -> Result<()> {
    if topic.is_empty()
        || topic.as_bytes().contains(&0)
        || topic.contains('+')
        || topic.contains('#')
    {
        bail!("invalid persisted topic name");
    }
    Ok(())
}

fn writer_loop(
    database: Database,
    receiver: mpsc::Receiver<StoreCommand>,
    mut revisions: HashMap<String, u64>,
    sync: bool,
) {
    while let Ok(command) = receiver.recv() {
        match command {
            StoreCommand::AtomicBatch { operations, ack } => {
                let result = apply_batch(&database, &operations, &mut revisions, sync);
                if let Err(error) = &result {
                    tracing::error!(%error, "hard persistence writer error; aborting process");
                    std::process::abort();
                }
                if let Some(ack) = ack {
                    let _ = ack.send(result.map_err(|error| format!("{error:#}")));
                }
            }
            StoreCommand::Flush(ack) => {
                let result = flush_database(&database);
                if let Err(error) = &result {
                    tracing::error!(%error, "hard persistence flush error; aborting process");
                    std::process::abort();
                }
                let _ = ack.send(result.map_err(|error| format!("{error:#}")));
            }
            StoreCommand::Shutdown(ack) => {
                let result = flush_database(&database);
                if let Err(error) = &result {
                    tracing::error!(%error, "hard persistence shutdown flush error; aborting process");
                    std::process::abort();
                }
                let _ = ack.send(result.map_err(|error| format!("{error:#}")));
                break;
            }
        }
    }
}

fn apply_batch(
    database: &Database,
    operations: &[StoreOperation],
    revisions: &mut HashMap<String, u64>,
    sync: bool,
) -> Result<()> {
    let mut batch_revisions = HashMap::new();
    let accepted: Vec<&StoreOperation> = operations
        .iter()
        .filter(|operation| {
            let key = operation.revision_key();
            let current = batch_revisions
                .get(&key)
                .copied()
                .or_else(|| revisions.get(&key).copied())
                .unwrap_or_default();
            if operation.revision() > current {
                batch_revisions.insert(key, operation.revision());
                true
            } else {
                false
            }
        })
        .collect();
    if accepted.is_empty() {
        return Ok(());
    }
    if accepted
        .iter()
        .any(|operation| operation.revision() == 0 || operation.revision() == u64::MAX)
    {
        bail!("refusing an unsafe persistence revision");
    }
    let mut transaction = database
        .begin_write()
        .context("begin persistence transaction")?;
    transaction.set_durability(if sync {
        Durability::Immediate
    } else {
        Durability::Eventual
    });
    {
        let mut sessions = transaction.open_table(SESSIONS)?;
        let mut retained = transaction.open_table(RETAINED)?;
        let mut wills = transaction.open_table(WILLS)?;
        let mut meta = transaction.open_table(META)?;
        for operation in &accepted {
            match operation {
                StoreOperation::PutSession { client_id, record } => {
                    let value = serde_json::to_vec(record)?;
                    sessions.insert(client_id.as_str(), value.as_slice())?;
                }
                StoreOperation::DeleteSession { client_id, .. } => {
                    sessions.remove(client_id.as_str())?;
                }
                StoreOperation::PutRetained { topic, record } => {
                    let value = serde_json::to_vec(record)?;
                    retained.insert(topic.as_str(), value.as_slice())?;
                }
                StoreOperation::DeleteRetained { topic, .. } => {
                    retained.remove(topic.as_str())?;
                }
                StoreOperation::PutWill { client_id, record } => {
                    let value = serde_json::to_vec(record)?;
                    wills.insert(client_id.as_str(), value.as_slice())?;
                }
                StoreOperation::DeleteWill { client_id, .. } => {
                    wills.remove(client_id.as_str())?;
                }
            }
            let key = operation.revision_key();
            let value = serde_json::to_vec(&operation.revision())?;
            meta.insert(key.as_str(), value.as_slice())?;
        }
    }
    transaction
        .commit()
        .context("commit persistence transaction")?;
    for operation in accepted {
        revisions.insert(operation.revision_key(), operation.revision());
    }
    Ok(())
}

fn flush_database(database: &Database) -> Result<()> {
    let mut transaction = database.begin_write().context("begin flush barrier")?;
    transaction.set_durability(Durability::Immediate);
    transaction.commit().context("commit flush barrier")
}
