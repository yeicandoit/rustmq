use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use dashmap::DashMap;
use ring::{
    digest::{Context, SHA256, SHA512},
    rand::{SecureRandom, SystemRandom},
};
use subtle::ConstantTimeEq;

use crate::persistence::{DurableStore, PersistentApiKey, StoreOperation};

pub const MAX_API_KEYS: usize = 100;
const API_SECRET_BYTES: usize = 32;
const SECRET_SALT_BYTES: usize = 16;
const SECRET_HASH_BYTES: usize = 32;
const MAX_SECRET_TEXT_BYTES: usize = 128;

#[derive(Clone, Debug)]
pub struct ApiKeyView {
    pub name: String,
    pub api_key: String,
    pub enable: bool,
    pub expired_at_epoch_s: Option<u64>,
    pub created_at_epoch_s: u64,
    pub description: String,
}

#[derive(Clone)]
struct ApiKeyRecord {
    view: ApiKeyView,
    secret_salt: [u8; SECRET_SALT_BYTES],
    secret_hash: [u8; SECRET_HASH_BYTES],
    revision: u64,
}

impl ApiKeyRecord {
    fn from_persistent(record: PersistentApiKey) -> Self {
        let secret_salt = record
            .secret_salt
            .try_into()
            .expect("validated API key salt length");
        let secret_hash = record
            .secret_hash
            .try_into()
            .expect("validated API key hash length");
        Self {
            view: ApiKeyView {
                name: record.name,
                api_key: record.api_key,
                enable: record.enable,
                expired_at_epoch_s: record.expired_at_epoch_s,
                created_at_epoch_s: record.created_at_epoch_s,
                description: record.description,
            },
            secret_salt,
            secret_hash,
            revision: record.revision,
        }
    }

    fn persistent(&self) -> PersistentApiKey {
        PersistentApiKey {
            name: self.view.name.clone(),
            revision: self.revision,
            api_key: self.view.api_key.clone(),
            secret_salt: self.secret_salt.to_vec(),
            secret_hash: self.secret_hash.to_vec(),
            enable: self.view.enable,
            expired_at_epoch_s: self.view.expired_at_epoch_s,
            created_at_epoch_s: self.view.created_at_epoch_s,
            description: self.view.description.clone(),
        }
    }
}

#[derive(Debug)]
pub enum ApiKeyError {
    InvalidName,
    AlreadyExists,
    Capacity,
    NotFound,
    Unavailable,
}

struct ApiKeyCatalogInner {
    by_name: DashMap<String, Arc<ApiKeyRecord>>,
    by_key: DashMap<String, Arc<ApiKeyRecord>>,
    mutation: Mutex<()>,
    revision: AtomicU64,
    store: Arc<dyn DurableStore>,
}

#[derive(Clone)]
pub struct ApiKeyCatalog {
    inner: Arc<ApiKeyCatalogInner>,
}

impl ApiKeyCatalog {
    pub fn from_snapshot(
        records: HashMap<String, PersistentApiKey>,
        store: Arc<dyn DurableStore>,
        next_revision: u64,
    ) -> Self {
        let by_name = DashMap::with_capacity(records.len());
        let by_key = DashMap::with_capacity(records.len());
        for record in records.into_values() {
            let record = Arc::new(ApiKeyRecord::from_persistent(record));
            by_key.insert(record.view.api_key.clone(), Arc::clone(&record));
            by_name.insert(record.view.name.clone(), record);
        }
        Self {
            inner: Arc::new(ApiKeyCatalogInner {
                by_name,
                by_key,
                mutation: Mutex::new(()),
                revision: AtomicU64::new(next_revision),
                store,
            }),
        }
    }

    pub fn list(&self) -> Vec<ApiKeyView> {
        let mut records: Vec<_> = self
            .inner
            .by_name
            .iter()
            .map(|record| record.view.clone())
            .collect();
        records.sort_unstable_by(|left, right| left.name.cmp(&right.name));
        records
    }

    pub fn get(&self, name: &str) -> Option<ApiKeyView> {
        self.inner
            .by_name
            .get(name)
            .map(|record| record.view.clone())
    }

    pub fn create(
        &self,
        name: String,
        description: String,
        enable: bool,
        expired_at_epoch_s: Option<u64>,
        created_at_epoch_s: u64,
    ) -> std::result::Result<(ApiKeyView, String), ApiKeyError> {
        if !valid_api_key_name(&name) {
            return Err(ApiKeyError::InvalidName);
        }
        let _guard = self
            .inner
            .mutation
            .lock()
            .map_err(|_| ApiKeyError::Unavailable)?;
        if self.inner.by_name.contains_key(&name) {
            return Err(ApiKeyError::AlreadyExists);
        }
        if self.inner.by_name.len() >= MAX_API_KEYS {
            return Err(ApiKeyError::Capacity);
        }

        let api_key = public_key_for_name(&name);
        if self.inner.by_key.contains_key(&api_key) {
            return Err(ApiKeyError::AlreadyExists);
        }
        let (secret, secret_salt, secret_hash) = generate_secret()?;
        let record = Arc::new(ApiKeyRecord {
            view: ApiKeyView {
                name,
                api_key,
                enable,
                expired_at_epoch_s,
                created_at_epoch_s,
                description,
            },
            secret_salt,
            secret_hash,
            revision: self.next_revision(),
        });
        self.persist(StoreOperation::PutApiKey {
            name: record.view.name.clone(),
            record: record.persistent(),
        })?;
        self.inner
            .by_key
            .insert(record.view.api_key.clone(), Arc::clone(&record));
        self.inner
            .by_name
            .insert(record.view.name.clone(), record.clone());
        Ok((record.view.clone(), secret))
    }

    pub fn update(
        &self,
        name: &str,
        description: Option<String>,
        enable: Option<bool>,
        expired_at_epoch_s: Option<u64>,
    ) -> std::result::Result<ApiKeyView, ApiKeyError> {
        let _guard = self
            .inner
            .mutation
            .lock()
            .map_err(|_| ApiKeyError::Unavailable)?;
        let old = self
            .inner
            .by_name
            .get(name)
            .map(|record| Arc::clone(&record))
            .ok_or(ApiKeyError::NotFound)?;
        let record = Arc::new(ApiKeyRecord {
            view: ApiKeyView {
                name: old.view.name.clone(),
                api_key: old.view.api_key.clone(),
                enable: enable.unwrap_or(old.view.enable),
                expired_at_epoch_s,
                created_at_epoch_s: old.view.created_at_epoch_s,
                description: description.unwrap_or_else(|| old.view.description.clone()),
            },
            secret_salt: old.secret_salt,
            secret_hash: old.secret_hash,
            revision: self.next_revision(),
        });
        self.persist(StoreOperation::PutApiKey {
            name: record.view.name.clone(),
            record: record.persistent(),
        })?;
        self.inner
            .by_key
            .insert(record.view.api_key.clone(), Arc::clone(&record));
        self.inner
            .by_name
            .insert(record.view.name.clone(), record.clone());
        Ok(record.view.clone())
    }

    pub fn delete(&self, name: &str) -> std::result::Result<(), ApiKeyError> {
        let _guard = self
            .inner
            .mutation
            .lock()
            .map_err(|_| ApiKeyError::Unavailable)?;
        let record = self
            .inner
            .by_name
            .get(name)
            .map(|record| Arc::clone(&record))
            .ok_or(ApiKeyError::NotFound)?;
        self.persist(StoreOperation::DeleteApiKey {
            name: name.to_owned(),
            revision: self.next_revision(),
        })?;
        self.inner.by_key.remove(&record.view.api_key);
        self.inner.by_name.remove(name);
        Ok(())
    }

    pub fn authorize(&self, api_key: &str, secret: &[u8], now_epoch_s: u64) -> bool {
        let Some(record) = self.inner.by_key.get(api_key) else {
            return false;
        };
        if !record.view.enable
            || record
                .view
                .expired_at_epoch_s
                .is_some_and(|expired_at| expired_at < now_epoch_s)
            || secret.len() > MAX_SECRET_TEXT_BYTES
        {
            return false;
        }
        let actual = hash_secret(&record.secret_salt, secret);
        record.secret_hash.ct_eq(&actual).into()
    }

    fn next_revision(&self) -> u64 {
        self.inner
            .revision
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |revision| {
                revision.checked_add(1)
            })
            .unwrap_or_else(|_| {
                tracing::error!("API key revision namespace exhausted; aborting fail-closed");
                std::process::abort();
            })
    }

    fn persist(&self, operation: StoreOperation) -> std::result::Result<(), ApiKeyError> {
        self.inner
            .store
            .apply_immediate(vec![operation])
            .map_err(|error| {
                tracing::error!(%error, "durable API key mutation failed");
                ApiKeyError::Unavailable
            })
    }
}

pub fn valid_api_key_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 256 {
        return false;
    }
    let mut bytes = name.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

pub fn public_key_for_name(name: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = ring::digest::digest(&SHA512, name.as_bytes());
    let mut output = String::with_capacity(16);
    for byte in &digest.as_ref()[..8] {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn generate_secret(
) -> std::result::Result<(String, [u8; SECRET_SALT_BYTES], [u8; SECRET_HASH_BYTES]), ApiKeyError> {
    let random = SystemRandom::new();
    let mut secret_bytes = [0_u8; API_SECRET_BYTES];
    random
        .fill(&mut secret_bytes)
        .map_err(|_| ApiKeyError::Unavailable)?;
    let secret = URL_SAFE_NO_PAD.encode(secret_bytes);
    let mut salt = [0_u8; SECRET_SALT_BYTES];
    random
        .fill(&mut salt)
        .map_err(|_| ApiKeyError::Unavailable)?;
    let hash = hash_secret(&salt, secret.as_bytes());
    Ok((secret, salt, hash))
}

fn hash_secret(salt: &[u8; SECRET_SALT_BYTES], secret: &[u8]) -> [u8; SECRET_HASH_BYTES] {
    let mut context = Context::new(&SHA256);
    context.update(salt);
    context.update(secret);
    context
        .finish()
        .as_ref()
        .try_into()
        .expect("SHA-256 output is always 32 bytes")
}

pub fn validate_persistent_api_key(record: &PersistentApiKey) -> Result<()> {
    anyhow::ensure!(valid_api_key_name(&record.name), "invalid API key name");
    anyhow::ensure!(
        record.api_key == public_key_for_name(&record.name),
        "API key name/public key mismatch"
    );
    anyhow::ensure!(
        record.secret_salt.len() == SECRET_SALT_BYTES,
        "invalid API key secret salt length"
    );
    anyhow::ensure!(
        record.secret_hash.len() == SECRET_HASH_BYTES,
        "invalid API key secret hash length"
    );
    anyhow::ensure!(
        record.created_at_epoch_s > 0
            && i64::try_from(record.created_at_epoch_s).is_ok()
            && record
                .expired_at_epoch_s
                .is_none_or(|epoch| i64::try_from(epoch).is_ok()),
        "invalid API key timestamp"
    );
    anyhow::ensure!(
        record.revision > 0 && record.revision < u64::MAX,
        "unsafe API key revision"
    );
    Ok(())
}
