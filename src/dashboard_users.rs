use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use anyhow::Result;
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use dashmap::DashMap;
use ring::rand::{SecureRandom, SystemRandom};

use crate::persistence::{DurableStore, PersistentDashboardUser, StoreOperation};

const PASSWORD_SALT_BYTES: usize = 16;
const ARGON2_MEMORY_KIB: u32 = 19 * 1024;
const ARGON2_ITERATIONS: u32 = 2;
const ARGON2_PARALLELISM: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagementRole {
    Administrator,
}

impl ManagementRole {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Administrator => "administrator",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "administrator" => Some(Self::Administrator),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DashboardUserView {
    pub username: String,
    pub description: String,
}

#[derive(Clone, Debug)]
pub struct DashboardIdentity {
    pub username: Arc<str>,
    pub role: ManagementRole,
    pub auth_epoch: u64,
}

#[derive(Clone)]
struct DashboardUserRecord {
    username: String,
    password_hash: String,
    description: String,
    role: ManagementRole,
    auth_epoch: u64,
    revision: u64,
}

impl DashboardUserRecord {
    fn from_persistent(record: PersistentDashboardUser) -> Self {
        Self {
            username: record.username,
            password_hash: record.password_hash,
            description: record.description,
            role: ManagementRole::parse(&record.role).expect("validated Dashboard user role"),
            auth_epoch: record.auth_epoch,
            revision: record.revision,
        }
    }

    fn persistent(&self) -> PersistentDashboardUser {
        PersistentDashboardUser {
            username: self.username.clone(),
            revision: self.revision,
            password_hash: self.password_hash.clone(),
            description: self.description.clone(),
            role: self.role.as_str().to_owned(),
            auth_epoch: self.auth_epoch,
        }
    }

    fn view(&self) -> DashboardUserView {
        DashboardUserView {
            username: self.username.clone(),
            description: self.description.clone(),
        }
    }

    fn identity(&self) -> DashboardIdentity {
        DashboardIdentity {
            username: Arc::from(self.username.as_str()),
            role: self.role,
            auth_epoch: self.auth_epoch,
        }
    }
}

#[derive(Debug)]
pub enum DashboardUserError {
    InvalidUsername,
    InvalidPassword(String),
    AlreadyExists,
    NotFound,
    PasswordMismatch,
    Unavailable,
}

struct DashboardUserCatalogInner {
    by_name: DashMap<String, Arc<DashboardUserRecord>>,
    mutation: Mutex<()>,
    revision: AtomicU64,
    store: Arc<dyn DurableStore>,
}

#[derive(Clone)]
pub struct DashboardUserCatalog {
    inner: Arc<DashboardUserCatalogInner>,
}

impl DashboardUserCatalog {
    pub fn from_snapshot(
        records: HashMap<String, PersistentDashboardUser>,
        store: Arc<dyn DurableStore>,
        next_revision: u64,
    ) -> Self {
        let by_name = DashMap::with_capacity(records.len());
        for record in records.into_values() {
            let record = Arc::new(DashboardUserRecord::from_persistent(record));
            by_name.insert(record.username.clone(), record);
        }
        Self {
            inner: Arc::new(DashboardUserCatalogInner {
                by_name,
                mutation: Mutex::new(()),
                revision: AtomicU64::new(next_revision),
                store,
            }),
        }
    }

    pub fn bootstrap(
        &self,
        username: String,
        password: String,
    ) -> std::result::Result<bool, DashboardUserError> {
        validate_username(&username)?;
        validate_password(&password)?;
        let _guard = self
            .inner
            .mutation
            .lock()
            .map_err(|_| DashboardUserError::Unavailable)?;
        if self.inner.by_name.contains_key(&username) {
            return Ok(false);
        }
        let record = Arc::new(DashboardUserRecord {
            username,
            password_hash: hash_password(&password)?,
            description: "administrator".to_owned(),
            role: ManagementRole::Administrator,
            auth_epoch: 1,
            revision: self.next_revision(),
        });
        self.persist(StoreOperation::PutDashboardUser {
            username: record.username.clone(),
            record: record.persistent(),
        })?;
        self.inner.by_name.insert(record.username.clone(), record);
        Ok(true)
    }

    pub fn authenticate(&self, username: &str, password: &str) -> Option<DashboardIdentity> {
        if validate_username(username).is_err() || validate_password(password).is_err() {
            return None;
        }
        let record = self.inner.by_name.get(username)?;
        verify_password(password, &record.password_hash).then(|| record.identity())
    }

    #[must_use]
    pub fn identity_matches(&self, username: &str, role: ManagementRole, auth_epoch: u64) -> bool {
        self.inner
            .by_name
            .get(username)
            .is_some_and(|record| record.role == role && record.auth_epoch == auth_epoch)
    }

    pub fn list(&self) -> Vec<DashboardUserView> {
        let mut users: Vec<_> = self
            .inner
            .by_name
            .iter()
            .map(|record| record.view())
            .collect();
        users.sort_unstable_by(|left, right| left.username.cmp(&right.username));
        users
    }

    pub fn create(
        &self,
        username: String,
        password: String,
        description: String,
    ) -> std::result::Result<DashboardUserView, DashboardUserError> {
        validate_username(&username)?;
        validate_password(&password)?;
        let password_hash = hash_password(&password)?;
        let _guard = self
            .inner
            .mutation
            .lock()
            .map_err(|_| DashboardUserError::Unavailable)?;
        if self.inner.by_name.contains_key(&username) {
            return Err(DashboardUserError::AlreadyExists);
        }
        let record = Arc::new(DashboardUserRecord {
            username,
            password_hash,
            description,
            role: ManagementRole::Administrator,
            auth_epoch: 1,
            revision: self.next_revision(),
        });
        self.persist(StoreOperation::PutDashboardUser {
            username: record.username.clone(),
            record: record.persistent(),
        })?;
        self.inner
            .by_name
            .insert(record.username.clone(), Arc::clone(&record));
        Ok(record.view())
    }

    pub fn update_description(
        &self,
        username: &str,
        description: String,
    ) -> std::result::Result<DashboardUserView, DashboardUserError> {
        let _guard = self
            .inner
            .mutation
            .lock()
            .map_err(|_| DashboardUserError::Unavailable)?;
        let old = self
            .inner
            .by_name
            .get(username)
            .map(|record| Arc::clone(&record))
            .ok_or(DashboardUserError::NotFound)?;
        let record = Arc::new(DashboardUserRecord {
            username: old.username.clone(),
            password_hash: old.password_hash.clone(),
            description,
            role: old.role,
            auth_epoch: old.auth_epoch,
            revision: self.next_revision(),
        });
        self.persist(StoreOperation::PutDashboardUser {
            username: record.username.clone(),
            record: record.persistent(),
        })?;
        self.inner
            .by_name
            .insert(record.username.clone(), Arc::clone(&record));
        Ok(record.view())
    }

    pub fn change_password(
        &self,
        username: &str,
        old_password: &str,
        new_password: &str,
    ) -> std::result::Result<(), DashboardUserError> {
        let _guard = self
            .inner
            .mutation
            .lock()
            .map_err(|_| DashboardUserError::Unavailable)?;
        let old = self
            .inner
            .by_name
            .get(username)
            .map(|record| Arc::clone(&record))
            .ok_or(DashboardUserError::NotFound)?;
        if !verify_password(old_password, &old.password_hash) {
            return Err(DashboardUserError::PasswordMismatch);
        }
        validate_password(new_password)?;
        let auth_epoch = old
            .auth_epoch
            .checked_add(1)
            .ok_or(DashboardUserError::Unavailable)?;
        let record = Arc::new(DashboardUserRecord {
            username: old.username.clone(),
            password_hash: hash_password(new_password)?,
            description: old.description.clone(),
            role: old.role,
            auth_epoch,
            revision: self.next_revision(),
        });
        self.persist(StoreOperation::PutDashboardUser {
            username: record.username.clone(),
            record: record.persistent(),
        })?;
        self.inner.by_name.insert(record.username.clone(), record);
        Ok(())
    }

    pub fn delete(&self, username: &str) -> std::result::Result<(), DashboardUserError> {
        let _guard = self
            .inner
            .mutation
            .lock()
            .map_err(|_| DashboardUserError::Unavailable)?;
        if !self.inner.by_name.contains_key(username) {
            return Err(DashboardUserError::NotFound);
        }
        self.persist(StoreOperation::DeleteDashboardUser {
            username: username.to_owned(),
            revision: self.next_revision(),
        })?;
        self.inner.by_name.remove(username);
        Ok(())
    }

    fn next_revision(&self) -> u64 {
        self.inner
            .revision
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |revision| {
                revision.checked_add(1)
            })
            .unwrap_or_else(|_| {
                tracing::error!(
                    "Dashboard user revision namespace exhausted; aborting fail-closed"
                );
                std::process::abort();
            })
    }

    fn persist(&self, operation: StoreOperation) -> std::result::Result<(), DashboardUserError> {
        self.inner
            .store
            .apply_immediate(vec![operation])
            .map_err(|error| {
                tracing::error!(%error, "durable Dashboard user mutation failed");
                DashboardUserError::Unavailable
            })
    }
}

pub fn validate_username(username: &str) -> std::result::Result<(), DashboardUserError> {
    if username.is_empty()
        || username.len() > 100
        || !username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(DashboardUserError::InvalidUsername);
    }
    Ok(())
}

pub fn validate_password(password: &str) -> std::result::Result<(), DashboardUserError> {
    if !(8..=64).contains(&password.len()) {
        return Err(DashboardUserError::InvalidPassword(
            "The range of password length is 8~64".to_owned(),
        ));
    }
    if !password.is_ascii() {
        return Err(DashboardUserError::InvalidPassword(
            "Only ascii characters are allowed in the password".to_owned(),
        ));
    }
    const SPECIAL: &[u8] = b"!@#$%^&*()_+-=[]{}\"|;':,./<>?`~ ";
    let groups = u8::from(password.bytes().any(|byte| byte.is_ascii_alphabetic()))
        + u8::from(password.bytes().any(|byte| byte.is_ascii_digit()))
        + u8::from(password.bytes().any(|byte| SPECIAL.contains(&byte)));
    if groups < 2 {
        return Err(DashboardUserError::InvalidPassword(
            "Password must contain characters from at least two of letters, numbers, and special characters"
                .to_owned(),
        ));
    }
    Ok(())
}

fn argon2() -> std::result::Result<Argon2<'static>, DashboardUserError> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        None,
    )
    .map_err(|_| DashboardUserError::Unavailable)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn hash_password(password: &str) -> std::result::Result<String, DashboardUserError> {
    let mut salt = [0_u8; PASSWORD_SALT_BYTES];
    SystemRandom::new()
        .fill(&mut salt)
        .map_err(|_| DashboardUserError::Unavailable)?;
    let salt = SaltString::encode_b64(&salt).map_err(|_| DashboardUserError::Unavailable)?;
    argon2()?
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| DashboardUserError::Unavailable)
}

fn verify_password(password: &str, encoded: &str) -> bool {
    let Ok(hash) = PasswordHash::new(encoded) else {
        return false;
    };
    argon2().is_ok_and(|argon2| argon2.verify_password(password.as_bytes(), &hash).is_ok())
}

pub fn validate_persistent_dashboard_user(record: &PersistentDashboardUser) -> Result<()> {
    validate_username(&record.username)
        .map_err(|error| anyhow::anyhow!("invalid Dashboard username: {error:?}"))?;
    anyhow::ensure!(
        ManagementRole::parse(&record.role).is_some(),
        "invalid Dashboard user role"
    );
    anyhow::ensure!(record.auth_epoch > 0, "invalid Dashboard user auth epoch");
    anyhow::ensure!(
        record.revision > 0 && record.revision < u64::MAX,
        "unsafe Dashboard user revision"
    );
    anyhow::ensure!(
        record
            .password_hash
            .starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
        "Dashboard user password hash uses unsupported parameters"
    );
    let hash = PasswordHash::new(&record.password_hash)
        .map_err(|_| anyhow::anyhow!("invalid Dashboard user password hash"))?;
    anyhow::ensure!(
        hash.algorithm.as_str() == "argon2id",
        "Dashboard user password hash must use Argon2id"
    );
    Ok(())
}
