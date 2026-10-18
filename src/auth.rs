use std::{any::Any, fmt};

use bytes::Bytes;
use subtle::{Choice, ConstantTimeEq};

use crate::config::AuthConfig;

pub const PLAIN_METHOD: &str = "PLAIN";
pub const BAD_USERNAME_OR_PASSWORD: u8 = 0x86;
pub const BAD_AUTHENTICATION_METHOD: u8 = 0x8c;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthCredential<'a> {
    pub method: &'a str,
    pub data: Option<&'a [u8]>,
}

pub struct AuthCache {
    method: String,
    provider_state: Box<dyn Any + Send + Sync>,
}

impl AuthCache {
    #[must_use]
    pub fn new<T>(method: impl Into<String>, provider_state: T) -> Self
    where
        T: Any + Send + Sync,
    {
        Self {
            method: method.into(),
            provider_state: Box::new(provider_state),
        }
    }

    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    #[must_use]
    pub fn provider_state<T: Any>(&self) -> Option<&T> {
        self.provider_state.downcast_ref()
    }

    pub fn provider_state_mut<T: Any>(&mut self) -> Option<&mut T> {
        self.provider_state.downcast_mut()
    }
}

impl fmt::Debug for AuthCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthCache")
            .field("method", &self.method)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum AuthOutcome {
    Continue {
        cache: AuthCache,
        authentication_data: Option<Bytes>,
    },
    Success {
        principal: String,
        authentication_data: Option<Bytes>,
    },
    Error {
        reason_code: u8,
    },
}

pub trait AuthenticationProvider: Send + Sync {
    fn authenticate_standard(
        &self,
        username: Option<&str>,
        password: Option<&[u8]>,
    ) -> Result<Option<String>, u8>;

    fn start(&self, credential: AuthCredential<'_>) -> AuthOutcome;

    fn next(&self, cache: AuthCache, credential: AuthCredential<'_>) -> AuthOutcome;
}

const MAX_STATIC_CREDENTIAL_LEN: usize = 1024;

#[derive(Clone)]
struct FixedSecret {
    bytes: [u8; MAX_STATIC_CREDENTIAL_LEN],
    len: usize,
}

impl FixedSecret {
    fn new(secret: &[u8]) -> Option<Self> {
        if secret.len() > MAX_STATIC_CREDENTIAL_LEN {
            return None;
        }
        let mut bytes = [0; MAX_STATIC_CREDENTIAL_LEN];
        bytes[..secret.len()].copy_from_slice(secret);
        Some(Self {
            bytes,
            len: secret.len(),
        })
    }

    fn matches(&self, candidate: &[u8]) -> Choice {
        if candidate.len() > MAX_STATIC_CREDENTIAL_LEN {
            return Choice::from(0);
        }
        let mut candidate_bytes = [0; MAX_STATIC_CREDENTIAL_LEN];
        candidate_bytes[..candidate.len()].copy_from_slice(candidate);
        candidate_bytes.as_slice().ct_eq(self.bytes.as_slice()) & candidate.len().ct_eq(&self.len)
    }
}

#[derive(Clone)]
struct ConfiguredCredentials {
    username: FixedSecret,
    password: FixedSecret,
}

#[derive(Clone)]
enum StaticCredentials {
    Anonymous,
    Configured(Box<ConfiguredCredentials>),
    Invalid,
}

#[derive(Clone)]
pub struct StaticAuthenticationProvider {
    credentials: StaticCredentials,
}

#[derive(Debug)]
struct PlainState {
    round: u8,
}

impl StaticAuthenticationProvider {
    #[must_use]
    pub fn new(config: &AuthConfig) -> Self {
        let credentials = match (&config.username, &config.password) {
            (None, None) => StaticCredentials::Anonymous,
            (Some(username), Some(password)) => {
                match (
                    FixedSecret::new(username.as_bytes()),
                    FixedSecret::new(password.as_bytes()),
                ) {
                    (Some(username), Some(password)) => {
                        StaticCredentials::Configured(Box::new(ConfiguredCredentials {
                            username,
                            password,
                        }))
                    }
                    _ => StaticCredentials::Invalid,
                }
            }
            _ => StaticCredentials::Invalid,
        };
        Self { credentials }
    }

    pub fn authenticate_standard(
        &self,
        username: Option<&str>,
        password: Option<&[u8]>,
    ) -> Result<Option<String>, u8> {
        let (expected_user, expected_password) = match &self.credentials {
            StaticCredentials::Anonymous => return Ok(None),
            StaticCredentials::Configured(credentials) => {
                (&credentials.username, &credentials.password)
            }
            StaticCredentials::Invalid => return Err(BAD_USERNAME_OR_PASSWORD),
        };
        let Some(username) = username else {
            return Err(BAD_USERNAME_OR_PASSWORD);
        };
        let Some(password) = password else {
            return Err(BAD_USERNAME_OR_PASSWORD);
        };
        if credentials_match(
            username.as_bytes(),
            password,
            expected_user,
            expected_password,
        ) {
            Ok(Some(username.to_owned()))
        } else {
            Err(BAD_USERNAME_OR_PASSWORD)
        }
    }

    fn authenticate_plain(&self, cache: AuthCache, data: Option<&[u8]>) -> AuthOutcome {
        let (expected_user, expected_password) = match &self.credentials {
            StaticCredentials::Anonymous => {
                return AuthOutcome::Error {
                    reason_code: BAD_AUTHENTICATION_METHOD,
                };
            }
            StaticCredentials::Configured(credentials) => {
                (&credentials.username, &credentials.password)
            }
            StaticCredentials::Invalid => {
                return AuthOutcome::Error {
                    reason_code: BAD_USERNAME_OR_PASSWORD,
                };
            }
        };
        let Some(data) = data else {
            return AuthOutcome::Continue {
                cache,
                authentication_data: None,
            };
        };
        let Some((authorization_id, authentication_id, password)) = parse_sasl_plain(data) else {
            return AuthOutcome::Error {
                reason_code: BAD_USERNAME_OR_PASSWORD,
            };
        };
        let Ok(authentication_id) = std::str::from_utf8(authentication_id) else {
            return AuthOutcome::Error {
                reason_code: BAD_USERNAME_OR_PASSWORD,
            };
        };
        let authorization_matches = authorization_id.is_empty()
            || std::str::from_utf8(authorization_id).is_ok_and(|id| id == authentication_id);
        let valid = credentials_match(
            authentication_id.as_bytes(),
            password,
            expected_user,
            expected_password,
        );
        if authorization_matches && valid {
            AuthOutcome::Success {
                principal: authentication_id.to_owned(),
                authentication_data: None,
            }
        } else {
            AuthOutcome::Error {
                reason_code: BAD_USERNAME_OR_PASSWORD,
            }
        }
    }
}

impl AuthenticationProvider for StaticAuthenticationProvider {
    fn authenticate_standard(
        &self,
        username: Option<&str>,
        password: Option<&[u8]>,
    ) -> Result<Option<String>, u8> {
        StaticAuthenticationProvider::authenticate_standard(self, username, password)
    }

    fn start(&self, credential: AuthCredential<'_>) -> AuthOutcome {
        if credential.method != PLAIN_METHOD {
            return AuthOutcome::Error {
                reason_code: BAD_AUTHENTICATION_METHOD,
            };
        }
        self.authenticate_plain(
            AuthCache::new(credential.method, PlainState { round: 1 }),
            credential.data,
        )
    }

    fn next(&self, mut cache: AuthCache, credential: AuthCredential<'_>) -> AuthOutcome {
        if credential.method != cache.method {
            return AuthOutcome::Error {
                reason_code: BAD_AUTHENTICATION_METHOD,
            };
        }
        let Some(state) = cache.provider_state_mut::<PlainState>() else {
            return AuthOutcome::Error {
                reason_code: BAD_AUTHENTICATION_METHOD,
            };
        };
        if credential.data.is_none() && state.round >= 1 {
            return AuthOutcome::Error {
                reason_code: BAD_USERNAME_OR_PASSWORD,
            };
        }
        state.round = state.round.saturating_add(1);
        self.authenticate_plain(cache, credential.data)
    }
}

fn credentials_match(
    username: &[u8],
    password: &[u8],
    expected_user: &FixedSecret,
    expected_password: &FixedSecret,
) -> bool {
    bool::from(expected_user.matches(username) & expected_password.matches(password))
}

fn parse_sasl_plain(data: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let first = data.iter().position(|byte| *byte == 0)?;
    let second_relative = data.get(first + 1..)?.iter().position(|byte| *byte == 0)?;
    let second = first + 1 + second_relative;
    let authorization_id = &data[..first];
    let authentication_id = &data[first + 1..second];
    let password = &data[second + 1..];
    if authentication_id.is_empty() || password.contains(&0) {
        return None;
    }
    Some((authorization_id, authentication_id, password))
}
