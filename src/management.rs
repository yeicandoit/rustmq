use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::{
        rejection::{JsonRejection, QueryRejection},
        DefaultBodyLimit, Extension, Path, Query, Request, State,
    },
    http::{header, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use bytes::Bytes;
use dashmap::DashMap;
use regex::Regex;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use subtle::ConstantTimeEq;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::{
    banned::{normalize_who, BanError, BanKind, BanView, NewBan},
    broker::{
        Broker, ClientSnapshot, MetricsSnapshot, PublishOutcome, RetainedSnapshot, StatsSnapshot,
        SubscriptionOptions, SubscriptionSnapshot,
    },
    config::ManagementConfig,
    dashboard_users::{
        DashboardIdentity, DashboardUserCatalog, DashboardUserError, DashboardUserView,
        ManagementRole,
    },
    management_api_keys::{valid_api_key_name, ApiKeyCatalog, ApiKeyError, ApiKeyView},
    protocol::Publish,
    topic::{parse_filter, topic_matches, validate_topic_name},
};

const AUTH_REALM: &str = "Basic Realm=\"emqx-dashboard\"";
const MAX_CREDENTIAL_BYTES: usize = 2049;
const BEARER_TOKEN_BYTES: usize = 32;
const MAX_BEARER_TOKEN_TEXT_BYTES: usize = 128;
const MAX_RETAINED_DETAIL_BYTES: usize = 1024 * 1024;
const SNAPSHOT_CONCURRENCY: usize = 4;
const SNAPSHOT_WAIT: Duration = Duration::from_secs(1);

#[derive(Clone)]
pub struct ApiState {
    broker: Broker,
    node_id: Arc<str>,
    started: Instant,
    started_epoch_ms: u64,
    auth: ManagementAuth,
    max_page_limit: usize,
    max_body_bytes: usize,
    snapshot_slots: Arc<Semaphore>,
    id_counter: Arc<AtomicU64>,
}

impl ApiState {
    #[must_use]
    pub fn new(broker: Broker, node_id: String, config: &ManagementConfig) -> Self {
        let started_epoch_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        let auth = ManagementAuth::new(config, broker.api_keys(), broker.dashboard_users());
        Self {
            broker,
            node_id: Arc::from(node_id),
            started: Instant::now(),
            started_epoch_ms,
            auth,
            max_page_limit: config.max_page_limit,
            max_body_bytes: config.max_body_bytes,
            snapshot_slots: Arc::new(Semaphore::new(SNAPSHOT_CONCURRENCY)),
            id_counter: Arc::new(AtomicU64::new(1)),
        }
    }

    fn next_id(&self) -> String {
        let sequence = self.id_counter.fetch_add(1, Ordering::Relaxed);
        format!("{:016x}{sequence:016x}", self.started_epoch_ms)
    }
}

#[derive(Clone)]
struct AuthVerifier {
    expected: Arc<[u8; MAX_CREDENTIAL_BYTES]>,
    expected_len: usize,
}

impl AuthVerifier {
    fn new(api_key: &str, api_secret: &str) -> Self {
        let credential = format!("{api_key}:{api_secret}");
        let mut expected = [0_u8; MAX_CREDENTIAL_BYTES];
        let length = credential.len().min(MAX_CREDENTIAL_BYTES);
        expected[..length].copy_from_slice(&credential.as_bytes()[..length]);
        Self {
            expected: Arc::new(expected),
            expected_len: length,
        }
    }

    fn verify(&self, value: &[u8]) -> bool {
        constant_time_bytes_equal::<MAX_CREDENTIAL_BYTES>(
            self.expected.as_ref(),
            self.expected_len,
            value,
        )
    }
}

fn constant_time_bytes_equal<const N: usize>(
    expected: &[u8; N],
    expected_len: usize,
    value: &[u8],
) -> bool {
    let mut supplied = [0_u8; N];
    let length = value.len().min(N);
    supplied[..length].copy_from_slice(&value[..length]);
    let bytes_equal = expected.ct_eq(&supplied).unwrap_u8();
    let lengths_equal = expected_len.ct_eq(&value.len()).unwrap_u8();
    (bytes_equal & lengths_equal) == 1
}

#[derive(Clone)]
struct ManagementAuth {
    basic: AuthVerifier,
    api_keys: ApiKeyCatalog,
    users: DashboardUserCatalog,
    default_username: Arc<str>,
    bearer: Option<BearerAuth>,
}

impl ManagementAuth {
    fn new(
        config: &ManagementConfig,
        api_keys: ApiKeyCatalog,
        users: DashboardUserCatalog,
    ) -> Self {
        let bearer = config.bearer_enabled.then(|| {
            BearerAuth::new(
                users.clone(),
                Duration::from_millis(config.bearer_token_ttl_ms),
                config.bearer_max_tokens,
            )
        });
        Self {
            basic: AuthVerifier::new(
                config.api_key.as_deref().unwrap_or_default(),
                config.api_secret.as_deref().unwrap_or_default(),
            ),
            api_keys,
            users,
            default_username: Arc::from(config.dashboard_username.as_deref().unwrap_or_default()),
            bearer,
        }
    }
}

#[derive(Clone)]
struct BearerAuth {
    users: DashboardUserCatalog,
    sessions: Arc<DashMap<[u8; BEARER_TOKEN_BYTES], BearerSession>>,
    ttl: Duration,
    max_tokens: usize,
    issue_lock: Arc<Mutex<()>>,
}

struct BearerSession {
    owner: Arc<str>,
    role: ManagementRole,
    auth_epoch: u64,
    expires_at: Instant,
}

#[derive(Debug)]
enum TokenIssueError {
    Capacity,
    Unavailable,
}

enum TokenVerification {
    Valid {
        key: [u8; BEARER_TOKEN_BYTES],
        owner: Arc<str>,
        role: ManagementRole,
    },
    Expired,
    Bad,
}

impl BearerAuth {
    fn new(users: DashboardUserCatalog, ttl: Duration, max_tokens: usize) -> Self {
        Self {
            users,
            sessions: Arc::new(DashMap::new()),
            ttl,
            max_tokens,
            issue_lock: Arc::new(Mutex::new(())),
        }
    }

    fn issue(&self, identity: DashboardIdentity) -> Result<String, TokenIssueError> {
        let _guard = self
            .issue_lock
            .lock()
            .map_err(|_| TokenIssueError::Unavailable)?;
        let now = Instant::now();
        self.sessions.retain(|_, session| session.expires_at > now);
        if self.sessions.len() >= self.max_tokens {
            return Err(TokenIssueError::Capacity);
        }
        let expires_at = now
            .checked_add(self.ttl)
            .ok_or(TokenIssueError::Unavailable)?;
        let random = SystemRandom::new();
        for _ in 0..8 {
            let mut key = [0_u8; BEARER_TOKEN_BYTES];
            random
                .fill(&mut key)
                .map_err(|_| TokenIssueError::Unavailable)?;
            if self.sessions.contains_key(&key) {
                continue;
            }
            self.sessions.insert(
                key,
                BearerSession {
                    owner: identity.username,
                    role: identity.role,
                    auth_epoch: identity.auth_epoch,
                    expires_at,
                },
            );
            return Ok(URL_SAFE_NO_PAD.encode(key));
        }
        Err(TokenIssueError::Unavailable)
    }

    fn verify_and_refresh(&self, token: &str) -> TokenVerification {
        let Some(key) = decode_bearer_token(token) else {
            return TokenVerification::Bad;
        };
        let now = Instant::now();
        let Some(mut session) = self.sessions.get_mut(&key) else {
            return TokenVerification::Bad;
        };
        if session.expires_at <= now {
            drop(session);
            self.sessions.remove(&key);
            return TokenVerification::Expired;
        }
        if !self
            .users
            .identity_matches(&session.owner, session.role, session.auth_epoch)
        {
            drop(session);
            self.sessions.remove(&key);
            return TokenVerification::Bad;
        }
        if let Some(expires_at) = now.checked_add(self.ttl) {
            session.expires_at = expires_at;
        }
        TokenVerification::Valid {
            key,
            owner: Arc::clone(&session.owner),
            role: session.role,
        }
    }

    fn revoke(&self, key: &[u8; BEARER_TOKEN_BYTES], owner: &str) -> bool {
        self.sessions
            .remove_if(key, |_, session| session.owner.as_ref() == owner)
            .is_some()
    }
}

fn decode_bearer_token(token: &str) -> Option<[u8; BEARER_TOKEN_BYTES]> {
    if token.is_empty() || token.len() > MAX_BEARER_TOKEN_TEXT_BYTES {
        return None;
    }
    let decoded = URL_SAFE_NO_PAD.decode(token).ok()?;
    decoded.try_into().ok()
}

#[derive(Debug, Serialize)]
pub struct ApiError {
    code: &'static str,
    message: String,
    #[serde(skip)]
    status: StatusCode,
    #[serde(skip)]
    authenticate: bool,
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            status,
            authenticate: false,
        }
    }

    fn unauthorized(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            status: StatusCode::UNAUTHORIZED,
            authenticate: true,
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "BAD_REQUEST", message)
    }

    fn resource_limit(message: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, "RESOURCE_LIMIT", message)
    }

    fn unknown_error(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "UNKNOWN_ERROR", message)
    }

    fn not_found(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, code, message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status;
        let authenticate = self.authenticate;
        let mut response = (status, Json(self)).into_response();
        if authenticate {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static(AUTH_REALM),
            );
        }
        response
    }
}

pub fn router(state: ApiState, enabled: bool) -> Router {
    let public = Router::new()
        .route("/status", get(status))
        .route("/api/v5/status", get(status));
    if !enabled {
        return public.with_state(state);
    }

    let public = public
        .route("/api/v5/login", post(login))
        .layer(DefaultBodyLimit::max(state.max_body_bytes))
        .with_state(state.clone());
    let protected = Router::new()
        .route("/api/v5/logout", post(logout))
        .route("/api/v5/users", get(list_users).post(create_user))
        .route(
            "/api/v5/users/{username}",
            axum::routing::put(update_user).delete(delete_user),
        )
        .route(
            "/api/v5/users/{username}/change_pwd",
            post(change_user_password),
        )
        .route("/api/v5/clients", get(list_clients))
        .route(
            "/api/v5/clients/{clientid}",
            get(get_client).delete(delete_client),
        )
        .route("/api/v5/clients/kickout/bulk", post(bulk_kickout))
        .route(
            "/api/v5/clients/{clientid}/subscriptions",
            get(client_subscriptions),
        )
        .route(
            "/api/v5/clients/{clientid}/subscribe",
            post(client_subscribe),
        )
        .route(
            "/api/v5/clients/{clientid}/unsubscribe",
            post(client_unsubscribe),
        )
        .route("/api/v5/subscriptions", get(list_subscriptions))
        .route("/api/v5/publish", post(publish))
        .route("/api/v5/publish/bulk", post(publish_bulk))
        .route(
            "/api/v5/mqtt/retainer/messages",
            get(list_retained).delete(clear_retained),
        )
        .route(
            "/api/v5/mqtt/retainer/message/{*topic}",
            get(get_retained).delete(delete_retained),
        )
        .route("/api/v5/nodes", get(nodes))
        .route("/api/v5/nodes/{node}", get(node))
        .route("/api/v5/nodes/{node}/stats", get(node_stats))
        .route("/api/v5/nodes/{node}/metrics", get(node_metrics))
        .route("/api/v5/stats", get(stats))
        .route("/api/v5/metrics", get(metrics))
        .route("/api/v5/api_key", get(list_api_keys).post(create_api_key))
        .route(
            "/api/v5/api_key/{name}",
            get(get_api_key).put(update_api_key).delete(delete_api_key),
        )
        .route(
            "/api/v5/banned",
            get(list_bans).post(create_ban).delete(clear_bans),
        )
        .route("/api/v5/banned/{kind}/{*who}", delete(delete_ban))
        .fallback(api_not_found)
        .layer(DefaultBodyLimit::max(state.max_body_bytes))
        .layer(middleware::from_fn_with_state(
            state.auth.clone(),
            require_auth,
        ))
        .with_state(state);
    public.merge(protected)
}

#[derive(Clone)]
enum AuthIdentity {
    Basic,
    Bearer {
        key: [u8; BEARER_TOKEN_BYTES],
        owner: Arc<str>,
        role: ManagementRole,
    },
}

async fn require_auth(
    State(auth): State<ManagementAuth>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let identity = authenticate(&auth, request.headers().get(header::AUTHORIZATION))?;
    request.extensions_mut().insert(identity);
    Ok(next.run(request).await)
}

fn authenticate(
    auth: &ManagementAuth,
    authorization: Option<&HeaderValue>,
) -> Result<AuthIdentity, ApiError> {
    let Some(value) = authorization else {
        return Err(ApiError::unauthorized(
            "AUTHORIZATION_HEADER_ERROR",
            "Authorization header is required; Basic or Bearer authentication is supported",
        ));
    };
    let value = value.to_str().map_err(|_| {
        ApiError::unauthorized(
            "AUTHORIZATION_HEADER_ERROR",
            "Malformed Authorization header; Basic or Bearer authentication is supported",
        )
    })?;
    let Some((scheme, credential)) = value.split_once(' ') else {
        return Err(ApiError::unauthorized(
            "AUTHORIZATION_HEADER_ERROR",
            "Malformed Authorization header; Basic or Bearer authentication is supported",
        ));
    };
    if credential.is_empty() {
        return Err(ApiError::unauthorized(
            "AUTHORIZATION_HEADER_ERROR",
            "Authorization credential must not be empty",
        ));
    }

    if scheme.eq_ignore_ascii_case("basic") {
        let decoded = STANDARD.decode(credential).map_err(|_| {
            ApiError::unauthorized(
                "AUTHORIZATION_HEADER_ERROR",
                "Malformed Basic credentials; expected base64 api_key:api_secret",
            )
        })?;
        let Some(separator) = decoded.iter().position(|byte| *byte == b':') else {
            return Err(ApiError::unauthorized(
                "AUTHORIZATION_HEADER_ERROR",
                "Malformed Basic credentials; expected api_key:api_secret",
            ));
        };
        let static_valid = auth.basic.verify(&decoded);
        let (api_key, secret_with_separator) = decoded.split_at(separator);
        let dynamic_valid = std::str::from_utf8(api_key).is_ok_and(|api_key| {
            auth.api_keys.authorize(
                api_key,
                &secret_with_separator[1..],
                current_epoch_seconds(),
            )
        });
        if !(static_valid | dynamic_valid) {
            return Err(ApiError::unauthorized(
                "BAD_API_KEY_OR_SECRET",
                "Bad API key or secret",
            ));
        }
        return Ok(AuthIdentity::Basic);
    }

    if scheme.eq_ignore_ascii_case("bearer") {
        let Some(bearer) = &auth.bearer else {
            return Err(ApiError::unauthorized(
                "AUTHORIZATION_HEADER_ERROR",
                "Bearer authentication is disabled",
            ));
        };
        return match bearer.verify_and_refresh(credential) {
            TokenVerification::Valid { key, owner, role } => {
                Ok(AuthIdentity::Bearer { key, owner, role })
            }
            TokenVerification::Expired => Err(ApiError::unauthorized(
                "TOKEN_TIME_OUT",
                "Bearer token has expired",
            )),
            TokenVerification::Bad => Err(ApiError::unauthorized("BAD_TOKEN", "Bad Bearer token")),
        };
    }

    Err(ApiError::unauthorized(
        "AUTHORIZATION_HEADER_ERROR",
        "Unsupported Authorization scheme; Basic or Bearer authentication is supported",
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginRequest {
    username: String,
    password: String,
}

async fn login(
    State(state): State<ApiState>,
    body: Result<Json<LoginRequest>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Some(bearer) = state.auth.bearer.clone() else {
        return Err(ApiError::not_found(
            "NOT_FOUND",
            "Bearer authentication is disabled",
        ));
    };
    let Json(request) = json_body(body)?;
    let users = state.auth.users.clone();
    let username = request.username;
    let password = request.password;
    let identity = tokio::task::spawn_blocking(move || users.authenticate(&username, &password))
        .await
        .map_err(|_| ApiError::unknown_error("Dashboard authentication task failed"))?
        .ok_or_else(|| ApiError::unauthorized("BAD_USERNAME_OR_PWD", "Bad username or password"))?;
    let token = match bearer.issue(identity) {
        Ok(token) => token,
        Err(TokenIssueError::Capacity) => {
            return Err(ApiError::resource_limit(
                "The Bearer token capacity has been reached",
            ));
        }
        Err(TokenIssueError::Unavailable) => {
            return Err(ApiError::unknown_error("Failed to issue Bearer token"));
        }
    };
    Ok(Json(json!({
        "token": token,
        "version": env!("CARGO_PKG_VERSION"),
        "license": { "edition": "opensource" }
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LogoutRequest {
    username: String,
}

async fn logout(
    State(state): State<ApiState>,
    Extension(identity): Extension<AuthIdentity>,
    body: Result<Json<LogoutRequest>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let Json(request) = json_body(body)?;
    let AuthIdentity::Bearer { key, owner, .. } = identity else {
        return Err(ApiError::unauthorized(
            "API_KEY_NOT_ALLOW",
            "API key authentication cannot log out a Dashboard session; use a Bearer token",
        ));
    };
    let Some(bearer) = &state.auth.bearer else {
        return Err(ApiError::unauthorized("BAD_TOKEN", "Bad Bearer token"));
    };
    if owner.as_ref() != request.username || !bearer.revoke(&key, &request.username) {
        return Err(ApiError::unauthorized(
            "WRONG_TOKEN_OR_USERNAME",
            "Bearer token does not belong to the supplied username",
        ));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
struct DashboardUserResponse {
    username: String,
    description: String,
}

impl From<DashboardUserView> for DashboardUserResponse {
    fn from(user: DashboardUserView) -> Self {
        Self {
            username: user.username,
            description: user.description,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateDashboardUserRequest {
    username: String,
    password: String,
    #[serde(default)]
    description: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateDashboardUserRequest {
    description: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangeDashboardPasswordRequest {
    old_pwd: String,
    new_pwd: String,
}

async fn list_users(
    State(state): State<ApiState>,
    Extension(identity): Extension<AuthIdentity>,
) -> Result<Json<Vec<DashboardUserResponse>>, ApiError> {
    require_bearer_admin(&identity)?;
    Ok(Json(
        state
            .auth
            .users
            .list()
            .into_iter()
            .map(DashboardUserResponse::from)
            .collect(),
    ))
}

async fn create_user(
    State(state): State<ApiState>,
    Extension(identity): Extension<AuthIdentity>,
    body: Result<Json<CreateDashboardUserRequest>, JsonRejection>,
) -> Result<Json<DashboardUserResponse>, ApiError> {
    require_bearer_admin(&identity)?;
    let Json(request) = json_body(body)?;
    let users = state.auth.users.clone();
    let user = tokio::task::spawn_blocking(move || {
        users.create(request.username, request.password, request.description)
    })
    .await
    .map_err(|_| ApiError::unknown_error("Dashboard user creation task failed"))?
    .map_err(map_dashboard_user_error)?;
    Ok(Json(user.into()))
}

async fn update_user(
    State(state): State<ApiState>,
    Extension(identity): Extension<AuthIdentity>,
    Path(username): Path<String>,
    body: Result<Json<UpdateDashboardUserRequest>, JsonRejection>,
) -> Result<Json<DashboardUserResponse>, ApiError> {
    require_bearer_admin(&identity)?;
    let Json(request) = json_body(body)?;
    let user = state
        .auth
        .users
        .update_description(&username, request.description)
        .map_err(map_dashboard_user_error)?;
    Ok(Json(user.into()))
}

async fn delete_user(
    State(state): State<ApiState>,
    Extension(identity): Extension<AuthIdentity>,
    Path(username): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_bearer_admin(&identity)?;
    if username == state.auth.default_username.as_ref() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "NOT_ALLOWED",
            format!("Cannot delete user {username}"),
        ));
    }
    if matches!(
        &identity,
        AuthIdentity::Bearer { owner, .. } if owner.as_ref() == username
    ) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "NOT_ALLOWED",
            "Cannot delete self",
        ));
    }
    state
        .auth
        .users
        .delete(&username)
        .map_err(map_dashboard_user_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn change_user_password(
    State(state): State<ApiState>,
    Path(username): Path<String>,
    body: Result<Json<ChangeDashboardPasswordRequest>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let Json(request) = json_body(body)?;
    if request.old_pwd.is_empty() || request.new_pwd.is_empty() {
        return Err(ApiError::bad_request(
            "Old password or new password undefined",
        ));
    }
    let users = state.auth.users.clone();
    tokio::task::spawn_blocking(move || {
        users.change_password(&username, &request.old_pwd, &request.new_pwd)
    })
    .await
    .map_err(|_| ApiError::unknown_error("Dashboard password change task failed"))?
    .map_err(map_dashboard_user_error)?;
    Ok(StatusCode::NO_CONTENT)
}

fn require_bearer_admin(identity: &AuthIdentity) -> Result<(), ApiError> {
    match identity {
        AuthIdentity::Bearer {
            role: ManagementRole::Administrator,
            ..
        } => Ok(()),
        AuthIdentity::Basic => Err(ApiError::unauthorized(
            "API_KEY_NOT_ALLOW",
            "API key authentication cannot manage Dashboard users; use a Bearer token",
        )),
    }
}

fn map_dashboard_user_error(error: DashboardUserError) -> ApiError {
    match error {
        DashboardUserError::InvalidUsername => ApiError::bad_request(
            "Username must contain only letters, numbers, and underscores and be at most 100 bytes",
        ),
        DashboardUserError::InvalidPassword(message) => ApiError::bad_request(message),
        DashboardUserError::AlreadyExists => ApiError::bad_request("username_already_exists"),
        DashboardUserError::NotFound => ApiError::not_found("USER_NOT_FOUND", "username_not_found"),
        DashboardUserError::PasswordMismatch => ApiError::new(
            StatusCode::BAD_REQUEST,
            "ERROR_PWD_NOT_MATCH",
            "Old password not match",
        ),
        DashboardUserError::Unavailable => {
            ApiError::unknown_error("Dashboard user store is unavailable")
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ApiKeyExpiration {
    Epoch(u64),
    Text(String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateApiKeyRequest {
    name: String,
    #[serde(default)]
    desc: String,
    #[serde(default = "default_enabled")]
    enable: bool,
    expired_at: Option<ApiKeyExpiration>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateApiKeyRequest {
    desc: Option<String>,
    enable: Option<bool>,
    expired_at: Option<ApiKeyExpiration>,
}

#[derive(Serialize)]
struct ApiKeyResponse {
    name: String,
    api_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    api_secret: Option<String>,
    expired_at: String,
    created_at: String,
    desc: String,
    enable: bool,
    expired: bool,
}

async fn list_api_keys(
    State(state): State<ApiState>,
    Extension(identity): Extension<AuthIdentity>,
) -> Result<Json<Vec<ApiKeyResponse>>, ApiError> {
    require_bearer_for_api_keys(&identity)?;
    let records = state
        .auth
        .api_keys
        .list()
        .into_iter()
        .map(|record| api_key_response(record, None))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(records))
}

async fn create_api_key(
    State(state): State<ApiState>,
    Extension(identity): Extension<AuthIdentity>,
    body: Result<Json<CreateApiKeyRequest>, JsonRejection>,
) -> Result<Json<ApiKeyResponse>, ApiError> {
    require_bearer_for_api_keys(&identity)?;
    let Json(request) = json_body(body)?;
    let expired_at = parse_api_key_expiration(request.expired_at)?;
    let (record, secret) = state
        .auth
        .api_keys
        .create(
            request.name,
            request.desc,
            request.enable,
            expired_at,
            current_epoch_seconds(),
        )
        .map_err(map_api_key_error)?;
    Ok(Json(api_key_response(record, Some(secret))?))
}

async fn get_api_key(
    State(state): State<ApiState>,
    Extension(identity): Extension<AuthIdentity>,
    Path(name): Path<String>,
) -> Result<Json<ApiKeyResponse>, ApiError> {
    require_bearer_for_api_keys(&identity)?;
    validate_api_key_path(&name)?;
    let record = state
        .auth
        .api_keys
        .get(&name)
        .ok_or_else(api_key_not_found)?;
    Ok(Json(api_key_response(record, None)?))
}

async fn update_api_key(
    State(state): State<ApiState>,
    Extension(identity): Extension<AuthIdentity>,
    Path(name): Path<String>,
    body: Result<Json<UpdateApiKeyRequest>, JsonRejection>,
) -> Result<Json<ApiKeyResponse>, ApiError> {
    require_bearer_for_api_keys(&identity)?;
    validate_api_key_path(&name)?;
    let Json(request) = json_body(body)?;
    let expired_at = parse_api_key_expiration(request.expired_at)?;
    let record = state
        .auth
        .api_keys
        .update(&name, request.desc, request.enable, expired_at)
        .map_err(map_api_key_error)?;
    Ok(Json(api_key_response(record, None)?))
}

async fn delete_api_key(
    State(state): State<ApiState>,
    Extension(identity): Extension<AuthIdentity>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_bearer_for_api_keys(&identity)?;
    validate_api_key_path(&name)?;
    state
        .auth
        .api_keys
        .delete(&name)
        .map_err(map_api_key_error)?;
    Ok(StatusCode::NO_CONTENT)
}

fn require_bearer_for_api_keys(identity: &AuthIdentity) -> Result<(), ApiError> {
    if matches!(identity, AuthIdentity::Bearer { .. }) {
        Ok(())
    } else {
        Err(ApiError::unauthorized(
            "API_KEY_NOT_ALLOW",
            "API key authentication cannot manage API keys; use a Bearer token",
        ))
    }
}

fn validate_api_key_path(name: &str) -> Result<(), ApiError> {
    if valid_api_key_name(name) {
        Ok(())
    } else {
        Err(map_api_key_error(ApiKeyError::InvalidName))
    }
}

fn default_enabled() -> bool {
    true
}

fn parse_api_key_expiration(expiration: Option<ApiKeyExpiration>) -> Result<Option<u64>, ApiError> {
    match expiration {
        None => Ok(None),
        Some(ApiKeyExpiration::Epoch(epoch)) => Ok(Some(epoch)),
        Some(ApiKeyExpiration::Text(value)) if value == "infinity" => Ok(None),
        Some(ApiKeyExpiration::Text(value)) => {
            let timestamp = OffsetDateTime::parse(&value, &Rfc3339)
                .map_err(|_| ApiError::bad_request("expired_at must be RFC 3339 or infinity"))?
                .unix_timestamp();
            let timestamp = u64::try_from(timestamp)
                .map_err(|_| ApiError::bad_request("expired_at must not precede Unix epoch"))?;
            Ok(Some(timestamp))
        }
    }
}

fn api_key_response(
    record: ApiKeyView,
    api_secret: Option<String>,
) -> Result<ApiKeyResponse, ApiError> {
    let now = current_epoch_seconds();
    let expired = record
        .expired_at_epoch_s
        .is_some_and(|expired_at| expired_at < now);
    Ok(ApiKeyResponse {
        name: record.name,
        api_key: record.api_key,
        api_secret,
        expired_at: match record.expired_at_epoch_s {
            Some(epoch) => format_epoch_seconds(epoch)?,
            None => "infinity".to_owned(),
        },
        created_at: format_epoch_seconds(record.created_at_epoch_s)?,
        desc: record.description,
        enable: record.enable,
        expired,
    })
}

fn format_epoch_seconds(epoch: u64) -> Result<String, ApiError> {
    let epoch = i64::try_from(epoch)
        .map_err(|_| ApiError::unknown_error("API key timestamp is out of range"))?;
    OffsetDateTime::from_unix_timestamp(epoch)
        .map_err(|_| ApiError::unknown_error("API key timestamp is out of range"))?
        .format(&Rfc3339)
        .map_err(|_| ApiError::unknown_error("Failed to format API key timestamp"))
}

fn current_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn api_key_not_found() -> ApiError {
    ApiError::not_found("NOT_FOUND", "Name NOT FOUND")
}

fn map_api_key_error(error: ApiKeyError) -> ApiError {
    match error {
        ApiKeyError::InvalidName => ApiError::bad_request(
            "Name must match ^[A-Za-z]+[A-Za-z0-9-_]*$ and be at most 256 bytes",
        ),
        ApiKeyError::AlreadyExists => {
            ApiError::bad_request("API key name or generated key already exists")
        }
        ApiKeyError::Capacity => ApiError::bad_request("Maximum number of ApiKeys reached"),
        ApiKeyError::NotFound => api_key_not_found(),
        ApiKeyError::Unavailable => ApiError::unknown_error("API key store is unavailable"),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateBanRequest {
    #[serde(rename = "as")]
    kind: String,
    who: String,
    #[serde(default = "default_ban_by")]
    by: String,
    #[serde(default)]
    reason: String,
    at: Option<ApiKeyExpiration>,
    until: Option<ApiKeyExpiration>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct BanQuery {
    page: Option<usize>,
    limit: Option<usize>,
    clientid: Option<String>,
    username: Option<String>,
    peerhost: Option<String>,
    like_clientid: Option<String>,
    like_username: Option<String>,
    like_peerhost: Option<String>,
    like_peerhost_net: Option<String>,
}

#[derive(Serialize)]
struct BanResponse {
    #[serde(rename = "as")]
    kind: &'static str,
    who: String,
    by: String,
    reason: String,
    at: String,
    until: String,
}

async fn list_bans(
    State(state): State<ApiState>,
    query: Result<Query<BanQuery>, QueryRejection>,
) -> Result<Json<Page<BanResponse>>, ApiError> {
    let Query(mut query) = query_params(query)?;
    if let Some(peerhost) = &mut query.peerhost {
        *peerhost = normalize_who(BanKind::PeerHost, peerhost).map_err(map_ban_error)?;
    }
    let pagination = pagination(query.page, query.limit, state.max_page_limit)?;
    let filter_count = [
        query.clientid.is_some(),
        query.username.is_some(),
        query.peerhost.is_some(),
        query.like_clientid.is_some(),
        query.like_username.is_some(),
        query.like_peerhost.is_some(),
        query.like_peerhost_net.is_some(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    if filter_count > 1 {
        return Err(ApiError::bad_request("too_many_filters"));
    }
    let like = query
        .like_clientid
        .as_deref()
        .or(query.like_username.as_deref())
        .or(query.like_peerhost.as_deref())
        .or(query.like_peerhost_net.as_deref())
        .map(Regex::new)
        .transpose()
        .map_err(|error| ApiError::bad_request(format!("invalid filter regex: {error}")))?;
    let records = state
        .broker
        .bans()
        .list(current_epoch_seconds())
        .map_err(map_ban_error)?;
    let records = records
        .into_iter()
        .filter(|record| ban_matches_query(record, &query, like.as_ref()))
        .map(ban_response)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(paginate(records, pagination)))
}

async fn create_ban(
    State(state): State<ApiState>,
    body: Result<Json<CreateBanRequest>, JsonRejection>,
) -> Result<Json<BanResponse>, ApiError> {
    let Json(request) = json_body(body)?;
    let kind = BanKind::parse(&request.kind).ok_or_else(|| map_ban_error(BanError::InvalidKind))?;
    let now = current_epoch_seconds();
    let at = parse_ban_at(request.at, now)?;
    let until = parse_api_key_expiration(request.until)?;
    let record = state
        .broker
        .bans()
        .create(
            NewBan {
                kind,
                who: request.who,
                by: request.by,
                reason: request.reason,
                at_epoch_s: at,
                until_epoch_s: until,
            },
            now,
        )
        .map_err(map_ban_error)?;
    if kind == BanKind::ClientId {
        if let Err(error) = state
            .broker
            .kick_online_client_if_present(&record.who)
            .await
        {
            tracing::warn!(client_id = %record.who, %error, "ban committed but online client kick failed");
        }
    }
    Ok(Json(ban_response(record)?))
}

async fn clear_bans(State(state): State<ApiState>) -> Result<StatusCode, ApiError> {
    state.broker.bans().clear().map_err(map_ban_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_ban(
    State(state): State<ApiState>,
    Path((kind, who)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let kind = BanKind::parse(&kind).ok_or_else(|| map_ban_error(BanError::InvalidKind))?;
    state
        .broker
        .bans()
        .delete(kind, &who)
        .map_err(map_ban_error)?;
    Ok(StatusCode::NO_CONTENT)
}

fn ban_matches_query(record: &BanView, query: &BanQuery, like: Option<&Regex>) -> bool {
    if let Some(client_id) = &query.clientid {
        return record.kind == BanKind::ClientId && record.who == *client_id;
    }
    if let Some(username) = &query.username {
        return record.kind == BanKind::Username && record.who == *username;
    }
    if let Some(peerhost) = &query.peerhost {
        return record.kind == BanKind::PeerHost && record.who == *peerhost;
    }
    let Some(pattern) = like else {
        return true;
    };
    if query.like_clientid.is_some() {
        matches!(record.kind, BanKind::ClientId | BanKind::ClientIdRegex)
            && pattern.is_match(&record.who)
    } else if query.like_username.is_some() {
        matches!(record.kind, BanKind::Username | BanKind::UsernameRegex)
            && pattern.is_match(&record.who)
    } else if query.like_peerhost.is_some() {
        record.kind == BanKind::PeerHost && pattern.is_match(&record.who)
    } else {
        record.kind == BanKind::PeerHostNetwork && pattern.is_match(&record.who)
    }
}

fn default_ban_by() -> String {
    "mgmt_api".to_owned()
}

fn parse_ban_at(value: Option<ApiKeyExpiration>, default: u64) -> Result<u64, ApiError> {
    match value {
        None => Ok(default),
        Some(ApiKeyExpiration::Epoch(epoch)) => Ok(epoch),
        Some(ApiKeyExpiration::Text(value)) if value == "infinity" => {
            Err(ApiError::bad_request("at cannot be infinity"))
        }
        Some(ApiKeyExpiration::Text(value)) => {
            parse_api_key_expiration(Some(ApiKeyExpiration::Text(value)))?.ok_or_else(|| {
                ApiError::bad_request("at must be an epoch second or RFC 3339 timestamp")
            })
        }
    }
}

fn ban_response(record: BanView) -> Result<BanResponse, ApiError> {
    Ok(BanResponse {
        kind: record.kind.as_str(),
        who: record.who,
        by: record.by,
        reason: record.reason,
        at: format_epoch_seconds(record.at_epoch_s)?,
        until: match record.until_epoch_s {
            Some(until) => format_epoch_seconds(until)?,
            None => "infinity".to_owned(),
        },
    })
}

fn map_ban_error(error: BanError) -> ApiError {
    match error {
        BanError::InvalidKind => ApiError::bad_request(
            "as must be clientid, username, peerhost, clientid_re, username_re, or peerhost_net",
        ),
        BanError::InvalidWho(message) => ApiError::bad_request(message),
        BanError::AlreadyExists => ApiError::new(
            StatusCode::BAD_REQUEST,
            "ALREADY_EXISTS",
            "The banned entry already exists",
        ),
        BanError::Capacity => ApiError::resource_limit("The ban capacity has been reached"),
        BanError::NotFound => ApiError::not_found("NOT_FOUND", "Banned entry not found"),
        BanError::Unavailable => ApiError::unknown_error("Ban store is unavailable"),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusQuery {
    format: Option<String>,
}

async fn status(
    State(state): State<ApiState>,
    query: Result<Query<StatusQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query_params(query)?;
    let format = query.format.as_deref().unwrap_or("text");
    let body = match format {
        "text" => format!("Node {} is started\nrustmq is running\n", state.node_id).into_response(),
        "json" => Json(json!({
            "node_name": state.node_id.as_ref(),
            "rel_vsn": env!("CARGO_PKG_VERSION"),
            "broker_status": "started",
            "app_status": "running"
        }))
        .into_response(),
        _ => return Err(ApiError::bad_request("format must be text or json")),
    };
    let mut response = body;
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("15"));
    Ok(response)
}

#[derive(Debug, Serialize)]
struct PageMeta {
    page: usize,
    limit: usize,
    count: usize,
    hasnext: bool,
}

#[derive(Debug, Serialize)]
struct Page<T> {
    data: Vec<T>,
    meta: PageMeta,
}

#[derive(Clone, Copy)]
struct Pagination {
    page: usize,
    limit: usize,
    start: usize,
    end: usize,
}

fn pagination(
    page: Option<usize>,
    limit: Option<usize>,
    maximum: usize,
) -> Result<Pagination, ApiError> {
    let page = page.unwrap_or(1);
    let limit = limit.unwrap_or(100);
    if page == 0 {
        return Err(ApiError::bad_request("page must be at least 1"));
    }
    if limit == 0 || limit > maximum {
        return Err(ApiError::bad_request(format!(
            "limit must be between 1 and {maximum}"
        )));
    }
    let start = page
        .checked_sub(1)
        .and_then(|offset| offset.checked_mul(limit))
        .ok_or_else(|| ApiError::bad_request("page offset overflow"))?;
    let end = start
        .checked_add(limit)
        .ok_or_else(|| ApiError::bad_request("page range overflow"))?;
    Ok(Pagination {
        page,
        limit,
        start,
        end,
    })
}

fn paginate<T>(data: Vec<T>, pagination: Pagination) -> Page<T> {
    let count = data.len();
    let start = pagination.start.min(count);
    let hasnext = pagination.end < count;
    let data = data
        .into_iter()
        .skip(start)
        .take(pagination.limit)
        .collect();
    Page {
        data,
        meta: PageMeta {
            page: pagination.page,
            limit: pagination.limit,
            count,
            hasnext,
        },
    }
}

async fn snapshot_permit(state: &ApiState) -> Result<OwnedSemaphorePermit, ApiError> {
    tokio::time::timeout(SNAPSHOT_WAIT, state.snapshot_slots.clone().acquire_owned())
        .await
        .map_err(|_| ApiError::resource_limit("snapshot concurrency limit exceeded"))?
        .map_err(|_| ApiError::resource_limit("snapshot service is unavailable"))
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientQuery {
    page: Option<usize>,
    limit: Option<usize>,
    clientid: Option<String>,
    username: Option<String>,
    like_clientid: Option<String>,
    like_username: Option<String>,
    conn_state: Option<String>,
    node: Option<String>,
}

async fn list_clients(
    State(state): State<ApiState>,
    query: Result<Query<ClientQuery>, QueryRejection>,
) -> Result<Json<Page<ClientSnapshot>>, ApiError> {
    let Query(query) = query_params(query)?;
    if query
        .node
        .as_deref()
        .is_some_and(|node| node != state.node_id.as_ref())
    {
        return Err(ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "NODE_DOWN",
            "Requested node is unavailable",
        ));
    }
    let connection_state = match query.conn_state.as_deref() {
        None => None,
        Some("connected" | "online") => Some(true),
        Some("disconnected" | "offline") => Some(false),
        Some(_) => {
            return Err(ApiError::bad_request(
                "conn_state must be connected, disconnected, online, or offline",
            ))
        }
    };
    let pagination = pagination(query.page, query.limit, state.max_page_limit)?;
    let _permit = snapshot_permit(&state).await?;
    let clients = state
        .broker
        .clients_snapshot_bounded(
            &state.node_id,
            state.max_page_limit,
            |clientid, username, online| {
                query
                    .clientid
                    .as_ref()
                    .is_none_or(|value| clientid == value)
                    && query
                        .username
                        .as_ref()
                        .is_none_or(|value| username.is_some_and(|username| username == value))
                    && query
                        .like_clientid
                        .as_ref()
                        .is_none_or(|value| clientid.contains(value))
                    && query.like_username.as_ref().is_none_or(|value| {
                        username.is_some_and(|username| username.contains(value))
                    })
                    && connection_state.is_none_or(|expected| online == expected)
            },
        )
        .map_err(|_| {
            ApiError::resource_limit("client snapshot exceeds management max_page_limit")
        })?;
    Ok(Json(paginate(clients, pagination)))
}

async fn get_client(
    State(state): State<ApiState>,
    Path(clientid): Path<String>,
) -> Result<Json<ClientSnapshot>, ApiError> {
    state
        .broker
        .get_client(&clientid, &state.node_id)
        .map(Json)
        .ok_or_else(|| ApiError::not_found("CLIENTID_NOT_FOUND", "Client ID not found"))
}

async fn delete_client(
    State(state): State<ApiState>,
    Path(clientid): Path<String>,
) -> Result<StatusCode, ApiError> {
    match state.broker.kick_or_delete_client(&clientid).await {
        Ok(true) => Ok(StatusCode::NO_CONTENT),
        Ok(false) => Err(ApiError::not_found(
            "CLIENTID_NOT_FOUND",
            "Client ID not found",
        )),
        Err(error) => Err(ApiError::unknown_error(error.to_string())),
    }
}

async fn bulk_kickout(
    State(state): State<ApiState>,
    body: Result<Json<Vec<String>>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let Json(clientids) = json_body(body)?;
    if clientids.is_empty() {
        return Err(ApiError::bad_request("client ID array must not be empty"));
    }
    for clientid in clientids {
        state
            .broker
            .kick_or_delete_client(&clientid)
            .await
            .map_err(|error| ApiError::unknown_error(error.to_string()))?;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn client_subscriptions(
    State(state): State<ApiState>,
    Path(clientid): Path<String>,
) -> Result<Json<Vec<SubscriptionSnapshot>>, ApiError> {
    state
        .broker
        .client_subscriptions(&clientid)
        .map(Json)
        .ok_or_else(|| ApiError::not_found("CLIENTID_NOT_FOUND", "Client ID not found"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubscribeRequest {
    topic: String,
    #[serde(default)]
    qos: u8,
    #[serde(default)]
    nl: bool,
    #[serde(default)]
    rap: bool,
    #[serde(default)]
    rh: u8,
}

async fn client_subscribe(
    State(state): State<ApiState>,
    Path(clientid): Path<String>,
    body: Result<Json<SubscribeRequest>, JsonRejection>,
) -> Result<Json<SubscriptionSnapshot>, ApiError> {
    let Json(request) = json_body(body)?;
    parse_filter(&request.topic).map_err(|error| ApiError::bad_request(error.to_string()))?;
    state
        .broker
        .admin_subscribe(
            &clientid,
            &request.topic,
            SubscriptionOptions {
                qos: request.qos,
                no_local: request.nl,
                retain_as_published: request.rap,
                retain_handling: request.rh,
                subscription_identifier: None,
            },
        )
        .map(Json)
        .map_err(|error| {
            if error.to_string().contains("unknown online session") {
                ApiError::not_found("CLIENTID_NOT_FOUND", "Client ID not found")
            } else {
                ApiError::bad_request(error.to_string())
            }
        })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UnsubscribeRequest {
    topic: String,
}

async fn client_unsubscribe(
    State(state): State<ApiState>,
    Path(clientid): Path<String>,
    body: Result<Json<UnsubscribeRequest>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let Json(request) = json_body(body)?;
    match state.broker.admin_unsubscribe(&clientid, &request.topic) {
        Ok(true) => Ok(StatusCode::NO_CONTENT),
        Ok(false) => Err(ApiError::not_found(
            "NOT_FOUND",
            "Subscription doesn't exist",
        )),
        Err(error) if error.to_string().contains("unknown session") => Err(ApiError::not_found(
            "CLIENTID_NOT_FOUND",
            "Client ID not found",
        )),
        Err(error) => Err(ApiError::bad_request(error.to_string())),
    }
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubscriptionQuery {
    page: Option<usize>,
    limit: Option<usize>,
    node: Option<String>,
    clientid: Option<String>,
    qos: Option<u8>,
    topic: Option<String>,
    match_topic: Option<String>,
    share_group: Option<String>,
    durable: Option<bool>,
}

async fn list_subscriptions(
    State(state): State<ApiState>,
    query: Result<Query<SubscriptionQuery>, QueryRejection>,
) -> Result<Json<Page<SubscriptionSnapshot>>, ApiError> {
    let Query(query) = query_params(query)?;
    if query.qos.is_some_and(|qos| qos > 2) {
        return Err(ApiError::bad_request("qos must be 0, 1, or 2"));
    }
    if query
        .node
        .as_deref()
        .is_some_and(|node| node != state.node_id.as_ref())
    {
        return Err(ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "NODE_DOWN",
            "Requested node is unavailable",
        ));
    }
    if let Some(topic) = query.match_topic.as_deref() {
        validate_topic_name(topic).map_err(|error| ApiError::bad_request(error.to_string()))?;
    }
    let pagination = pagination(query.page, query.limit, state.max_page_limit)?;
    let _permit = snapshot_permit(&state).await?;
    let subscriptions = state
        .broker
        .subscriptions_snapshot_bounded(
            state.max_page_limit,
            |clientid, subscription_topic, options, durable, _target| {
                let parsed = parse_filter(subscription_topic).ok();
                query
                    .clientid
                    .as_ref()
                    .is_none_or(|expected| clientid == expected)
                    && query.qos.is_none_or(|qos| options.qos == qos)
                    && query
                        .topic
                        .as_ref()
                        .is_none_or(|expected| subscription_topic == expected)
                    && query.durable.is_none_or(|expected| durable == expected)
                    && query.share_group.as_ref().is_none_or(|group| {
                        parsed
                            .as_ref()
                            .and_then(|filter| filter.shared_group.as_ref())
                            == Some(group)
                    })
                    && query.match_topic.as_ref().is_none_or(|topic| {
                        parsed
                            .as_ref()
                            .is_some_and(|filter| topic_matches(&filter.filter, topic))
                    })
            },
        )
        .map_err(|_| {
            ApiError::resource_limit("subscription snapshot exceeds management max_page_limit")
        })?;
    Ok(Json(paginate(subscriptions, pagination)))
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishRequest {
    topic: String,
    payload: String,
    #[serde(default)]
    qos: u8,
    #[serde(default)]
    retain: bool,
    #[serde(default = "plain_encoding")]
    payload_encoding: String,
    properties: Option<PublishProperties>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishProperties {
    message_expiry_interval: Option<u32>,
}

fn plain_encoding() -> String {
    "plain".to_owned()
}

struct PreparedPublish {
    publish: Publish,
}

fn prepare_publish(
    request: PublishRequest,
    max_payload_bytes: usize,
) -> Result<PreparedPublish, ApiError> {
    validate_topic_name(&request.topic)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    if request.qos > 2 {
        return Err(ApiError::bad_request("qos must be 0, 1, or 2"));
    }
    let payload = match request.payload_encoding.as_str() {
        "plain" => request.payload.into_bytes(),
        "base64" => STANDARD
            .decode(request.payload)
            .map_err(|_| ApiError::bad_request("payload is not valid base64"))?,
        _ => {
            return Err(ApiError::bad_request(
                "payload_encoding must be plain or base64",
            ))
        }
    };
    if payload.len() > max_payload_bytes {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "PAYLOAD_TOO_LARGE",
            "decoded payload exceeds management max_body_bytes",
        ));
    }
    let expires_at = request
        .properties
        .and_then(|properties| properties.message_expiry_interval)
        .and_then(|seconds| Instant::now().checked_add(Duration::from_secs(u64::from(seconds))));
    Ok(PreparedPublish {
        publish: Publish {
            dup: false,
            qos: request.qos,
            retain: request.retain,
            topic: request.topic,
            packet_id: None,
            payload: Bytes::from(payload),
            expires_at,
            subscription_identifiers: Vec::new(),
            topic_alias: None,
        },
    })
}

fn publish_result(state: &ApiState, outcome: PublishOutcome) -> (StatusCode, Value) {
    if outcome.matched == 0 {
        (
            StatusCode::ACCEPTED,
            json!({"reason_code": 16, "message": "no_matching_subscribers"}),
        )
    } else if outcome.accepted == 0 {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"reason_code": 131, "message": "failed_to_dispatch"}),
        )
    } else {
        (StatusCode::OK, json!({"id": state.next_id()}))
    }
}

async fn publish(
    State(state): State<ApiState>,
    body: Result<Json<PublishRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let Json(request) = json_body(body)?;
    let prepared = prepare_publish(request, state.max_body_bytes)?;
    let (status, response) = publish_result(&state, state.broker.publish(prepared.publish));
    Ok((status, Json(response)))
}

async fn publish_bulk(
    State(state): State<ApiState>,
    body: Result<Json<Vec<PublishRequest>>, JsonRejection>,
) -> Result<(StatusCode, Json<Vec<Value>>), ApiError> {
    let Json(requests) = json_body(body)?;
    if requests.is_empty() {
        return Err(ApiError::bad_request("publish array must not be empty"));
    }
    let prepared: Vec<_> = requests
        .into_iter()
        .map(|request| prepare_publish(request, state.max_body_bytes))
        .collect::<Result<_, _>>()?;
    let mut overall = StatusCode::OK;
    let results = prepared
        .into_iter()
        .map(|prepared| {
            let (status, response) = publish_result(&state, state.broker.publish(prepared.publish));
            if status == StatusCode::SERVICE_UNAVAILABLE {
                overall = StatusCode::SERVICE_UNAVAILABLE;
            } else if status == StatusCode::ACCEPTED && overall == StatusCode::OK {
                overall = StatusCode::ACCEPTED;
            }
            response
        })
        .collect();
    Ok((overall, Json(results)))
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedQuery {
    page: Option<usize>,
    limit: Option<usize>,
    topic: Option<String>,
}

async fn list_retained(
    State(state): State<ApiState>,
    query: Result<Query<RetainedQuery>, QueryRejection>,
) -> Result<Json<Page<RetainedSnapshot>>, ApiError> {
    let Query(query) = query_params(query)?;
    if let Some(filter) = query.topic.as_deref() {
        parse_filter(filter).map_err(|error| ApiError::bad_request(error.to_string()))?;
    }
    let pagination = pagination(query.page, query.limit, state.max_page_limit)?;
    let _permit = snapshot_permit(&state).await?;
    let retained = state
        .broker
        .retained_snapshot_bounded(state.max_page_limit, |topic| {
            query
                .topic
                .as_ref()
                .is_none_or(|filter| topic_matches(filter, topic))
        })
        .map_err(|_| {
            ApiError::resource_limit("retained snapshot exceeds management max_page_limit")
        })?;
    Ok(Json(paginate(retained, pagination)))
}

#[derive(Serialize)]
struct RetainedDetail {
    #[serde(flatten)]
    summary: RetainedSnapshot,
    payload_encoding: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<String>,
}

async fn get_retained(
    State(state): State<ApiState>,
    Path(topic): Path<String>,
) -> Result<Json<RetainedDetail>, ApiError> {
    let detail = state
        .broker
        .get_retained(&topic)
        .ok_or_else(|| ApiError::not_found("NOT_FOUND", "Viewed message doesn't exist"))?;
    let payload = (detail.payload.len() <= MAX_RETAINED_DETAIL_BYTES)
        .then(|| STANDARD.encode(detail.payload));
    Ok(Json(RetainedDetail {
        summary: detail.summary,
        payload_encoding: "base64",
        payload,
    }))
}

async fn delete_retained(
    State(state): State<ApiState>,
    Path(topic): Path<String>,
) -> Result<StatusCode, ApiError> {
    if state.broker.delete_retained(&topic) {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found(
            "NOT_FOUND",
            "Viewed message doesn't exist",
        ))
    }
}

async fn clear_retained(State(state): State<ApiState>) -> StatusCode {
    state.broker.clear_retained();
    StatusCode::NO_CONTENT
}

#[derive(Serialize)]
struct NodeInfo {
    node: String,
    node_status: &'static str,
    uptime: u64,
    started_at_epoch_ms: u64,
}

fn node_info(state: &ApiState) -> NodeInfo {
    NodeInfo {
        node: state.node_id.to_string(),
        node_status: "running",
        uptime: state.started.elapsed().as_secs(),
        started_at_epoch_ms: state.started_epoch_ms,
    }
}

async fn nodes(State(state): State<ApiState>) -> Json<Vec<NodeInfo>> {
    Json(vec![node_info(&state)])
}

async fn node(
    State(state): State<ApiState>,
    Path(node): Path<String>,
) -> Result<Json<Value>, ApiError> {
    ensure_node(&state, &node)?;
    Ok(Json(json!(node_info(&state))))
}

#[derive(Serialize)]
struct NodeStats<'a> {
    node: &'a str,
    #[serde(flatten)]
    stats: StatsSnapshot,
}

#[derive(Serialize)]
struct NodeMetrics<'a> {
    node: &'a str,
    #[serde(flatten)]
    metrics: MetricsSnapshot,
}

async fn node_stats(
    State(state): State<ApiState>,
    Path(node): Path<String>,
) -> Result<Json<Value>, ApiError> {
    ensure_node(&state, &node)?;
    Ok(Json(json!(NodeStats {
        node: &state.node_id,
        stats: state.broker.stats(),
    })))
}

async fn node_metrics(
    State(state): State<ApiState>,
    Path(node): Path<String>,
) -> Result<Json<Value>, ApiError> {
    ensure_node(&state, &node)?;
    Ok(Json(json!(NodeMetrics {
        node: &state.node_id,
        metrics: state.broker.metrics_snapshot(),
    })))
}

fn ensure_node(state: &ApiState, node: &str) -> Result<(), ApiError> {
    if node == state.node_id.as_ref() {
        Ok(())
    } else {
        Err(ApiError::not_found("NOT_FOUND", "Node not found"))
    }
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AggregateQuery {
    #[serde(default)]
    aggregate: bool,
}

async fn stats(
    State(state): State<ApiState>,
    query: Result<Query<AggregateQuery>, QueryRejection>,
) -> Result<Json<Value>, ApiError> {
    let Query(query) = query_params(query)?;
    let snapshot = NodeStats {
        node: &state.node_id,
        stats: state.broker.stats(),
    };
    if query.aggregate {
        Ok(Json(json!(snapshot.stats)))
    } else {
        Ok(Json(json!([snapshot])))
    }
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct MetricsQuery {
    #[serde(default)]
    aggregate: bool,
    node: Option<String>,
}

async fn metrics(
    State(state): State<ApiState>,
    query: Result<Query<MetricsQuery>, QueryRejection>,
) -> Result<Json<Value>, ApiError> {
    let Query(query) = query_params(query)?;
    if query
        .node
        .as_deref()
        .is_some_and(|node| node != state.node_id.as_ref())
    {
        return Ok(Json(json!([])));
    }
    let snapshot = NodeMetrics {
        node: &state.node_id,
        metrics: state.broker.metrics_snapshot(),
    };
    if query.aggregate {
        Ok(Json(json!(snapshot.metrics)))
    } else {
        Ok(Json(json!([snapshot])))
    }
}

async fn api_not_found() -> ApiError {
    ApiError::not_found("NOT_FOUND", "API endpoint not found")
}

fn query_params<T>(query: Result<Query<T>, QueryRejection>) -> Result<Query<T>, ApiError> {
    query.map_err(|rejection| ApiError::bad_request(rejection.body_text()))
}

fn json_body<T>(body: Result<Json<T>, JsonRejection>) -> Result<Json<T>, ApiError> {
    body.map_err(|rejection| {
        let status = rejection.status();
        let status = if status == StatusCode::UNSUPPORTED_MEDIA_TYPE {
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        } else if status == StatusCode::PAYLOAD_TOO_LARGE {
            StatusCode::PAYLOAD_TOO_LARGE
        } else {
            StatusCode::BAD_REQUEST
        };
        ApiError::new(status, "BAD_REQUEST", rejection.body_text())
    })
}
