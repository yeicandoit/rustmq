use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::{
        rejection::{JsonRejection, QueryRejection},
        DefaultBodyLimit, Path, Query, Request, State,
    },
    http::{header, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use subtle::ConstantTimeEq;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::{
    broker::{
        Broker, ClientSnapshot, MetricsSnapshot, PublishOutcome, RetainedSnapshot, StatsSnapshot,
        SubscriptionOptions, SubscriptionSnapshot,
    },
    config::ManagementConfig,
    protocol::Publish,
    topic::{parse_filter, topic_matches, validate_topic_name},
};

const AUTH_REALM: &str = "Basic Realm=\"emqx-dashboard\"";
const MAX_CREDENTIAL_BYTES: usize = 2049;
const MAX_RETAINED_DETAIL_BYTES: usize = 1024 * 1024;
const SNAPSHOT_CONCURRENCY: usize = 4;
const SNAPSHOT_WAIT: Duration = Duration::from_secs(1);

#[derive(Clone)]
pub struct ApiState {
    broker: Broker,
    node_id: Arc<str>,
    started: Instant,
    started_epoch_ms: u64,
    auth: AuthVerifier,
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
        Self {
            broker,
            node_id: Arc::from(node_id),
            started: Instant::now(),
            started_epoch_ms,
            auth: AuthVerifier::new(
                config.api_key.as_deref().unwrap_or_default(),
                config.api_secret.as_deref().unwrap_or_default(),
            ),
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
        let mut supplied = [0_u8; MAX_CREDENTIAL_BYTES];
        let length = value.len().min(MAX_CREDENTIAL_BYTES);
        supplied[..length].copy_from_slice(&value[..length]);
        let bytes_equal = self.expected.as_ref().ct_eq(&supplied).unwrap_u8();
        let lengths_equal = self.expected_len.ct_eq(&value.len()).unwrap_u8();
        (bytes_equal & lengths_equal) == 1
    }
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
        .route("/api/v5/status", get(status))
        .with_state(state.clone());
    if !enabled {
        return public;
    }

    let protected = Router::new()
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
        .route("/api/v5/api_key", any(not_implemented))
        .route("/api/v5/api_key/{name}", any(not_implemented))
        .route("/api/v5/banned", any(not_implemented))
        .fallback(api_not_found)
        .layer(DefaultBodyLimit::max(state.max_body_bytes))
        .layer(middleware::from_fn_with_state(
            state.auth.clone(),
            require_auth,
        ))
        .with_state(state);
    public.merge(protected)
}

async fn require_auth(
    State(auth): State<AuthVerifier>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let Some(value) = request.headers().get(header::AUTHORIZATION) else {
        return Err(ApiError::unauthorized(
            "AUTHORIZATION_HEADER_ERROR",
            "Authorization header is required; only Basic authentication is supported",
        ));
    };
    let value = value.to_str().map_err(|_| {
        ApiError::unauthorized(
            "AUTHORIZATION_HEADER_ERROR",
            "Malformed Authorization header; only Basic authentication is supported",
        )
    })?;
    let Some((scheme, encoded)) = value.split_once(' ') else {
        return Err(ApiError::unauthorized(
            "AUTHORIZATION_HEADER_ERROR",
            "Malformed Authorization header; only Basic authentication is supported",
        ));
    };
    if !scheme.eq_ignore_ascii_case("basic") || encoded.is_empty() {
        return Err(ApiError::unauthorized(
            "AUTHORIZATION_HEADER_ERROR",
            "Unsupported Authorization scheme; only Basic authentication is supported",
        ));
    }
    let decoded = STANDARD.decode(encoded).map_err(|_| {
        ApiError::unauthorized(
            "AUTHORIZATION_HEADER_ERROR",
            "Malformed Basic credentials; only Basic authentication is supported",
        )
    })?;
    if !decoded.contains(&b':') {
        return Err(ApiError::unauthorized(
            "AUTHORIZATION_HEADER_ERROR",
            "Malformed Basic credentials; expected api_key:api_secret",
        ));
    }
    if !auth.verify(&decoded) {
        return Err(ApiError::unauthorized(
            "BAD_API_KEY_OR_SECRET",
            "Bad API key or secret",
        ));
    }
    Ok(next.run(request).await)
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

async fn not_implemented() -> ApiError {
    ApiError::new(
        StatusCode::NOT_IMPLEMENTED,
        "NOT_IMPLEMENTED",
        "This EMQX management API is not implemented by RustMQ",
    )
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
