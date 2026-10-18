use std::{
    collections::VecDeque,
    fmt,
    str::FromStr,
    sync::{Arc, Mutex},
};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::topic::{parse_filter, topic_matches};

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NoMatch {
    #[default]
    Allow,
    Deny,
}

impl FromStr for NoMatch {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            _ => bail!("authorization no_match must be allow or deny"),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DenyAction {
    #[default]
    Ignore,
    Disconnect,
}

impl FromStr for DenyAction {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "ignore" => Ok(Self::Ignore),
            "disconnect" => Ok(Self::Disconnect),
            _ => bail!("authorization deny_action must be ignore or disconnect"),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    Allow,
    Deny,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    All,
    Publish,
    Subscribe,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthorizationRuleConfig {
    pub permission: Permission,
    pub action: RuleAction,
    #[serde(default)]
    pub principal: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub topics: Option<Vec<String>>,
    #[serde(default)]
    pub exact_topics: Option<Vec<String>>,
    #[serde(default = "default_qos")]
    pub qos: Vec<u8>,
    #[serde(default)]
    pub retain: Option<bool>,
}

fn default_qos() -> Vec<u8> {
    vec![0, 1, 2]
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct AuthorizationConfig {
    pub no_match: NoMatch,
    pub deny_action: DenyAction,
    pub cache_capacity: usize,
    pub rules: Vec<AuthorizationRuleConfig>,
}

impl Default for AuthorizationConfig {
    fn default() -> Self {
        Self {
            no_match: NoMatch::Allow,
            deny_action: DenyAction::Ignore,
            cache_capacity: 32,
            rules: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AuthorizationAction {
    Publish,
    Subscribe,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationDecision {
    Allow,
    Deny,
}

impl AuthorizationDecision {
    #[must_use]
    pub fn is_allowed(self) -> bool {
        self == Self::Allow
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscriptionAuthorization {
    Allow,
    Deny,
    InvalidFilter,
}

impl From<AuthorizationDecision> for SubscriptionAuthorization {
    fn from(decision: AuthorizationDecision) -> Self {
        match decision {
            AuthorizationDecision::Allow => Self::Allow,
            AuthorizationDecision::Deny => Self::Deny,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationContext {
    pub principal: Option<String>,
    pub client_id: String,
}

#[derive(Clone, Debug)]
enum TemplatePart {
    Literal(String),
    Principal,
    ClientId,
}

#[derive(Clone, Debug)]
struct TopicTemplate {
    parts: Vec<TemplatePart>,
    rendered_capacity: usize,
    needs_principal: bool,
}

impl TopicTemplate {
    fn compile(value: &str) -> Result<Self> {
        if value.is_empty() {
            bail!("authorization topic must not be empty");
        }
        let mut parts = Vec::new();
        let mut rest = value;
        let mut rendered_capacity = value.len();
        let mut needs_principal = false;
        while let Some(start) = rest.find("${") {
            if start > 0 {
                parts.push(TemplatePart::Literal(rest[..start].to_owned()));
            }
            let variable = &rest[start + 2..];
            let Some(end) = variable.find('}') else {
                bail!("unterminated authorization topic template in {value:?}");
            };
            match &variable[..end] {
                "principal" => {
                    parts.push(TemplatePart::Principal);
                    needs_principal = true;
                }
                "clientid" => parts.push(TemplatePart::ClientId),
                name => bail!("unknown authorization topic template variable {name:?}"),
            }
            rendered_capacity = rendered_capacity.saturating_add(32);
            rest = &variable[end + 1..];
        }
        if rest.contains('}') {
            bail!("unmatched }} in authorization topic template {value:?}");
        }
        if !rest.is_empty() {
            parts.push(TemplatePart::Literal(rest.to_owned()));
        }
        let template = Self {
            parts,
            rendered_capacity,
            needs_principal,
        };
        let validation_context = AuthorizationContext {
            principal: Some("principal".to_owned()),
            client_id: "clientid".to_owned(),
        };
        let rendered = template
            .render(&validation_context)
            .expect("validation principal is present");
        parse_filter(&rendered)
            .with_context(|| format!("invalid authorization topic filter {value:?}"))?;
        Ok(template)
    }

    /// Renders template variables only as literal topic-level content. Unsafe values make
    /// the rule not match rather than contributing MQTT filter syntax.
    fn render(&self, context: &AuthorizationContext) -> Option<String> {
        if self.needs_principal && context.principal.is_none() {
            return None;
        }
        let mut output = String::with_capacity(self.rendered_capacity);
        for part in &self.parts {
            match part {
                TemplatePart::Literal(value) => output.push_str(value),
                TemplatePart::Principal => {
                    let value = context.principal.as_deref()?;
                    if !is_safe_template_level(value) {
                        return None;
                    }
                    output.push_str(value);
                }
                TemplatePart::ClientId => {
                    if !is_safe_template_level(&context.client_id) {
                        return None;
                    }
                    output.push_str(&context.client_id);
                }
            }
        }
        Some(output)
    }
}

fn is_safe_template_level(value: &str) -> bool {
    !value.contains(['/', '+', '#', '\0'])
}

#[derive(Clone, Debug)]
struct CompiledExactTopic {
    publish: String,
    subscribe: String,
}

#[derive(Clone, Debug)]
struct CompiledRule {
    permission: Permission,
    action: RuleAction,
    principal: Option<String>,
    client_id: Option<String>,
    topics: Vec<TopicTemplate>,
    exact_topics: Vec<CompiledExactTopic>,
    qos: [bool; 3],
    retain: Option<bool>,
}

impl CompiledRule {
    fn compile(index: usize, config: &AuthorizationRuleConfig) -> Result<Self> {
        if config.qos.is_empty() {
            bail!("authorization rule {index} qos must not be empty");
        }
        let mut qos = [false; 3];
        for value in &config.qos {
            let slot = qos
                .get_mut(usize::from(*value))
                .with_context(|| format!("authorization rule {index} has invalid QoS {value}"))?;
            *slot = true;
        }
        if matches!(config.action, RuleAction::Subscribe) && config.retain.is_some() {
            bail!("authorization rule {index} retain is only valid for publish or all actions");
        }
        let topics = match &config.topics {
            Some(values) if values.is_empty() => {
                bail!("authorization rule {index} topics must not be empty")
            }
            Some(values) => values
                .iter()
                .map(|value| TopicTemplate::compile(value))
                .collect::<Result<Vec<_>>>()
                .with_context(|| format!("compile authorization rule {index}"))?,
            None => Vec::new(),
        };
        let exact_topics = match &config.exact_topics {
            Some(values) if values.is_empty() => {
                bail!("authorization rule {index} exact_topics must not be empty")
            }
            Some(values) => values
                .iter()
                .map(|value| compile_exact_topic(index, config.action, value))
                .collect::<Result<Vec<_>>>()?,
            None => Vec::new(),
        };
        if topics.is_empty() && exact_topics.is_empty() {
            bail!("authorization rule {index} requires topics or exact_topics");
        }
        Ok(Self {
            permission: config.permission,
            action: config.action,
            principal: config.principal.clone(),
            client_id: config.client_id.clone(),
            topics,
            exact_topics,
            qos,
            retain: config.retain,
        })
    }

    fn matches_common(
        &self,
        context: &AuthorizationContext,
        action: AuthorizationAction,
        qos: u8,
        retain: bool,
    ) -> bool {
        if !matches!(
            (self.action, action),
            (RuleAction::All, _)
                | (RuleAction::Publish, AuthorizationAction::Publish)
                | (RuleAction::Subscribe, AuthorizationAction::Subscribe)
        ) || !self.qos.get(usize::from(qos)).copied().unwrap_or(false)
            || self
                .principal
                .as_ref()
                .is_some_and(|principal| context.principal.as_ref() != Some(principal))
            || self
                .client_id
                .as_ref()
                .is_some_and(|client_id| client_id != &context.client_id)
        {
            return false;
        }
        action != AuthorizationAction::Publish || self.retain.is_none_or(|value| value == retain)
    }

    fn matches_publish(&self, context: &AuthorizationContext, topic: &str) -> bool {
        self.exact_topics.iter().any(|item| item.publish == topic)
            || self.topics.iter().any(|template| {
                template
                    .render(context)
                    .is_some_and(|filter| topic_matches(&filter, topic))
            })
    }

    fn matches_subscribe(&self, context: &AuthorizationContext, requested: &str) -> bool {
        self.exact_topics
            .iter()
            .any(|item| item.subscribe == requested)
            || self.topics.iter().any(|template| {
                template.render(context).is_some_and(|allowed| {
                    parse_filter(&allowed)
                        .is_ok_and(|parsed| filter_contains_filter(&parsed.filter, requested))
                })
            })
    }
}

fn compile_exact_topic(
    index: usize,
    action: RuleAction,
    value: &str,
) -> Result<CompiledExactTopic> {
    if value.is_empty() || value.as_bytes().contains(&0) {
        bail!("authorization rule {index} has an empty or NUL exact topic");
    }
    let subscribe = parse_filter(value)
        .with_context(|| format!("authorization rule {index} has invalid exact topic/filter"))?
        .filter;
    if matches!(action, RuleAction::Publish)
        && (value.contains(['+', '#']) || value.starts_with("$share/"))
    {
        bail!("authorization rule {index} publish exact topic must be a topic name");
    }
    Ok(CompiledExactTopic {
        publish: value.to_owned(),
        subscribe,
    })
}

#[derive(Debug)]
pub struct AuthorizationEngine {
    rules: Vec<CompiledRule>,
    no_match: AuthorizationDecision,
    deny_action: DenyAction,
    cache_capacity: usize,
}

impl AuthorizationEngine {
    pub fn compile(config: &AuthorizationConfig) -> Result<Arc<Self>> {
        if config.cache_capacity == 0 {
            bail!("authorization cache_capacity must be greater than zero");
        }
        let rules = config
            .rules
            .iter()
            .enumerate()
            .map(|(index, rule)| CompiledRule::compile(index, rule))
            .collect::<Result<Vec<_>>>()?;
        Ok(Arc::new(Self {
            rules,
            no_match: match config.no_match {
                NoMatch::Allow => AuthorizationDecision::Allow,
                NoMatch::Deny => AuthorizationDecision::Deny,
            },
            deny_action: config.deny_action,
            cache_capacity: config.cache_capacity,
        }))
    }

    #[must_use]
    pub fn session(
        self: &Arc<Self>,
        principal: Option<String>,
        client_id: String,
    ) -> Arc<AuthorizationSession> {
        Arc::new(AuthorizationSession {
            engine: Arc::clone(self),
            context: AuthorizationContext {
                principal,
                client_id,
            },
            cache: Mutex::new(VecDeque::with_capacity(self.cache_capacity)),
        })
    }

    #[must_use]
    pub fn deny_action(&self) -> DenyAction {
        self.deny_action
    }

    fn authorize(
        &self,
        context: &AuthorizationContext,
        action: AuthorizationAction,
        qos: u8,
        retain: bool,
        normalized: &str,
    ) -> AuthorizationDecision {
        for rule in &self.rules {
            if !rule.matches_common(context, action, qos, retain) {
                continue;
            }
            let topic_matches = match action {
                AuthorizationAction::Publish => rule.matches_publish(context, normalized),
                AuthorizationAction::Subscribe => rule.matches_subscribe(context, normalized),
            };
            if topic_matches {
                return match rule.permission {
                    Permission::Allow => AuthorizationDecision::Allow,
                    Permission::Deny => AuthorizationDecision::Deny,
                };
            }
        }
        self.no_match
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CacheKey {
    action: AuthorizationAction,
    qos: u8,
    retain: bool,
    topic: String,
}

#[derive(Debug)]
pub struct AuthorizationSession {
    engine: Arc<AuthorizationEngine>,
    context: AuthorizationContext,
    cache: Mutex<VecDeque<(CacheKey, AuthorizationDecision)>>,
}

impl AuthorizationSession {
    #[must_use]
    pub fn context(&self) -> &AuthorizationContext {
        &self.context
    }

    #[must_use]
    pub fn deny_action(&self) -> DenyAction {
        self.engine.deny_action()
    }

    #[must_use]
    pub fn authorize_publish(&self, topic: &str, qos: u8, retain: bool) -> AuthorizationDecision {
        self.authorize(AuthorizationAction::Publish, topic, qos, retain)
    }

    #[must_use]
    pub fn authorize_subscribe(&self, filter: &str, qos: u8) -> SubscriptionAuthorization {
        let Ok(normalized) = parse_filter(filter).map(|parsed| parsed.filter) else {
            return SubscriptionAuthorization::InvalidFilter;
        };
        self.authorize(AuthorizationAction::Subscribe, &normalized, qos, false)
            .into()
    }

    fn authorize(
        &self,
        action: AuthorizationAction,
        normalized: &str,
        qos: u8,
        retain: bool,
    ) -> AuthorizationDecision {
        let key = CacheKey {
            action,
            qos,
            retain,
            topic: normalized.to_owned(),
        };
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(index) = cache.iter().position(|(cached, _)| cached == &key) {
            let entry = cache.remove(index).expect("cached index exists");
            let decision = entry.1;
            cache.push_front(entry);
            return decision;
        }
        let decision = self
            .engine
            .authorize(&self.context, action, qos, retain, normalized);
        if cache.len() == self.engine.cache_capacity {
            cache.pop_back();
        }
        cache.push_front((key, decision));
        decision
    }
}

/// Returns true only when every topic selected by `requested` is also selected by `allowed`.
#[must_use]
pub fn filter_contains_filter(allowed: &str, requested: &str) -> bool {
    let Ok(allowed) = parse_filter(allowed) else {
        return false;
    };
    let Ok(requested) = parse_filter(requested) else {
        return false;
    };
    let allowed_levels: Vec<_> = allowed.filter.split('/').collect();
    let requested_levels: Vec<_> = requested.filter.split('/').collect();

    let requested_can_select_system = requested_levels
        .first()
        .is_some_and(|level| level.starts_with('$'));
    let allowed_can_select_system = allowed_levels
        .first()
        .is_some_and(|level| level.starts_with('$'));
    if requested_can_select_system && !allowed_can_select_system {
        return false;
    }

    levels_contained(&allowed_levels, &requested_levels)
}

fn levels_contained(allowed: &[&str], requested: &[&str]) -> bool {
    match (allowed.first(), requested.first()) {
        (Some(&"#"), _) => true,
        (_, Some(&"#")) => matches!(allowed, ["#"]),
        (None, None) => true,
        (None, Some(_)) | (Some(_), None) => false,
        (Some(allowed_level), Some(requested_level)) => {
            (*allowed_level == "+" || (*requested_level != "+" && allowed_level == requested_level))
                && levels_contained(&allowed[1..], &requested[1..])
        }
    }
}

impl fmt::Display for AuthorizationDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => formatter.write_str("allow"),
            Self::Deny => formatter.write_str("deny"),
        }
    }
}
