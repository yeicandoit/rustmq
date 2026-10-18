use anyhow::{bail, Result};

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct TopicFilter {
    pub original: String,
    pub filter: String,
    pub shared_group: Option<String>,
}

pub fn validate_topic_name(value: &str) -> Result<()> {
    if value.is_empty() || value.as_bytes().contains(&0) {
        bail!("topic name is empty or contains NUL");
    }
    if value.contains(['+', '#']) {
        bail!("topic name must not contain wildcards");
    }
    if value.len() > usize::from(u16::MAX) {
        bail!("topic name exceeds MQTT UTF-8 length limit");
    }
    Ok(())
}

pub fn parse_filter(value: &str) -> Result<TopicFilter> {
    if value.is_empty() || value.as_bytes().contains(&0) {
        bail!("topic filter is empty or contains NUL");
    }
    let (group, filter) = if let Some(rest) = value.strip_prefix("$share/") {
        let Some((group, filter)) = rest.split_once('/') else {
            bail!("shared subscription must contain group and filter");
        };
        if group.is_empty() || group.contains(['+', '#']) || filter.is_empty() {
            bail!("invalid shared subscription");
        }
        (Some(group.to_owned()), filter)
    } else {
        (None, value)
    };
    let levels: Vec<_> = filter.split('/').collect();
    for (index, level) in levels.iter().enumerate() {
        if level.contains('#') && (*level != "#" || index + 1 != levels.len()) {
            bail!("# must occupy the final level");
        }
        if level.contains('+') && *level != "+" {
            bail!("+ must occupy an entire level");
        }
    }
    Ok(TopicFilter {
        original: value.to_owned(),
        filter: filter.to_owned(),
        shared_group: group,
    })
}

#[must_use]
pub fn topic_matches(filter: &str, topic: &str) -> bool {
    let Ok(parsed) = parse_filter(filter) else {
        return false;
    };
    if topic.starts_with('$')
        && !parsed.filter.starts_with('$')
        && matches!(parsed.filter.split('/').next(), Some("#" | "+"))
    {
        return false;
    }
    let mut names = topic.split('/');
    let mut filters = parsed.filter.split('/');
    loop {
        match (filters.next(), names.next()) {
            (Some("#"), _) | (None, None) => return true,
            (Some("+"), Some(_)) => {}
            (Some(filter_level), Some(name_level)) if filter_level == name_level => {}
            _ => return false,
        }
    }
}

#[must_use]
pub fn bucket_for_filter(filter: &str) -> String {
    let parsed = parse_filter(filter).ok();
    let first = parsed
        .as_ref()
        .and_then(|item| item.filter.split('/').next())
        .unwrap_or("#");
    if matches!(first, "+" | "#") {
        "*".to_owned()
    } else {
        first.to_owned()
    }
}

#[must_use]
pub fn bucket_for_topic(topic: &str) -> &str {
    topic.split('/').next().unwrap_or("")
}
