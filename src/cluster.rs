use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

use anyhow::{bail, Result};

pub trait Cluster: Send + Sync {
    fn owner(&self, key: &str) -> Result<String>;
    fn is_local(&self, node: &str) -> bool;
    fn members(&self) -> Vec<String>;
}

pub trait MetadataStore: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    fn put(&self, key: &str, value: &[u8]) -> Result<()>;
}

#[derive(Clone, Debug)]
pub struct SingleNodeCluster {
    node_id: String,
}

impl SingleNodeCluster {
    #[must_use]
    pub fn new(node_id: impl Into<String>) -> Self {
        Self {
            node_id: node_id.into(),
        }
    }
}

impl Cluster for SingleNodeCluster {
    fn owner(&self, _key: &str) -> Result<String> {
        Ok(self.node_id.clone())
    }
    fn is_local(&self, node: &str) -> bool {
        node == self.node_id
    }
    fn members(&self) -> Vec<String> {
        vec![self.node_id.clone()]
    }
}

pub fn owner_for_key(key: &str, nodes: &[String]) -> Result<String> {
    if nodes.is_empty() {
        bail!("cluster has no nodes");
    }
    let mut best: Option<(u64, &String)> = None;
    for node in nodes {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        node.hash(&mut hasher);
        let score = hasher.finish();
        if best.is_none_or(|(current, _)| score > current) {
            best = Some((score, node));
        }
    }
    best.map(|(_, node)| node.clone())
        .ok_or_else(|| anyhow::anyhow!("cluster has no nodes"))
}
