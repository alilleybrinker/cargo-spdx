//! Functions for interacting with `cargo-metadata`.

use anyhow::{anyhow, Result};
use cargo_metadata::{Metadata, MetadataCommand, Package};

pub struct CrateMetadata(Metadata);

impl CrateMetadata {
    /// Load crate metadata.
    pub fn load() -> Result<Self> {
        Ok(CrateMetadata(MetadataCommand::new().exec()?))
    }

    /// Extract the root package info from the crate metadata.
    pub fn root(&self) -> Result<&Package> {
        self.0
            .resolve
            .as_ref()
            .and_then(|r| r.root.as_ref().map(|r| &self.0[r]))
            .ok_or_else(|| anyhow!("no root found"))
    }
}