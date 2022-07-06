//! Functions for interacting with `cargo-metadata`.

use anyhow::{anyhow, Result};
use cargo_metadata::{Metadata, Package};

pub trait MetadataExt<'a> {
    fn root(&'a self) -> Result<&'a Package>;
}

impl<'a> MetadataExt<'a> for Metadata {
    /// Extract the root package info from the crate metadata.
    fn root(&'a self) -> Result<&'a Package> {
        self.resolve
            .as_ref()
            .and_then(|r| r.root.as_ref().map(|r| &self[r]))
            .ok_or_else(|| anyhow!("no root found"))
    }
}
