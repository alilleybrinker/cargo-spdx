//! Functions for interacting with `cargo-metadata`.

use anyhow::{anyhow, Result};
use cargo_metadata::{Metadata, Package};

/// Extract the root package info from the crate metadata.
pub fn get_root(metadata: &Metadata) -> Result<&Package> {
    metadata
        .resolve
        .as_ref()
        .and_then(|r| r.root.as_ref().map(|r| &metadata[r]))
        .ok_or_else(|| anyhow!("no root found"))
}
