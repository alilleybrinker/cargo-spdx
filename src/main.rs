//! Generate an SPDX SBOM for a Rust crate.

#![deny(missing_debug_implementations)]
#![deny(missing_copy_implementations)]
#![deny(missing_docs)]

use crate::spdx::{Creator, DocumentBuilder};
use anyhow::{anyhow, Result};
use cargo_metadata::{Metadata, MetadataCommand, Package};
use time::OffsetDateTime;

mod key_value;
mod spdx;

/**
 * Basically, this tool should work as follows:
 *
 * Find the root of the crate.
 * Use cargo metadata to get the dependency graph and crate info.
 * Put that info into SPDX format.
 */

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {}", e);
    }
}

fn run() -> Result<()> {
    // Get the metadata for the crate.
    let metadata = MetadataCommand::new().exec()?;

    // Get the root of the dependency tree.
    let root = get_root(&metadata)?;
    println!("root: {}", root.name);

    let test_doc = DocumentBuilder::default()
        .spdx_version((2, 2))
        .document_name("test.spdx")
        .try_document_namespace("https://google.com")?
        .creator(vec![Creator::tool("cargo-spdx 0.1.0")])
        .created(OffsetDateTime::now_utc())
        .build()?;

    key_value::write_to_disk(&test_doc, "test.spdx")?;

    Ok(())
}

fn get_root(metadata: &Metadata) -> Result<&Package> {
    metadata
        .resolve
        .as_ref()
        .and_then(|r| r.root.as_ref().map(|r| &metadata[r]))
        .ok_or_else(|| anyhow!("no root found"))
}
