/**
 * Basically, this tool should work as follows:
 *
 * Find the root of the crate.
 * Use cargo metadata to get the dependency graph and crate info.
 * Put that info into SPDX format.
 */
use anyhow::{anyhow, Result};
use cargo_metadata::{Metadata, MetadataCommand, Package};

mod spdx;

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {}", e);
    }
}

fn run() -> Result<()> {
    // Get the metadata for the crate.
    let metadata = MetadataCommand::new().exec()?;

    // Get the root of the dependency tree.
    let root = get_root(&metadata).ok_or_else(|| anyhow!("no root"))?;
    println!("root: {}", root.name);

    Ok(())
}

fn get_root(metadata: &Metadata) -> Option<&Package> {
    metadata
        .resolve
        .as_ref()
        .and_then(|r| r.root.as_ref().map(|r| &metadata[r]))
}
