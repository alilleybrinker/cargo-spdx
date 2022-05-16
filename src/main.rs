//! Generate an SPDX SBOM for a Rust crate.

#![deny(missing_debug_implementations)]
#![deny(missing_copy_implementations)]
#![deny(missing_docs)]

use crate::document::{Creator, DocumentBuilder};
use anyhow::{anyhow, Result};
use cargo_metadata::{Metadata, MetadataCommand, Package};

mod document;
mod git;
mod key_value;

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

    // Print the name of the root package.
    println!("root: {}", root.name);

    // Construct an example document.
    let test_doc = DocumentBuilder::default()
        .document_name(get_filename(root).as_ref())
        .try_document_namespace("https://google.com")?
        .creator(get_creator())
        .build()?;

    // Write that document to disk.
    key_value::write_to_disk(&test_doc)?;

    Ok(())
}

/// Extract the root package info from the crate metadata.
fn get_root(metadata: &Metadata) -> Result<&Package> {
    metadata
        .resolve
        .as_ref()
        .and_then(|r| r.root.as_ref().map(|r| &metadata[r]))
        .ok_or_else(|| anyhow!("no root found"))
}

/// Get the name of the SPDX file being generated.
fn get_filename(pkg: &Package) -> String {
    format!("{}.spdx", pkg.name)
}

/// Identify the creator(s) of the SBOM.
fn get_creator() -> Vec<Creator> {
    let mut creator = vec![];

    if let Ok(user) = git::get_current_user() {
        creator.push(Creator::person(user.name, user.email));
    }

    creator.push(Creator::tool("cargo-spdx 0.1.0"));
    creator
}
