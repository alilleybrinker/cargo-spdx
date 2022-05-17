//! Generate an SPDX SBOM for a Rust crate.

#![deny(missing_debug_implementations)]
#![deny(missing_copy_implementations)]
#![deny(missing_docs)]

use crate::cli::Format;
use crate::document::{Creator, DocumentBuilder};
use anyhow::{anyhow, Result};
use cargo_metadata::{Metadata, MetadataCommand, Package};
use clap::Parser as _;

mod cli;
mod document;
mod git;
mod key_value;

/// Program entrypoint, only calls `run` and reports errors.
fn main() {
    if let Err(e) = run() {
        eprintln!("error: {}", e);
    }
}

/// Gathers CLI args, constructs an SPDX `Document`, and outputs that document.
fn run() -> Result<()> {
    // Parse the command line args.
    let args = cli::Cli::parse();

    // Get the metadata for the crate.
    let metadata = MetadataCommand::new().exec()?;

    // Get the root of the dependency tree.
    let root = get_root(&metadata)?;

    // Construct the document.
    let doc = DocumentBuilder::default()
        .document_name(args.output_file_name(root).to_string_lossy().as_ref())
        .try_document_namespace(args.host_url())?
        .creator(get_creator())
        .build()?;

    // Get the writer to the right output stream.
    let mut writer = args.open_output_writer(root)?;

    // Write the document out in the requested format.
    match args.format() {
        Format::KeyValue => key_value::write(&mut writer, &doc)?,
        _ => unimplemented!("{} format not yet implemented", args.format()),
    }

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

/// Identify the creator(s) of the SBOM.
fn get_creator() -> Vec<Creator> {
    let mut creator = vec![];

    if let Ok(user) = git::get_current_user() {
        creator.push(Creator::person(user.name, user.email));
    }

    creator.push(Creator::tool("cargo-spdx 0.1.0"));
    creator
}
