//! Generate an SPDX SBOM for a Rust crate.

#![deny(missing_debug_implementations)]
#![deny(missing_copy_implementations)]
#![deny(missing_docs)]

use crate::cargo::get_root;
use crate::cli::{Cli, Format};
use crate::document::{get_creator, DocumentBuilder};
use anyhow::Result;
use cargo_metadata::MetadataCommand;
use clap::Parser as _;

mod cargo;
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
    let args = Cli::parse();

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
