//! Generate an SPDX SBOM for a Rust crate.

#![deny(missing_debug_implementations)]
#![deny(missing_copy_implementations)]
#![deny(missing_docs)]

use crate::cargo::CrateMetadata;
use crate::cli::Cli;
use crate::document::DocumentBuilder;
use crate::format::Format;
use anyhow::Result;
use clap::Parser as _;

mod cargo;
mod cli;
mod document;
mod format;
mod git;
mod output;

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

    // Get the metadata for the crate and the crate root.
    let metadata = CrateMetadata::load()?;
    let root = metadata.root()?;

    // Construct the document.
    let doc = DocumentBuilder::default()
        .document_name(output::file_name(&args, root).to_string_lossy().as_ref())
        .try_document_namespace(args.host_url())?
        .creator(document::get_creator())
        .build()?;

    // Get the writer to the right output stream.
    let mut writer = output::open_writer(&args, root)?;

    // Write the document out in the requested format.
    match args.format() {
        Format::KeyValue => format::key_value::write(&mut writer, &doc)?,
        _ => unimplemented!("{} format not yet implemented", args.format()),
    }

    Ok(())
}
