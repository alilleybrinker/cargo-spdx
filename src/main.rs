//! Generate an SPDX SBOM for a Rust crate.

#![deny(missing_debug_implementations)]
#![deny(missing_copy_implementations)]
#![deny(missing_docs)]

use crate::cargo::CrateMetadata;
use crate::cli::Args;
use crate::document::DocumentBuilder;
use crate::format::Format;
use crate::output::OutputManager;
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
    // Load the CLI args and crate metadata, and then figure out where the SPDX file
    // will be written, setting up a manager to ensure we only write when conditions are met.
    let args = Args::parse();
    let metadata = CrateMetadata::load()?;
    let output_manager = OutputManager::new(&args, metadata.root()?);

    // Construct the document.
    let doc = DocumentBuilder::default()
        .document_name(output_manager.output_file_name())
        .try_document_namespace(args.host_url())?
        .creator(document::get_creator())
        .build()?;

    // Write the document to the output file.
    output_manager.write_document(doc)
}
