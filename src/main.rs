//! Generate an SPDX SBOM for a Rust crate.

#![deny(missing_debug_implementations)]
#![deny(missing_copy_implementations)]
#![deny(missing_docs)]

use crate::cargo::CrateMetadata;
use crate::cli::Args;
use crate::format::Format;
use crate::output::OutputManager;
use anyhow::Result;

mod cargo;
mod cli;
mod document;
mod format;
mod git;
mod output;

/// Program entrypoint, only inits the system, calls `run` and reports errors.
fn main() {
    init();

    if let Err(e) = run() {
        eprintln!("error: {}", e);
    }
}

/// Initialize the context needed to run.
fn init() {
    // Start the environment logger.
    env_logger::init();
}

/// Gathers CLI args, constructs an SPDX `Document`, and outputs that document.
fn run() -> Result<()> {
    // Load the CLI args and crate metadata, and then figure out where the SPDX file
    // will be written, setting up a manager to ensure we only write when conditions are met.
    let args = Args::read();
    let metadata = CrateMetadata::load()?;
    let output_manager = OutputManager::new(&args, metadata.root()?);

    // Build the document.
    let doc = document::build(&args, &output_manager.output_file_name())?;

    // Write the document to the output file.
    output_manager.write_document(doc)
}
