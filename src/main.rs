//! Generate an SPDX SBOM for a Rust crate.

#![deny(missing_debug_implementations)]
#![deny(missing_copy_implementations)]
#![deny(missing_docs)]

use crate::cargo::MetadataExt;
use crate::cli::Args;
use crate::format::Format;
use crate::output::OutputManager;
use anyhow::Result;
use build::build;
use cargo::cargo_exec;
use cargo_metadata::camino::Utf8PathBuf;
use cargo_metadata::MetadataCommand;
use clap::Parser;
use document::{get_creation_info, DocumentBuilder, File, FileType, Package, Relationship};
use std::io::BufRead;
use std::path::PathBuf;
use std::process::Command;

mod build;
mod cargo;
mod cli;
mod document;
mod format;
mod git;
mod output;

/// Program entrypoint, only inits the system, calls `run` and reports errors.
fn main() -> Result<()> {
    // Start the environment logger.
    env_logger::init();
    let args = Args::parse();

    // Invoke build subcommand if specified to run `cargo build` with added SBOMs
    if let Some(cmd) = &args.subcommand {
        match cmd {
            cli::Command::Build { args: build_args } => {
                build(build_args, args.host_url()?.as_ref(), args.format())?;
            }
        };
    }
    // Otherwise create an SBOM for the current workspace
    else {
        let metadata = MetadataCommand::new().exec()?;

        // Figure out where the SPDX file will be written, setting up a manager to ensure we only write when conditions are met.
        let output_manager = if let Some(output) = args.output() {
            // User specified a path, use that
            OutputManager::new(output, args.force(), args.format())
        } else {
            // Determine path from metadata
            let path = PathBuf::from(format!(
                "{}{}",
                &metadata.root()?.name,
                args.format().extension()
            ));
            OutputManager::new(&path, args.force(), args.format())
        };

        // Determine the files, package, and relationships for each
        // member of the workspace
        let mut packages = Vec::new();
        let mut files = Vec::new();
        let mut relationships = Vec::new();
        for member in &metadata.workspace_members {
            let package = &metadata[member];
            // List files in package
            let out = Command::new(&cargo_exec())
                .args([
                    "package",
                    "--list",
                    "--allow-dirty",
                    "--manifest-path",
                    package.manifest_path.as_str(),
                ])
                .output()?;
            let root = package.manifest_path.parent().unwrap();
            let mut source_files = out
                .stdout
                .lines()
                .filter_map(Result::ok)
                // `cargo package --list` includes the normalized Cargo.toml.orig
                // but this won't be present locally (`cargo package` fails if it is)
                // cargo package always lists Cargo.lock too, which may not be present.
                // So just filter out any entries which can't be found locally
                .filter_map(|path| {
                    // Path is relative to crate root, so we need to add
                    // the crate root in order to find it locally.
                    let mut abs_path = Utf8PathBuf::from(root);
                    abs_path.push(path);
                    if abs_path.exists() {
                        Some(abs_path)
                    } else {
                        None
                    }
                })
                .map(|path| -> Result<File, anyhow::Error> {
                    File::try_from_file(
                        &path,
                        root,
                        FileType::Source,
                        Some(&package.name),
                        Some(&package.version.to_string()),
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            let spdx_package: Package = package.into();
            for file in &source_files {
                relationships.push(Relationship {
                    comment: None,
                    related_spdx_element: file.spdxid.clone(),
                    relationship_type: document::RelationshipType::Contains,
                    spdx_element_id: spdx_package.spdxid.clone(),
                });
            }
            packages.push(spdx_package);
            files.append(&mut source_files);
        }

        let doc = DocumentBuilder::default()
            .document_name(output_manager.output_file_name())
            .try_document_namespace(args.host_url()?.as_ref())?
            .creation_info(get_creation_info()?)
            .files(files)
            .packages(packages)
            .relationships(relationships)
            .build()?;
        output_manager.write_document(&doc)?;
    }
    Ok(())
}
