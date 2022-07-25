//! Implements `cargo spdx build` subcommand

use crate::document::{self, File, Package, Relationship, RelationshipType};
use crate::format::Format;
use crate::output::OutputManager;
use anyhow::Result;
use cargo_metadata::camino::Utf8PathBuf;
use cargo_metadata::{Artifact, Metadata, MetadataCommand, PackageId};
use clap::Parser;
use std::collections::HashMap;
use std::ffi::OsString;
use std::io::{BufRead, BufReader};
use std::process::{ChildStdout, Command, Stdio};

// Used for capturing the `cargo build` arguments we need to intercept
#[derive(Debug, Parser)]
#[clap(name = "build", ignore_errors = true)]
struct CargoBuild {
    #[clap(long)]
    target: Option<String>,
    #[clap(long)]
    message_format: Option<String>,
    // clap_cargo doesn't support -F or comma separated features
    // https://github.com/crate-ci/clap-cargo/pull/33 fixes first
    // TODO fix second with custom parser
    #[clap(flatten)]
    features: clap_cargo::Features,
}

// Stores packages and binaries identified from `cargo build`
#[derive(Debug, Default)]
struct CargoBuildInfo {
    /// packages identified from cargo json messages
    packages: HashMap<PackageId, Package>,
    /// binaries identifed from cargo json messages
    binaries: Vec<(Utf8PathBuf, PackageId)>,
}

/// Runs a `cargo build`, outputting an SBOM for each binary produced
///
/// # Arguments
/// * `build_args` - Arguments that will be passed to `cargo build`
///
pub fn build(build_args: &[OsString], host_url: &str, format: Format) -> Result<()> {
    // This function runs `cargo build` with json messages enabled, in order to detect produced binaries
    // and identify crates used in build.

    // cargo sets this for cargo subcommands, so use that when invoking cargo, if present
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut cargo_build_args: Vec<OsString> = vec!["build".to_string().into()];
    cargo_build_args.extend(build_args.iter().cloned());

    // cargo messages only give a package id for crates, we need cargo metadata to get more
    // detail.
    // Determine what features/target args need passing to cargo metadata by forwarding any relevant
    // user specified `cargo build` args to `cargo metadata`.
    // (We could probably just not filter-platform, and pass all features, as cargo
    // messages tell us what was actually used in the build. But this future proofs
    // against us using the feature information returned by cargo metadata.)
    let mut metadata_cmd = MetadataCommand::new();
    let CargoBuild {
        features,
        target,
        message_format,
    } = CargoBuild::try_parse_from(&cargo_build_args)?;
    features.forward_metadata(&mut metadata_cmd);
    if let Some(target) = target {
        metadata_cmd.other_options(vec!["--filter-platform".to_string(), target]);
    }
    let metadata = metadata_cmd.exec()?;

    // If the user specified a non-json message format for cargo, then exit as we won't
    // be able to specify --message-format=json to cargo
    if let Some(message_format) = &message_format {
        if !message_format.starts_with("json") {
            anyhow::bail!(
                "--message-format must either be omittted or be set to one of the json options"
            );
        }
    } else {
        cargo_build_args.push("--message-format=json".to_string().into());
    }

    // Run `cargo build`
    let mut child = Command::new(cargo)
        .stderr(Stdio::inherit())
        .stdout(Stdio::piped())
        .args(cargo_build_args)
        .spawn()?;

    let stdout = child.stdout.take().unwrap();
    let cargo_build_info = process_json_messages(stdout, message_format.is_some(), &metadata)?;

    // Verify cargo build succeeds. If it fails, exit with the same exit code
    let ecode = child.wait()?;
    if !ecode.success() {
        log::error!(target: "cargo_spdx", "cargo build failed");
        std::process::exit(ecode.code().unwrap_or(1));
    }

    for (binary, package_id) in cargo_build_info.binaries {
        produce_sbom(
            binary,
            &cargo_build_info.packages,
            &package_id,
            host_url,
            format,
        )?;
    }
    Ok(())
}

// Identify binaries and packages from cargo's json messages
fn process_json_messages(
    stdout: ChildStdout,
    print_messages: bool,
    metadata: &Metadata,
) -> Result<CargoBuildInfo, anyhow::Error> {
    let mut collector = CargoBuildInfo::default();

    let reader = BufReader::new(stdout);
    reader
        .lines()
        .filter_map(|line| {
            line.and_then(|line| {
                // If the user specified a message format arg, then
                // print the message to stdout.
                if print_messages {
                    println!("{}", line);
                }

                Ok(serde_json::from_str(&line)?)
            })
            .ok()
        })
        .try_for_each::<_, Result<()>>(|artifact: Artifact| {
            // Identify dependent packages
            let package = &metadata[&artifact.package_id];
            if !collector.packages.contains_key(&artifact.package_id) {
                collector
                    .packages
                    .insert(artifact.package_id.clone(), package.into());
            }

            // Identify executables
            // TODO also identify compiled libraries e.g dll/.so/.a
            if let Some(executable) = artifact.executable {
                collector.binaries.push((executable, artifact.package_id));
            }

            Ok(())
        })?;
    Ok(collector)
}

// Create SBOM for each binary and output it alongside the binary
fn produce_sbom(
    binary: cargo_metadata::camino::Utf8PathBuf,
    packages: &HashMap<PackageId, Package>,
    package_id: &PackageId,
    host_url: &str,
    format: Format,
) -> Result<()> {
    let mut relationships = Vec::new();

    // Create file information
    let file = File::try_from_binary(&binary)?;

    // Indicate the crate the binary was generated from
    relationships.push(Relationship {
        comment: None,
        related_spdx_element: packages.get(package_id).unwrap().spdxid.clone(),
        relationship_type: RelationshipType::GeneratedFrom,
        spdx_element_id: file.spdxid.clone(),
    });

    // Add all crates as dependencies of the binary
    // (May include unused dependencies e.g as part of a workspace build that produces
    // multiple binaries. Not obvious how to refine this outside of cargo
    // without the user doing a build per binary)
    relationships.extend(packages.values().map(|package| Relationship {
        comment: None,
        related_spdx_element: package.spdxid.clone(),
        // Is this the best fit? Should the file indicate that it statically links the crate?
        relationship_type: RelationshipType::DependsOn,
        spdx_element_id: file.spdxid.clone(),
    }));

    // Create the SBOM and write it out
    let mut spdx_path = binary;
    spdx_path.set_extension(
        format!(
            "{}{}",
            spdx_path.extension().unwrap_or_default(),
            format.extension()
        )
        .trim_start_matches('.'),
    );
    let output_manager = OutputManager::new(&spdx_path.into_std_path_buf(), true, format);
    let doc = document::builder(host_url, &output_manager.output_file_name())?
        .files(vec![file])
        .packages(packages.values().cloned().collect())
        .relationships(relationships)
        .build()?;
    output_manager.write_document(&doc)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::CargoBuild;

    #[test]
    fn test_cargo_build_arg_parsing() {
        // Test there's no error when an arg not in CargoBuild is specified
        let cargs = CargoBuild::try_parse_from([
            "build",
            "--no-default-features",
            "--features",
            "foo bar",
            "--message-format=json",
            "--target=x86_64-unknown-linux-musl",
            "--release",
        ])
        .unwrap();
        assert!(cargs.features.no_default_features);
        assert_eq!(
            cargs.features.features,
            vec!["foo".to_string(), "bar".to_string()]
        );
        assert_eq!(cargs.message_format, Some("json".to_string()));
        assert_eq!(cargs.target, Some("x86_64-unknown-linux-musl".to_string()));
    }
}
