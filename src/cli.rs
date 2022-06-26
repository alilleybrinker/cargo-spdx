//! Defines the CLI for `cargo-spdx`.

use crate::format::Format;
use anyhow::{anyhow, Result};
use clap::Parser;
use std::ffi::OsStr;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Contains the parsed CLI arguments.
#[derive(Parser)]
#[clap(bin_name = "cargo")]
pub enum Args {
    /// Generate an SPDX SBOM for a crate.
    Spdx(SpdxArgs),
}

// Use a Deref impl to avoid the rest of the codebase having to care
// about the nesting structure required here.
impl Deref for Args {
    type Target = SpdxArgs;

    fn deref(&self) -> &Self::Target {
        match self {
            Args::Spdx(inner) => inner,
        }
    }
}

/// The inner argument type.
#[derive(Parser)]
#[clap(version, about, long_about = None)]
pub struct SpdxArgs {
    /// The output format to use: 'kv' (default), 'json', 'yaml', 'rdf'.
    #[clap(short, long)]
    #[clap(parse(try_from_str = parse_format))]
    format: Option<Format>,

    /// The URL where the SBOM will be hosted. Must be unique for each SBOM.
    #[clap(short = 'H', long)]
    host_url: String,

    /// The path of the desired output file.
    #[clap(short, long)]
    #[clap(parse(try_from_os_str = parse_output))]
    output: Option<PathBuf>,

    /// Force the output, replacing any existing file with the same name.
    #[clap(short = 'F', long)]
    force: bool,
}

/// Parse the format from the CLI input.
fn parse_format(input: &str) -> Result<Format> {
    let format = Format::from_str(input)?;

    match format {
        Format::KeyValue => Ok(format),
        Format::Json => return Err(anyhow!("JSON format not implemented")),
        Format::Yaml => return Err(anyhow!("YAML format not implemented")),
        Format::Rdf => return Err(anyhow!("RDF format not implemented")),
    }
}

/// Get a `PathBuf` to a file.
fn parse_output(input: &OsStr) -> Result<PathBuf> {
    let output = PathBuf::from(input);

    if output.file_name().is_none() {
        return Err(anyhow!("missing output file name"));
    }

    if output.is_dir() {
        return Err(anyhow!("output can't be a directory"));
    }

    Ok(output)
}

impl Args {
    /// Get the format selected by the user.
    #[inline]
    pub fn format(&self) -> Format {
        self.format.unwrap_or_default()
    }

    /// Get the URL the SBOM will be hosted.
    #[inline]
    pub fn host_url(&self) -> &str {
        &self.host_url
    }

    /// Get the possible output path of the program.
    #[inline]
    pub fn output(&self) -> Option<&Path> {
        self.output.as_deref()
    }

    /// Whether we should forcefully overwrite prior output.
    #[inline]
    pub fn force(&self) -> bool {
        self.force
    }

    /// Get the file extension for the configured format.
    #[inline]
    pub fn format_extension(&self) -> &'static str {
        self.format().extension()
    }
}
