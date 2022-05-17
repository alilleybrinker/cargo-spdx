//! Defines the CLI for `cargo-spdx`.

use anyhow::{anyhow, Error, Result};
use cargo_metadata::Package;
use clap::Parser;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::ops::Not as _;
use std::path::PathBuf;
use std::str::FromStr;

/// Contains the parsed CLI arguments.
#[derive(Parser)]
#[clap(version, about, long_about = None)]
pub struct Cli {
    /// The output format to use.
    #[clap(short, long)]
    format: Option<Format>,

    /// The URL where the SBOM will be hosted.
    #[clap(short = 'H', long)]
    host_url: String,

    /// The name of a file to write out to.
    #[clap(short, long)]
    #[clap(parse(try_from_os_str = parse_output))]
    output: Option<PathBuf>,

    /// Force the output, replacing any existing file with the same name.
    #[clap(short = 'F', long)]
    force: bool,

    /// Ignored.
    ///
    /// This is the "spdx" part when called as a Cargo subcommand.
    _spdx: String,
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

impl Cli {
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

    /// Get the path the file will be written out to.
    #[inline]
    pub fn resolve_output_path(&self, pkg: &Package) -> PathBuf {
        // It's either the specified path, or a default path based on the name of the root package
        // and the format selected by the user.
        self.output
            .clone()
            .unwrap_or_else(|| self.resolve_package_path(pkg))
    }

    /// Get the name of the output file, if there is one.
    #[inline]
    pub fn output_file_name(&self, pkg: &Package) -> OsString {
        // PANIC SAFETY: We check for the `file_name` when parsing arguments.
        self.resolve_output_path(pkg)
            .file_name()
            .unwrap()
            .to_owned()
    }

    /// Get a writer to the correct output stream.
    pub fn open_output_writer(&self, pkg: &Package) -> Result<Box<dyn Write>> {
        let file_path = self.resolve_output_path(pkg);

        // A little truth table making clear this conditional is the right one.
        //
        // ---------
        // | T | T | - forcing and exists - no error
        // | T | F | - forcing and doesn't exist - no error
        // | F | T | - not forcing and exists - error
        // | F | F | - not forcing and doesn't exist - no error
        // ---------

        if self.force.not() && file_path.exists() {
            return Err(anyhow!("output file already exists"));
        }

        Ok(Box::new(BufWriter::new(File::create(file_path)?)))
    }

    /// Get the name of the file to be generated for the package.
    fn resolve_package_path(&self, pkg: &Package) -> PathBuf {
        PathBuf::from(format!("{}{}", pkg.name, self.format().extension()))
    }
}

/// The output format for the SPDX document.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Format {
    /// Key-value format.
    KeyValue,

    /// JSON format.
    Json,

    /// YAML format.
    Yaml,

    /// RDF format.
    Rdf,
}

impl Format {
    /// Get the file extension for the format.
    fn extension(&self) -> &'static str {
        match self {
            Format::KeyValue => ".spdx",
            Format::Json => ".spdx.json",
            Format::Yaml => ".spdx.yaml",
            Format::Rdf => ".spdx.rdf",
        }
    }
}

impl Default for Format {
    fn default() -> Self {
        Format::KeyValue
    }
}

impl FromStr for Format {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "kv" => Ok(Format::KeyValue),
            "json" => Ok(Format::Json),
            "yaml" => Ok(Format::Yaml),
            "rdf" => Ok(Format::Rdf),
            s => Err(anyhow!("unknown format '{}'", s)),
        }
    }
}
