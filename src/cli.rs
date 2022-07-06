//! Defines the CLI for `cargo-spdx`.

use crate::format::Format;
use anyhow::{anyhow, Result};
use clap::Parser;
use clap::Subcommand;
use dialoguer::Input;
use std::borrow::Cow;
use std::ffi::OsString;
use std::ops::Deref;
use std::ops::Not as _;
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[allow(missing_docs)]
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
    host_url: Option<String>,

    /// The path of the desired output file.
    #[clap(short, long)]
    output: Option<PathBuf>,

    /// Force the output, replacing any existing file with the same name.
    #[clap(short = 'F', long)]
    force: bool,

    /// Do not run interactively.
    #[clap(short = 'n', long = "no-interact")]
    no_interact: bool,

    #[clap(subcommand)]
    pub subcommand: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run `cargo build`, generating SBOMs for produced binaries
    #[clap(after_help = "
The SBOMs are located alongside the binaries themselves, so if cargo produces
target/debug/foo then the SBOM will be created at target/debug/foo.spdx[.json,.yaml]
    
Example:
$ cargo spdx -H https://foo.com build -- --release --target x86_64-unknown-linux-musl

Returns an error if `--message-format` is passed as an argument")]
    Build {
        /// Arguments to pass to `cargo build`
        #[clap(multiple_values = true, takes_value = true, required = false)]
        args: Vec<OsString>,
    },
}

/// Parse the format from the CLI input.
fn parse_format(input: &str) -> Result<Format> {
    let format = Format::from_str(input)?;

    match format {
        Format::KeyValue | Format::Json | Format::Yaml => Ok(format),
        Format::Rdf => return Err(anyhow!("RDF format not implemented")),
    }
}

impl Args {
    /// Get the format selected by the user.
    #[inline]
    pub fn format(&self) -> Format {
        self.format.unwrap_or_default()
    }

    /// Get the URL the SBOM will be hosted.
    #[inline]
    pub fn host_url(&self) -> Result<Cow<'_, str>> {
        match &self.host_url {
            Some(host_url) => Ok(Cow::Borrowed(host_url)),
            None => {
                if self.is_interactive().not() {
                    return Err(anyhow!(
                        "if running non-interactively, --host-url must be specified"
                    ));
                }

                let host_url = Input::<String>::new()
                    .with_prompt("Where will the SBOM be hosted (must be unique)?")
                    .interact_text()?;

                Ok(Cow::Owned(host_url))
            }
        }
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

    /// Check if the command is running interactively.
    #[inline]
    pub fn is_interactive(&self) -> bool {
        self.no_interact.not()
    }
}
