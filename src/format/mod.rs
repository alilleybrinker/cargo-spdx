//! Defines the output formats supported by `cargo-spdx`.

pub mod key_value;

use anyhow::{anyhow, Error};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

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
    pub fn extension(&self) -> &'static str {
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

impl Display for Format {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Format::KeyValue => write!(f, "Key-Value"),
            Format::Json => write!(f, "JSON"),
            Format::Yaml => write!(f, "YAML"),
            Format::Rdf => write!(f, "RDF"),
        }
    }
}

impl FromStr for Format {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "kv" | "Key-Value" => Ok(Format::KeyValue),
            "json" | "JSON" => Ok(Format::Json),
            "yaml" | "YAML" => Ok(Format::Yaml),
            "rdf" | "RDF" => Ok(Format::Rdf),
            s => Err(anyhow!("unknown format '{}'", s)),
        }
    }
}
