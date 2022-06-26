use crate::document::Document;
use crate::{format, Args, Format};
use anyhow::{anyhow, Result};
use cargo_metadata::Package;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::ops::Not as _;
use std::path::PathBuf;

/// Handles writing to the correct path.
#[derive(Debug)]
pub struct OutputManager {
    /// The path to be written to.
    to: PathBuf,
    /// The format to write the output in.
    format: Format,
    /// Whether output is being forced.
    force: bool,
}

impl OutputManager {
    /// Get a new output manager based on CLI args and package info.
    pub fn new(args: &Args, pkg: &Package) -> Self {
        log::info!(target: "cargo_spdx", "determining output path");

        // It's either the specified path, or a default path based on the name of the root package
        // and the format selected by the user.
        let to = args
            .output()
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| format!("{}{}", pkg.name, args.format_extension()).into());

        let format = args.format();
        let force = args.force();

        OutputManager { to, format, force }
    }

    /// Get the name of the output file.
    #[inline]
    pub fn output_file_name(&self) -> String {
        // If there's no file, we have an empty `OsStr`, which is fine because we won't
        // write out anything anyway (this condition is checked during writing, and we error
        // out if there's no file name in the output path).
        self.to
            .file_name()
            .unwrap_or_else(|| OsStr::new(""))
            .to_string_lossy()
            .to_string()
    }

    /// Write the document to the output file in the specified format.
    #[inline]
    pub fn write_document(&self, doc: Document) -> Result<()> {
        // Check the output file has a file name and isn't a directory.
        if self.to.file_name().is_none() {
            return Err(anyhow!("missing output file name"));
        }

        if self.to.is_dir() {
            return Err(anyhow!("output can't be a directory"));
        }

        // Get the writer to the output file.
        let mut writer = self.get_writer()?;

        // Write the document out in the requested format.
        match self.format {
            Format::KeyValue => Ok(format::key_value::write(&mut writer, &doc)?),
            _ => Err(anyhow!("{} format not yet implemented", self.format)),
        }
    }

    /// Get a writer to the output file.
    ///
    /// Returns an error if the output file already exists and the user hasn't set output
    /// to be forced.
    fn get_writer(&self) -> Result<Box<dyn Write>> {
        // A little truth table making clear this conditional is the right one.
        //
        // ---------
        // | T | T | - forcing and exists - no error
        // | T | F | - forcing and doesn't exist - no error
        // | F | T | - not forcing and exists - error
        // | F | F | - not forcing and doesn't exist - no error
        // ---------
        if self.force.not() && self.to.exists() {
            return Err(anyhow!("output file already exists"));
        }

        Ok(Box::new(BufWriter::new(File::create(&self.to)?)))
    }
}
