use crate::Cli;
use anyhow::{anyhow, Result};
use cargo_metadata::Package;
use std::ffi::OsString;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::ops::Not as _;
use std::path::PathBuf;

/// Get the path the file will be written out to.
#[inline]
pub fn resolve_path(cli: &Cli, pkg: &Package) -> PathBuf {
    // It's either the specified path, or a default path based on the name of the root package
    // and the format selected by the user.
    cli.output()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| package_path(cli, pkg))
}

/// Get the name of the output file, if there is one.
#[inline]
pub fn file_name(cli: &Cli, pkg: &Package) -> OsString {
    resolve_path(cli, pkg)
        .file_name()
        // PANIC SAFETY: We check for the `file_name` when parsing arguments.
        .unwrap()
        .to_owned()
}

/// Get a writer to the correct output stream.
pub fn open_writer(cli: &Cli, pkg: &Package) -> Result<Box<dyn Write>> {
    let file_path = resolve_path(cli, pkg);

    // A little truth table making clear this conditional is the right one.
    //
    // ---------
    // | T | T | - forcing and exists - no error
    // | T | F | - forcing and doesn't exist - no error
    // | F | T | - not forcing and exists - error
    // | F | F | - not forcing and doesn't exist - no error
    // ---------

    if cli.force().not() && file_path.exists() {
        return Err(anyhow!("output file already exists"));
    }

    Ok(Box::new(BufWriter::new(File::create(file_path)?)))
}

/// Get the name of the file to be generated for the package.
fn package_path(cli: &Cli, pkg: &Package) -> PathBuf {
    PathBuf::from(format!("{}{}", pkg.name, cli.format().extension()))
}
