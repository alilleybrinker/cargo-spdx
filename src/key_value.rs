//! Writes the flat file format out.

use crate::spdx::Document;
use std::fs::File;
use std::io::{self, BufWriter, Write as _};
use std::path::Path;

/// Convenience macro to provide uniform field-writing syntax.
///
/// This macro exists to make the `write_to_disk` method body cleaner.
/// It provides a uniform calling construct to write out regular, optional,
/// and iterable fields.
///
/// Making it easier to skim the code at the call-sites it intended to make
/// the code more closely resemble the structure of the file being written out.
macro_rules! write_field {
    // Write out a single field.
    ( $f:ident, $fmt:literal, $field:expr ) => {
        writeln!($f, $fmt, $field)?
    };

    // Write out an optional field.
    ( @opt, $f:ident, $fmt:literal, $field:expr ) => {
        if let Some(field) = &$field {
            write_field!($f, $fmt, field);
        }
    };

    // Write out an iterable field.
    ( @all, $f:ident, $fmt:literal, $field:expr ) => {
        for item in &$field {
            write_field!($f, $fmt, item);
        }
    };
}

pub fn write_to_disk<P: AsRef<Path>>(doc: &Document, to: P) -> io::Result<()> {
    // Inner function which avoids excess code duplication due to monomorphization.
    fn _write_to_disk(doc: &Document, to: &Path) -> io::Result<()> {
        let mut f = BufWriter::new(File::create(to)?);

        write_field!(f, "SPDXVersion: {}", doc.spdx_version);
        write_field!(f, "DataLicense: {}", doc.data_license);
        write_field!(f, "SPDXID: {}", doc.spdx_identifier);
        write_field!(f, "DocumentName: {}", doc.document_name);
        write_field!(f, "DocumentNamespace: {}", doc.document_namespace);
        write_field!(@opt, f, "ExternalDocumentRef: {}", doc.external_document_reference);
        write_field!(@opt, f, "LicenseListVersion: {}", doc.license_list_version);
        write_field!(@all, f, "Creator: {}", doc.creator);
        write_field!(f, "Created: {}", doc.created);
        write_field!(@opt, f, "CreatorComment: {}", doc.creator_comment);
        write_field!(@opt, f, "DocumentComment: {}", doc.document_comment);

        Ok(())
    }

    _write_to_disk(doc, to.as_ref())
}
