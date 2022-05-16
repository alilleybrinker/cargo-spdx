//! Writes the flat file format out.

use crate::document::Document;
use anyhow::Result;
use std::io::Write;

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

pub fn write<W: Write>(mut w: W, doc: &Document) -> Result<()> {
    write_field!(w, "SPDXVersion: {}", doc.spdx_version);
    write_field!(w, "DataLicense: {}", doc.data_license);
    write_field!(w, "SPDXID: {}", doc.spdx_identifier);
    write_field!(w, "DocumentName: {}", doc.document_name);
    write_field!(w, "DocumentNamespace: {}", doc.document_namespace);
    write_field!(@opt, w, "ExternalDocumentRef: {}", doc.external_document_reference);
    write_field!(@opt, w, "LicenseListVersion: {}", doc.license_list_version);
    write_field!(@all, w, "Creator: {}", doc.creator);
    write_field!(w, "Created: {}", doc.created);
    write_field!(@opt, w, "CreatorComment: {}", doc.creator_comment);
    write_field!(@opt, w, "DocumentComment: {}", doc.document_comment);

    Ok(())
}
