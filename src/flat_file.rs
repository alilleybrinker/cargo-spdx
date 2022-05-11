//! Writes the flat file format out.

use crate::spdx::Document;
use std::fs::File;
use std::io::{self, Write as _};
use std::path::Path;

pub fn write_to_disk<P: AsRef<Path>>(doc: &Document, to: P) -> io::Result<()> {
    // Inner function which avoids excess code duplication due to monomorphization.
    fn _write_to_disk(doc: &Document, to: &Path) -> io::Result<()> {
        let mut f = File::create(to)?;

        writeln!(f, "SPDXVersion: {}", doc.spdx_version)?;
        writeln!(f, "DataLicense: {}", doc.data_license)?;
        writeln!(f, "SPDXID: {}", doc.spdx_identifier)?;
        writeln!(f, "DocumentName: {}", doc.document_name)?;
        writeln!(f, "DocumentNamespace: {}", doc.document_namespace)?;

        if let Some(external_document_reference) = &doc.external_document_reference {
            writeln!(f, "ExternalDocumentRef: {}", external_document_reference)?;
        }

        if let Some(license_list_version) = &doc.license_list_version {
            writeln!(f, "LicenseListVersion: {}", license_list_version)?;
        }

        for creator in &doc.creator {
            writeln!(f, "Creator: {}", creator)?;
        }

        writeln!(f, "Created: {}", doc.created)?;

        if let Some(creator_comment) = &doc.creator_comment {
            writeln!(f, "CreatorComment: {}", creator_comment)?;
        }

        if let Some(document_comment) = &doc.document_comment {
            writeln!(f, "DocumentComment: {}", document_comment)?;
        }

        Ok(())
    }

    _write_to_disk(doc, to.as_ref())
}
