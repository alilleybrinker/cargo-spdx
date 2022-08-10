//! Module for working with SPDX documents.

use crate::git::get_current_user;
use anyhow::{Context, Result};
use cargo_metadata::camino::Utf8Path;
pub use schema::*;
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::{fs, io};

mod schema;

pub const NOASSERTION: &str = "NOASSERTION";

/// Build a new SPDX document builder based on collected information.
pub fn builder(host_url: &str, output_file_name: &str) -> Result<DocumentBuilder> {
    log::info!(target: "cargo_spdx", "building the document");

    let mut builder = DocumentBuilder::default();
    builder
        .document_name(output_file_name)
        .try_document_namespace(host_url)?
        .creation_info(get_creation_info()?);
    Ok(builder)
}

/// Identify the creator(s) of the SBOM.
pub fn get_creation_info() -> Result<CreationInfo> {
    let mut creator = vec![];

    if let Ok(user) = get_current_user() {
        creator.push(Creator::person(user.name, user.email));
    }

    creator.push(Creator::tool("cargo-spdx 0.1.0"));

    Ok(CreationInfoBuilder::default().creators(creator).build()?)
}

impl From<&cargo_metadata::Package> for Package {
    fn from(package: &cargo_metadata::Package) -> Self {
        Package {
            name: package.name.to_string(),
            spdxid: format!("SPDXRef-{}-{}", package.name, package.version),
            version_info: Some(package.version.to_string()),
            package_file_name: None,
            supplier: None,
            originator: None,
            download_location: NOASSERTION.to_string(),
            files_analyzed: None,
            package_verification_code: None,
            checksums: None,
            homepage: package.homepage.clone(),
            source_info: None,
            license_concluded: NOASSERTION.to_string(),
            license_declared: NOASSERTION.to_string(),
            copyright_text: NOASSERTION.to_string(),
            description: None,
            comment: None,
            external_refs: Some(vec![ExternalRef {
                reference_category: ReferenceCategory::PackageManager,
                reference_type: "purl".to_string(),
                reference_locator: format!("pkg:cargo/{}@{}", package.name, package.version),
                comment: None,
            }]),
            annotations: None,
            attribution_texts: None,
            has_files: None,
            license_comments: None,
            license_info_from_files: None,
            summary: None,
        }
    }
}

impl File {
    /// Create a SPDX File information entry from a file on disk
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file
    /// * `root` - Root of the package. The file name in the SPDX entry will be relative to this
    /// * `file_type` - SPDX File type
    /// * `package_name` - Optional. If present will be included in the SPDXID for the File,
    /// to enable unique SPDXIDs
    /// * `package_version` - Optional. If present will be included in the SPDXID for the File,
    /// to enable unique SPDXIDs
    pub fn try_from_file(
        path: &Utf8Path,
        root: &Utf8Path,
        file_type: FileType,
        package_name: Option<&str>,
        package_version: Option<&str>,
    ) -> Result<File> {
        let file_name = pathdiff::diff_utf8_paths(path, root).unwrap();
        let spdxid = format!(
            "SPDXRef-File-{}{}{}",
            package_name.map(|n| format!("{}-", n)).unwrap_or_default(),
            package_version
                .map(|v| format!("{}-", v))
                .unwrap_or_default(),
            file_name
        )
        // SPDX IDs must only container alphanumeric chars, '.' or '-'
        .replace(
            |c: char| !(c.is_alphanumeric() || c == '-' || c == '.'),
            "-",
        );
        Ok(File {
            annotations: None,
            attribution_texts: None,
            checksums: Some(calculate_checksums(path)?),
            comment: None,
            copyright_text: NOASSERTION.to_string(),
            file_contributors: None,
            file_dependencies: None,
            file_name: file_name.to_string(),
            file_types: Some(vec![file_type]),
            license_comments: None,
            license_concluded: NOASSERTION.to_string(),
            license_info_in_files: None,
            notice_text: None,
            spdxid,
        })
    }
}

/// Generate SHA1 and SHA256 checksums for a given file
/// SPDX spec mandates SHA1
fn calculate_checksums(path: &Utf8Path) -> Result<Vec<FileChecksum>> {
    log::debug!("calculating checksums for {}", path);
    let mut file =
        fs::File::open(path).context(format!("Failed to calculate checksum for {}", path))?;
    let mut sha256 = Sha256::new();
    let sha1 = Sha1::new();
    io::copy(&mut file, &mut sha256)?;
    let sha256_hash = sha256.finalize();
    let sha1_hash = sha1.finalize();
    let output = vec![
        FileChecksum {
            algorithm: Algorithm::Sha1,
            checksum_value: hex::encode(&sha1_hash),
        },
        FileChecksum {
            algorithm: Algorithm::Sha256,
            checksum_value: hex::encode(&sha256_hash),
        },
    ];
    log::debug!("finished calculating checksums for {}", path);
    Ok(output)
}
