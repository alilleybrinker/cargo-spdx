//! Module for working with SPDX documents.

use crate::git::get_current_user;
use anyhow::{Context, Result};
use cargo_metadata::camino::Utf8PathBuf;
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
    pub fn try_from_binary(path: &Utf8PathBuf) -> Result<File> {
        let file_name = path.file_name().unwrap();
        let spdxid = format!("SPDXRef-File-{}", file_name);
        Ok(File {
            annotations: None,
            attribution_texts: None,
            checksums: Some(calculate_checksums(path)?),
            comment: None,
            copyright_text: NOASSERTION.to_string(),
            file_contributors: None,
            file_dependencies: None,
            file_name: file_name.to_string(),
            file_types: Some(vec![FileType::Binary]),
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
fn calculate_checksums(path: &Utf8PathBuf) -> Result<Vec<FileChecksum>> {
    let mut file = fs::File::open(path).context(format!("Failed to open {}", path))?;
    let mut sha256 = Sha256::new();
    let sha1 = Sha1::new();
    io::copy(&mut file, &mut sha256)?;
    let sha256_hash = sha256.finalize();
    let sha1_hash = sha1.finalize();
    Ok(vec![
        FileChecksum {
            algorithm: Algorithm::Sha1,
            checksum_value: hex::encode(&sha1_hash),
        },
        FileChecksum {
            algorithm: Algorithm::Sha256,
            checksum_value: hex::encode(&sha256_hash),
        },
    ])
}
