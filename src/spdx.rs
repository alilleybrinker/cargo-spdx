//! Defines the SPDX document structure.

#![allow(unused)]

use std::fmt::{Display, Formatter};
use time::{format_description, PrimitiveDateTime};
use url::Url;

/// An SPDX SBOM document.
#[derive(Debug)]
pub struct SpdxDocument {
    /// The version of the SPDX standard.
    pub spdx_version: SpdxVersion,
    /// The license of the SPDX file itself.
    pub data_license: DataLicense,
    /// The identifier for the object the SBOM is referencing.
    pub spdx_identifier: SpdxIdentifier,
    /// The name of the SPDX file itself.
    pub document_name: DocumentName,
    /// A document-specific namespace URI.
    pub document_namespace: DocumentNamespace,
    /// An external name for referring to the SPDX file.
    pub external_document_reference: Option<ExternalDocumentReference>,
    /// The version of the SPDX license list used.
    pub license_list_version: Option<LicenseListVersion>,
    /// The creator of the SPDX file.
    pub creator: Vec<Creator>,
    /// The timestamp for when the SPDX file was created.
    pub created: Created,
    /// Freeform comments about the creator of the SPDX file.
    pub creator_comment: Option<CreatorComment>,
    /// Freeform comments about the SPDX file.
    pub document_comment: Option<DocumentComment>,
}

/// The version of the SPDX standard being used.
#[derive(Debug)]
pub struct SpdxVersion {
    /// The major version.
    pub major: u32,
    /// The minor version.
    pub minor: u32,
}

impl Display for SpdxVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "SPDX-{}.{}", self.major, self.minor)
    }
}

// Only has one representation, so there's no need
// to store anything.
/// The license of the SBOM file itself.
#[derive(Debug)]
pub struct DataLicense;

impl Display for DataLicense {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "CC0-1.0")
    }
}

/// The identifier for the artifact the SBOM is for.
#[derive(Debug)]
pub struct SpdxIdentifier;

impl Display for SpdxIdentifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "SPDXRef-DOCUMENT")
    }
}

/// The name of the SPDX file itself.
#[derive(Debug)]
pub struct DocumentName(pub String);

impl Display for DocumentName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// TODO: Determine how to permit users to specify the document namespace.
//
// Options include:
// - A command line flag
// - An environment variable for the domain root
// - A `Cargo.toml` configuration field under the `extra` section
// - An interactive prompt if left unspecified.

/// A document-specific namespace URI.
///
/// Note that the SPDX 2.2 standard specifies an RFC 3986-compatible
/// URL for this field (with the requirement that the URL _not_ include
/// a fragment identifier.
///
/// Since we're generating an SBOM, rather than consuming them, we can
/// afford to be more restrictive than the SPDX standard. We use the Rust
/// `url` crate here, which follows the WHATWG's URL Living Standard.
/// The URL Living Standard resolves some ambiguities in RFC 3986,
/// and is not strictly compatible with it.
#[derive(Debug)]
pub struct DocumentNamespace(pub Url);

impl Display for DocumentNamespace {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// An external name for referring to the SPDX file.
#[derive(Debug)]
pub struct ExternalDocumentReference {
    /// An ID string made of letters, numbers, '.', '-', and/or '+'.
    id_string: IdString,
    /// The namespace of the document.
    document_uri: DocumentNamespace,
    /// A checksum for the external document reference.
    checksum: Checksum,
}

impl Display for ExternalDocumentReference {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DocumentRef-{} {} {}",
            self.id_string, self.document_uri, self.checksum
        )
    }
}

/// An ID string made of letters, numbers, '.', '-', and/or '+'.
#[derive(Debug)]
pub struct IdString(pub String);

impl Display for IdString {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A checksum for the external document reference.
#[derive(Debug)]
pub struct Checksum(pub String);

impl Display for Checksum {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The version of the SPDX license list used.
#[derive(Debug)]
pub struct LicenseListVersion {
    major: u32,
    minor: u32,
}

impl Display for LicenseListVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// The creator of the SPDX file.
#[derive(Debug)]
pub enum Creator {
    Person { name: String, email: Option<String> },
    Organization { name: String, email: Option<String> },
    Tool { name: String },
}

impl Display for Creator {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Creator::Person {
                name,
                email: Some(email),
            } => write!(f, "Person: {} ({})", name, email),
            Creator::Person { name, email: None } => write!(f, "Person: {}", name),
            Creator::Organization {
                name,
                email: Some(email),
            } => write!(f, "Organization: {} ({})", name, email),
            Creator::Organization { name, email: None } => write!(f, "Organization: {}", name),
            Creator::Tool { name } => write!(f, "{}", name),
        }
    }
}

/// The timestamp indicating when the SPDX file was created.
#[derive(Debug)]
pub struct Created(pub PrimitiveDateTime);

impl Display for Created {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let repr = {
            // PANIC SAFETY: We need to ensure the `PrimitiveDateTime` is never
            // invalid such that this formatting would panic.
            let format_str = "[year]-[month]-[day]T[hour]:[minute]:[second]Z";
            let format = format_description::parse(format_str).unwrap();
            self.0.format(&format).unwrap()
        };

        write!(f, "{}", repr)
    }
}

/// Freeform comment about the creator of the SPDX file.
#[derive(Debug)]
pub struct CreatorComment(pub String);

impl Display for CreatorComment {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Freeform comment about the SPDX file.
#[derive(Debug)]
pub struct DocumentComment(pub String);

impl Display for DocumentComment {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
