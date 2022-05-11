#![allow(unused)]

/// An SPDX SBOM document.
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
pub struct SpdxVersion {
    /// The major version.
    pub major: u32,
    /// The minor version.
    pub minor: u32,
}

// Only has one representation, so there's no need
// to store anything.
/// The license of the SBOM file itself.
pub struct DataLicense;

/// The identifier for the artifact the SBOM is for.
pub struct SpdxIdentifier(pub String);

/// The name of the SPDX file itself.
pub struct DocumentName(pub String);

/// A document-specific namespace URI.
pub struct DocumentNamespace(pub String);

/// An external name for referring to the SPDX file.
pub struct ExternalDocumentReference(pub String);

/// The version of the SPDX license list used.
pub struct LicenseListVersion(pub String);

/// The creator of the SPDX file.
pub enum Creator {
    Person { name: String, email: Option<String> },
    Organization { name: String, email: Option<String> },
    Tool { name: String },
}

/// The timestamp indicating when the SPDX file was created.
pub struct Created(pub String);

/// Freeform comment about the creator of the SPDX file.
pub struct CreatorComment(pub String);

/// Freeform comment about the SPDX file.
pub struct DocumentComment(pub String);
