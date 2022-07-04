//! Defines the SPDX document structure.

use crate::git::get_current_user;
use anyhow::Result;
use derive_builder::Builder;
use derive_more::{Display, From};
use serde::{Serialize, Serializer};
use std::fmt::{Display, Formatter};
use time::{format_description, OffsetDateTime};
use url::Url;

/// Build a new SPDX document based on collected information.
pub fn build(host_url: &str, output_file_name: &str) -> Result<Document> {
    log::info!(target: "cargo_spdx", "building the document");

    // Construct the document.
    Ok(DocumentBuilder::default()
        .document_name(output_file_name)
        .try_document_namespace(host_url)?
        .creation_info(get_creation_info()?)
        .build()?)
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

/// An SPDX SBOM document.
#[derive(Debug, Clone, Builder, Serialize)]
pub struct Document {
    /// The version of the SPD standard.
    #[builder(setter(into))]
    #[builder(default)]
    #[serde(rename = "spdxVersion")]
    pub spdx_version: SpdxVersion,

    /// The license of the SPDX file itself.
    #[builder(default)]
    #[builder(setter(skip))]
    #[serde(rename = "dataLicense")]
    pub data_license: DataLicense,

    /// The identifier for the object the SBOM is referencing.
    #[builder(default)]
    #[builder(setter(skip))]
    #[serde(rename = "SPDXID")]
    pub spdx_identifier: SpdxIdentifier,

    /// The name of the SPDX file itself.
    #[builder(setter(into))]
    #[serde(rename = "name")]
    pub document_name: DocumentName,

    /// A document-specific namespace URI.
    /// Note that the SPDX 2.2 standard specifies an RFC 3986-compatible
    /// URL for this field (with the requirement that the URL _not_ include
    /// a fragment identifier.
    ///
    /// Since we're generating an SBOM, rather than consuming them, we can
    /// afford to be more restrictive than the SPDX standard. We use the Rust
    /// `url` crate here, which follows the WHATWG's URL Living Standard.
    /// The URL Living Standard resolves some ambiguities in RFC 3986,
    /// and is not strictly compatible with it.
    #[builder(try_setter, setter(into))]
    #[serde(rename = "documentNamespace")]
    pub document_namespace: Url,

    /// An external name for referring to the SPDX file.
    #[builder(setter(strip_option))]
    #[builder(default)]
    #[serde(
        rename = "externalDocumentRefs",
        skip_serializing_if = "Option::is_none"
    )]
    pub external_document_reference: Option<ExternalDocumentReference>,

    /// Freeform comments about the SPDX file.
    #[builder(setter(strip_option))]
    #[builder(default)]
    #[serde(rename = "comment", skip_serializing_if = "Option::is_none")]
    pub document_comment: Option<String>,

    /// One instance is required for each SPDX file produced. It provides the necessary
    /// information for forward and backward compatibility for processing tools.
    #[serde(rename = "creationInfo")]
    pub creation_info: CreationInfo,
}

/// One instance is required for each SPDX file produced. It provides the necessary
/// information for forward and backward compatibility for processing tools.
#[derive(Debug, Clone, Builder, Serialize)]
pub struct CreationInfo {
    /// Freeform comments about the creator of the SPDX file.
    #[builder(setter(strip_option), default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Identify when the SPDX file was originally created. The date is to be specified according
    /// to combined date and time in UTC format as specified in ISO 8601 standard. This field is
    /// distinct from the fields in section 8, which involves the addition of information during
    /// a subsequent review.
    #[builder(default)]
    pub created: Created,
    /// Identify who (or what, in the case of a tool) created the SPDX file. If the SPDX file was
    /// created by an individual, indicate the person's name. If the SPDX file was created on
    /// behalf of a company or organization, indicate the entity name. If the SPDX file was
    /// created using a software tool, indicate the name and version for that tool. If multiple
    /// participants or tools were involved, use multiple instances of this field. Person name or
    /// organization name may be designated as “anonymous” if appropriate.
    #[builder(setter(strip_option))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creators: Option<Vec<Creator>>,
    /// An optional field for creators of the SPDX file to provide the version of the SPDX
    /// License List used when the SPDX file was created.
    #[serde(rename = "licenseListVersion", skip_serializing_if = "Option::is_none")]
    #[builder(setter(strip_option), default)]
    pub license_list_version: Option<LicenseListVersion>,
}

/// The version of the SPDX standard being used.
#[derive(Debug, Display, Clone, From)]
#[display(fmt = "SPDX-{}.{}", major, minor)]
pub struct SpdxVersion {
    /// The major version.
    pub major: u32,
    /// The minor version.
    pub minor: u32,
}

impl Default for SpdxVersion {
    fn default() -> Self {
        SpdxVersion { major: 2, minor: 2 }
    }
}

// Only has one representation, so there's no need
// to store anything.
/// The license of the SBOM file itself.
#[derive(Debug, Display, Clone, Default)]
#[display(fmt = "CC0-1.0")]
pub struct DataLicense;

/// The identifier for the artifact the SBOM is for.
#[derive(Debug, Display, Clone, Default)]
#[display(fmt = "SPDXRef-DOCUMENT")]
pub struct SpdxIdentifier;

/// The name of the SPDX file itself.
#[derive(Debug, Display, Clone, From, Serialize)]
pub struct DocumentName(pub String);

impl<'s> From<&'s str> for DocumentName {
    fn from(string: &'s str) -> Self {
        DocumentName(String::from(string))
    }
}
/// An external name for referring to the SPDX file.
#[derive(Debug, Display, Clone, Serialize)]
#[display(fmt = "DocumentRef-{} {} {}", id_string, document_uri, checksum)]
pub struct ExternalDocumentReference {
    /// An ID string made of letters, numbers, '.', '-', and/or '+'.
    id_string: IdString,
    /// The namespace of the document.
    document_uri: Url,
    /// A checksum for the external document reference.
    checksum: Checksum,
}

/// An ID string made of letters, numbers, '.', '-', and/or '+'.
#[derive(Debug, Display, Clone, From, Serialize)]
pub struct IdString(pub String);

/// A checksum for the external document reference.
#[derive(Debug, Display, Clone, From, Serialize)]
pub struct Checksum(pub String);

/// The version of the SPDX license list used.
#[derive(Debug, Display, Clone)]
#[display(fmt = "{}.{}", major, minor)]
pub struct LicenseListVersion {
    major: u32,
    minor: u32,
}

/// The creator of the SPDX file.
#[derive(Debug, Clone)]
pub enum Creator {
    #[allow(unused)]
    Person {
        name: String,
        email: Option<String>,
    },
    #[allow(unused)]
    Organization {
        name: String,
        email: Option<String>,
    },
    Tool {
        name: String,
    },
}

impl Creator {
    /// Construct a new `Creator::Person`.
    pub fn person(name: String, email: Option<String>) -> Self {
        Creator::Person { name, email }
    }

    /// Construct a new `Creator::Tool`.
    pub fn tool(s: &str) -> Self {
        Creator::Tool {
            name: String::from(s),
        }
    }
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
            Creator::Tool { name } => write!(f, "Tool: {}", name),
        }
    }
}

/// The timestamp indicating when the SPDX file was created.
#[derive(Debug, Clone, From)]

pub struct Created(pub OffsetDateTime);

impl Default for Created {
    fn default() -> Self {
        Created(OffsetDateTime::now_utc())
    }
}

// Make serde use the Display implementation for types with a custom
// display implementation
macro_rules! string_serialize {
    ($($ty:ty),*) => {
        $(impl Serialize for $ty { fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer { serializer.collect_str(&self) }})*
    };
}

string_serialize! {
  Created, Creator, LicenseListVersion, DataLicense, SpdxVersion, SpdxIdentifier
}

impl Display for Created {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let repr = {
            // PANIC SAFETY: We need to ensure the `OffsetDateTime` is never
            // invalid such that this formatting would panic.
            let format_str = "[year]-[month]-[day]T[hour]:[minute]:[second]Z";
            let format = format_description::parse(format_str).unwrap();
            self.0.format(&format).unwrap()
        };

        write!(f, "{}", repr)
    }
}
