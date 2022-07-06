//! Defines the SPDX document structure.

use crate::git::get_current_user;
use anyhow::Result;
use cargo_metadata::camino::Utf8PathBuf;
use derive_builder::Builder;
use derive_more::{Display, From};
use serde::{Deserialize, Serialize, Serializer};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::{
    fmt::{Display, Formatter},
    fs, io,
};
use time::{format_description, OffsetDateTime};
use url::Url;

pub const NOASSERTION: &str = "NOASSERTION";

/// Build a new SPDX document based on collected information.
pub fn build(host_url: &str, output_file_name: &str) -> Result<Document> {
    Ok(builder(host_url, output_file_name)?.build()?)
}

/// Build a new SPDX document based on collected information.
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

    /// Packages referenced in the SPDX document
    #[builder(setter(strip_option), default)]
    #[serde(rename = "packages")]
    pub packages: Option<Vec<Package>>,

    /// Files referenced in the SPDX document
    #[serde(rename = "files", skip_serializing_if = "Option::is_none")]
    #[builder(setter(strip_option), default)]
    pub files: Option<Vec<File>>,

    /// Relationships referenced in the SPDX document
    #[serde(rename = "relationships", skip_serializing_if = "Option::is_none")]
    #[builder(setter(strip_option), default)]
    pub relationships: Option<Vec<Relationship>>,
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
            external_refs: if package.source.is_some() {
                Some(vec![ExternalRef {
                    reference_category: ReferenceCategory::PackageManager,
                    reference_type: "purl".to_string(),
                    reference_locator: format!("pkg:cargo/{}@{}", package.name, package.version),
                    comment: None,
                }])
            } else {
                None
            },
            annotations: None,
            attribution_texts: None,
            has_files: None,
            license_comments: None,
            license_info_from_files: None,
            summary: None,
        }
    }
}

/// An Annotation is a comment on an SpdxItem by an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAnnotation {
    /// Identify when the comment was made. This is to be specified according to the combined
    /// date and time in the UTC format, as specified in the ISO 8601 standard.
    #[serde(rename = "annotationDate")]
    pub annotation_date: String,

    /// Type of the annotation.
    #[serde(rename = "annotationType")]
    pub annotation_type: AnnotationType,

    /// This field identifies the person, organization or tool that has commented on a file,
    /// package, or the entire document.
    #[serde(rename = "annotator")]
    pub annotator: String,

    #[serde(rename = "comment")]
    pub comment: String,
}

/// A Checksum is value that allows the contents of a file to be authenticated. Even small
/// changes to the content of the file will change its checksum. This class allows the
/// results of a variety of checksum and cryptographic message digest algorithms to be
/// represented.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChecksum {
    /// Identifies the algorithm used to produce the subject Checksum. Currently, SHA-1 is the
    /// only supported algorithm. It is anticipated that other algorithms will be supported at a
    /// later time.
    #[serde(rename = "algorithm")]
    pub algorithm: Algorithm,

    /// The checksumValue property provides a lower case hexidecimal encoded digest value
    /// produced using a specific algorithm.
    #[serde(rename = "checksumValue")]
    pub checksum_value: String,
}

/// An ExtractedLicensingInfo represents a license or licensing notice that was found in the
/// package. Any license text that is recognized as a license may be represented as a License
/// rather than an ExtractedLicensingInfo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HasExtractedLicensingInfo {
    #[serde(rename = "comment", skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    /// Cross Reference Detail for a license SeeAlso URL
    #[serde(rename = "crossRefs", skip_serializing_if = "Option::is_none")]
    pub cross_refs: Option<Vec<CrossRef>>,

    /// Verbatim license or licensing notice text that was discovered.
    #[serde(rename = "extractedText")]
    pub extracted_text: String,

    /// A human readable short form license identifier for a license. The license ID is iether on
    /// the standard license oist or the form "LicenseRef-"[idString] where [idString] is a
    /// unique string containing letters, numbers, ".", "-" or "+".
    #[serde(rename = "licenseId")]
    pub license_id: String,

    /// Identify name of this SpdxElement.
    #[serde(rename = "name", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(rename = "seeAlsos", skip_serializing_if = "Option::is_none")]
    pub see_alsos: Option<Vec<String>>,
}

/// Cross reference details for the a URL reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossRef {
    /// Indicate a URL is still a live accessible location on the public internet
    #[serde(rename = "isLive", skip_serializing_if = "Option::is_none")]
    pub is_live: Option<bool>,

    /// True if the URL is a valid well formed URL
    #[serde(rename = "isValid", skip_serializing_if = "Option::is_none")]
    pub is_valid: Option<bool>,

    /// True if the License SeeAlso URL points to a Wayback archive
    #[serde(rename = "isWayBackLink", skip_serializing_if = "Option::is_none")]
    pub is_way_back_link: Option<bool>,

    /// Status of a License List SeeAlso URL reference if it refers to a website that matches the
    /// license text.
    #[serde(rename = "match", skip_serializing_if = "Option::is_none")]
    pub cross_ref_match: Option<String>,

    /// The ordinal order of this element within a list
    #[serde(rename = "order", skip_serializing_if = "Option::is_none")]
    pub order: Option<i64>,

    /// Timestamp
    #[serde(rename = "timestamp", skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,

    /// URL Reference
    #[serde(rename = "url")]
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    /// Provide additional information about an SpdxElement.
    #[serde(rename = "annotations", skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Vec<PackageAnnotation>>,

    /// This field provides a place for the SPDX data creator to record acknowledgements that may
    /// be required to be communicated in some contexts. This is not meant to include theactual
    /// complete license text (see licenseConculded and licenseDeclared), and may or may not
    /// include copyright notices (see also copyrightText). The SPDX data creator may use this
    /// field to record other acknowledgements, such as particular clauses from license texts,
    /// which may be necessary or desirable to reproduce.
    #[serde(rename = "attributionTexts", skip_serializing_if = "Option::is_none")]
    pub attribution_texts: Option<Vec<String>>,

    /// The checksum property provides a mechanism that can be used to verify that the contents
    /// of a File or Package have not changed.
    #[serde(rename = "checksums", skip_serializing_if = "Option::is_none")]
    pub checksums: Option<Vec<PackageChecksum>>,

    #[serde(rename = "comment", skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    /// The text of copyright declarations recited in the Package or File.
    #[serde(rename = "copyrightText")]
    pub copyright_text: String,

    /// Provides a detailed description of the package.
    #[serde(rename = "description", skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// The URI at which this package is available for download. Private (i.e., not publicly
    /// reachable) URIs are acceptable as values of this property. The values
    /// http://spdx.org/rdf/terms#none and http://spdx.org/rdf/terms#noassertion may be used to
    /// specify that the package is not downloadable or that no attempt was made to determine its
    /// download location, respectively.
    #[serde(rename = "downloadLocation")]
    pub download_location: String,

    /// An External Reference allows a Package to reference an external source of additional
    /// information, metadata, enumerations, asset identifiers, or downloadable content believed
    /// to be relevant to the Package.
    #[serde(rename = "externalRefs", skip_serializing_if = "Option::is_none")]
    pub external_refs: Option<Vec<ExternalRef>>,

    /// Indicates whether the file content of this package has been available for or subjected to
    /// analysis when creating the SPDX document. If false indicates packages that represent
    /// metadata or URI references to a project, product, artifact, distribution or a component.
    /// If set to false, the package must not contain any files.
    #[serde(rename = "filesAnalyzed", skip_serializing_if = "Option::is_none")]
    pub files_analyzed: Option<bool>,

    /// Indicates that a particular file belongs to a package.
    #[serde(rename = "hasFiles", skip_serializing_if = "Option::is_none")]
    pub has_files: Option<Vec<String>>,

    #[serde(rename = "homepage", skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,

    /// The licenseComments property allows the preparer of the SPDX document to describe why the
    /// licensing in spdx:licenseConcluded was chosen.
    #[serde(rename = "licenseComments", skip_serializing_if = "Option::is_none")]
    pub license_comments: Option<String>,

    /// License expression for licenseConcluded.  The licensing that the preparer of this SPDX
    /// document has concluded, based on the evidence, actually applies to the package.
    #[serde(rename = "licenseConcluded")]
    pub license_concluded: String,

    /// License expression for licenseDeclared.  The licensing that the creators of the software
    /// in the package, or the packager, have declared. Declarations by the original software
    /// creator should be preferred, if they exist.
    #[serde(rename = "licenseDeclared")]
    pub license_declared: String,

    /// The licensing information that was discovered directly within the package. There will be
    /// an instance of this property for each distinct value of alllicenseInfoInFile properties
    /// of all files contained in the package.
    #[serde(
        rename = "licenseInfoFromFiles",
        skip_serializing_if = "Option::is_none"
    )]
    pub license_info_from_files: Option<Vec<String>>,

    /// Identify name of this SpdxElement.
    #[serde(rename = "name")]
    pub name: String,

    /// The name and, optionally, contact information of the person or organization that
    /// originally created the package. Values of this property must conform to the agent and
    /// tool syntax.
    #[serde(rename = "originator", skip_serializing_if = "Option::is_none")]
    pub originator: Option<String>,

    /// The base name of the package file name. For example, zlib-1.2.5.tar.gz.
    #[serde(rename = "packageFileName", skip_serializing_if = "Option::is_none")]
    pub package_file_name: Option<String>,

    /// A manifest based verification code (the algorithm is defined in section 4.7 of the full
    /// specification) of the SPDX Item. This allows consumers of this data and/or database to
    /// determine if an SPDX item they have in hand is identical to the SPDX item from which the
    /// data was produced. This algorithm works even if the SPDX document is included in the SPDX
    /// item.
    #[serde(
        rename = "packageVerificationCode",
        skip_serializing_if = "Option::is_none"
    )]
    pub package_verification_code: Option<PackageVerificationCode>,

    /// Allows the producer(s) of the SPDX document to describe how the package was acquired
    /// and/or changed from the original source.
    #[serde(rename = "sourceInfo", skip_serializing_if = "Option::is_none")]
    pub source_info: Option<String>,

    /// Uniquely identify any element in an SPDX document which may be referenced by other
    /// elements.
    #[serde(rename = "SPDXID")]
    pub spdxid: String,

    /// Provides a short description of the package.
    #[serde(rename = "summary", skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,

    /// The name and, optionally, contact information of the person or organization who was the
    /// immediate supplier of this package to the recipient. The supplier may be different than
    /// originator when the software has been repackaged. Values of this property must conform to
    /// the agent and tool syntax.
    #[serde(rename = "supplier", skip_serializing_if = "Option::is_none")]
    pub supplier: Option<String>,

    /// Provides an indication of the version of the package that is described by this
    /// SpdxDocument.
    #[serde(rename = "versionInfo", skip_serializing_if = "Option::is_none")]
    pub version_info: Option<String>,
}

/// An Annotation is a comment on an SpdxItem by an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageAnnotation {
    /// Identify when the comment was made. This is to be specified according to the combined
    /// date and time in the UTC format, as specified in the ISO 8601 standard.
    #[serde(rename = "annotationDate")]
    pub annotation_date: String,

    /// Type of the annotation.
    #[serde(rename = "annotationType")]
    pub annotation_type: AnnotationType,

    /// This field identifies the person, organization or tool that has commented on a file,
    /// package, or the entire document.
    #[serde(rename = "annotator")]
    pub annotator: String,

    #[serde(rename = "comment")]
    pub comment: String,
}

/// A Checksum is value that allows the contents of a file to be authenticated. Even small
/// changes to the content of the file will change its checksum. This class allows the
/// results of a variety of checksum and cryptographic message digest algorithms to be
/// represented.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageChecksum {
    /// Identifies the algorithm used to produce the subject Checksum. Currently, SHA-1 is the
    /// only supported algorithm. It is anticipated that other algorithms will be supported at a
    /// later time.
    #[serde(rename = "algorithm")]
    pub algorithm: Algorithm,

    /// The checksumValue property provides a lower case hexidecimal encoded digest value
    /// produced using a specific algorithm.
    #[serde(rename = "checksumValue")]
    pub checksum_value: String,
}

/// An External Reference allows a Package to reference an external source of additional
/// information, metadata, enumerations, asset identifiers, or downloadable content believed
/// to be relevant to the Package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalRef {
    #[serde(rename = "comment", skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    /// Category for the external reference
    #[serde(rename = "referenceCategory")]
    pub reference_category: ReferenceCategory,

    /// The unique string with no spaces necessary to access the package-specific information,
    /// metadata, or content within the target location. The format of the locator is subject to
    /// constraints defined by the <type>.
    #[serde(rename = "referenceLocator")]
    pub reference_locator: String,

    /// Type of the external reference. These are definined in an appendix in the SPDX
    /// specification.
    #[serde(rename = "referenceType")]
    pub reference_type: String,
}

/// A manifest based verification code (the algorithm is defined in section 4.7 of the full
/// specification) of the SPDX Item. This allows consumers of this data and/or database to
/// determine if an SPDX item they have in hand is identical to the SPDX item from which the
/// data was produced. This algorithm works even if the SPDX document is included in the SPDX
/// item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageVerificationCode {
    /// A file that was excluded when calculating the package verification code. This is usually
    /// a file containing SPDX data regarding the package. If a package contains more than one
    /// SPDX file all SPDX files must be excluded from the package verification code. If this is
    /// not done it would be impossible to correctly calculate the verification codes in both
    /// files.
    #[serde(
        rename = "packageVerificationCodeExcludedFiles",
        skip_serializing_if = "Option::is_none"
    )]
    pub package_verification_code_excluded_files: Option<Vec<String>>,

    /// The actual package verification code as a hex encoded value.
    #[serde(rename = "packageVerificationCodeValue")]
    pub package_verification_code_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relationship {
    #[serde(rename = "comment", skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    /// SPDX ID for SpdxElement.  A related SpdxElement.
    #[serde(rename = "relatedSpdxElement")]
    pub related_spdx_element: String,

    /// Describes the type of relationship between two SPDX elements.
    #[serde(rename = "relationshipType")]
    pub relationship_type: RelationshipType,

    /// Id to which the SPDX element is related
    #[serde(rename = "spdxElementId")]
    pub spdx_element_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reviewed {
    #[serde(rename = "comment", skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    /// The date and time at which the SpdxDocument was reviewed. This value must be in UTC and
    /// have 'Z' as its timezone indicator.
    #[serde(rename = "reviewDate")]
    pub review_date: String,

    /// The name and, optionally, contact information of the person who performed the review.
    /// Values of this property must conform to the agent and tool syntax.
    #[serde(rename = "reviewer", skip_serializing_if = "Option::is_none")]
    pub reviewer: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snippet {
    /// Provide additional information about an SpdxElement.
    #[serde(rename = "annotations", skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Vec<SnippetAnnotation>>,

    /// This field provides a place for the SPDX data creator to record acknowledgements that may
    /// be required to be communicated in some contexts. This is not meant to include theactual
    /// complete license text (see licenseConculded and licenseDeclared), and may or may not
    /// include copyright notices (see also copyrightText). The SPDX data creator may use this
    /// field to record other acknowledgements, such as particular clauses from license texts,
    /// which may be necessary or desirable to reproduce.
    #[serde(rename = "attributionTexts", skip_serializing_if = "Option::is_none")]
    pub attribution_texts: Option<Vec<String>>,

    #[serde(rename = "comment", skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    /// The text of copyright declarations recited in the Package or File.
    #[serde(rename = "copyrightText")]
    pub copyright_text: String,

    /// The licenseComments property allows the preparer of the SPDX document to describe why the
    /// licensing in spdx:licenseConcluded was chosen.
    #[serde(rename = "licenseComments", skip_serializing_if = "Option::is_none")]
    pub license_comments: Option<String>,

    /// License expression for licenseConcluded.  The licensing that the preparer of this SPDX
    /// document has concluded, based on the evidence, actually applies to the package.
    #[serde(rename = "licenseConcluded")]
    pub license_concluded: String,

    /// Licensing information that was discovered directly in the subject snippet. This is also
    /// considered a declared license for the snippet.
    #[serde(
        rename = "licenseInfoInSnippets",
        skip_serializing_if = "Option::is_none"
    )]
    pub license_info_in_snippets: Option<Vec<String>>,

    /// Identify name of this SpdxElement.
    #[serde(rename = "name")]
    pub name: String,

    /// This field defines the byte range in the original host file (in X.2) that the snippet
    /// information applies to
    #[serde(rename = "ranges", skip_serializing_if = "Option::is_none")]
    pub ranges: Option<Vec<Range>>,

    /// SPDX ID for File.  File containing the SPDX element (e.g. the file contaning a snippet).
    #[serde(rename = "snippetFromFile")]
    pub snippet_from_file: String,

    /// Uniquely identify any element in an SPDX document which may be referenced by other
    /// elements.
    #[serde(rename = "SPDXID")]
    pub spdxid: String,
}

/// An Annotation is a comment on an SpdxItem by an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnippetAnnotation {
    /// Identify when the comment was made. This is to be specified according to the combined
    /// date and time in the UTC format, as specified in the ISO 8601 standard.
    #[serde(rename = "annotationDate")]
    pub annotation_date: String,

    /// Type of the annotation.
    #[serde(rename = "annotationType")]
    pub annotation_type: AnnotationType,

    /// This field identifies the person, organization or tool that has commented on a file,
    /// package, or the entire document.
    #[serde(rename = "annotator")]
    pub annotator: String,

    #[serde(rename = "comment")]
    pub comment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Range {
    #[serde(rename = "endPointer")]
    pub end_pointer: EndPointer,

    #[serde(rename = "startPointer")]
    pub start_pointer: StartPointer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndPointer {
    /// line number offset in the file
    #[serde(rename = "lineNumber", skip_serializing_if = "Option::is_none")]
    pub line_number: Option<i64>,

    /// Byte offset in the file
    #[serde(rename = "offset", skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,

    /// SPDX ID for File
    #[serde(rename = "reference")]
    pub reference: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartPointer {
    /// line number offset in the file
    #[serde(rename = "lineNumber", skip_serializing_if = "Option::is_none")]
    pub line_number: Option<i64>,

    /// Byte offset in the file
    #[serde(rename = "offset", skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,

    /// SPDX ID for File
    #[serde(rename = "reference")]
    pub reference: String,
}

/// Type of the annotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnnotationType {
    #[serde(rename = "OTHER")]
    Other,

    #[serde(rename = "REVIEW")]
    Review,
}

/// Identifies the algorithm used to produce the subject Checksum. Currently, SHA-1 is the
/// only supported algorithm. It is anticipated that other algorithms will be supported at a
/// later time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Algorithm {
    #[serde(rename = "MD2")]
    Md2,

    #[serde(rename = "MD4")]
    Md4,

    #[serde(rename = "MD5")]
    Md5,

    #[serde(rename = "MD6")]
    Md6,

    #[serde(rename = "SHA1")]
    Sha1,

    #[serde(rename = "SHA224")]
    Sha224,

    #[serde(rename = "SHA256")]
    Sha256,

    #[serde(rename = "SHA384")]
    Sha384,

    #[serde(rename = "SHA512")]
    Sha512,
}

/// The type of the file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileType {
    #[serde(rename = "APPLICATION")]
    Application,

    #[serde(rename = "ARCHIVE")]
    Archive,

    #[serde(rename = "AUDIO")]
    Audio,

    #[serde(rename = "BINARY")]
    Binary,

    #[serde(rename = "DOCUMENTATION")]
    Documentation,

    #[serde(rename = "IMAGE")]
    Image,

    #[serde(rename = "OTHER")]
    Other,

    #[serde(rename = "SOURCE")]
    Source,

    #[serde(rename = "SPDX")]
    Spdx,

    #[serde(rename = "TEXT")]
    Text,

    #[serde(rename = "VIDEO")]
    Video,
}

/// Category for the external reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReferenceCategory {
    #[serde(rename = "OTHER")]
    Other,

    #[serde(rename = "PACKAGE_MANAGER")]
    PackageManager,

    #[serde(rename = "SECURITY")]
    Security,
}

/// Describes the type of relationship between two SPDX elements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RelationshipType {
    #[serde(rename = "ANCESTOR_OF")]
    AncestorOf,

    #[serde(rename = "BUILD_DEPENDENCY_OF")]
    BuildDependencyOf,

    #[serde(rename = "BUILD_TOOL_OF")]
    BuildToolOf,

    #[serde(rename = "CONTAINED_BY")]
    ContainedBy,

    #[serde(rename = "CONTAINS")]
    Contains,

    #[serde(rename = "COPY_OF")]
    CopyOf,

    #[serde(rename = "DATA_FILE_OF")]
    DataFileOf,

    #[serde(rename = "DEPENDENCY_MANIFEST_OF")]
    DependencyManifestOf,

    #[serde(rename = "DEPENDENCY_OF")]
    DependencyOf,

    #[serde(rename = "DEPENDS_ON")]
    DependsOn,

    #[serde(rename = "DESCENDANT_OF")]
    DescendantOf,

    #[serde(rename = "DESCRIBED_BY")]
    DescribedBy,

    #[serde(rename = "DESCRIBES")]
    Describes,

    #[serde(rename = "DEV_DEPENDENCY_OF")]
    DevDependencyOf,

    #[serde(rename = "DEV_TOOL_OF")]
    DevToolOf,

    #[serde(rename = "DISTRIBUTION_ARTIFACT")]
    DistributionArtifact,

    #[serde(rename = "DOCUMENTATION_OF")]
    DocumentationOf,

    #[serde(rename = "DYNAMIC_LINK")]
    DynamicLink,

    #[serde(rename = "EXAMPLE_OF")]
    ExampleOf,

    #[serde(rename = "EXPANDED_FROM_ARCHIVE")]
    ExpandedFromArchive,

    #[serde(rename = "FILE_ADDED")]
    FileAdded,

    #[serde(rename = "FILE_DELETED")]
    FileDeleted,

    #[serde(rename = "FILE_MODIFIED")]
    FileModified,

    #[serde(rename = "GENERATED_FROM")]
    GeneratedFrom,

    #[serde(rename = "GENERATES")]
    Generates,

    #[serde(rename = "HAS_PREREQUISITE")]
    HasPrerequisite,

    #[serde(rename = "METAFILE_OF")]
    MetafileOf,

    #[serde(rename = "OPTIONAL_COMPONENT_OF")]
    OptionalComponentOf,

    #[serde(rename = "OPTIONAL_DEPENDENCY_OF")]
    OptionalDependencyOf,

    #[serde(rename = "OTHER")]
    Other,

    #[serde(rename = "PACKAGE_OF")]
    PackageOf,

    #[serde(rename = "PATCH_APPLIED")]
    PatchApplied,

    #[serde(rename = "PATCH_FOR")]
    PatchFor,

    #[serde(rename = "PREREQUISITE_FOR")]
    PrerequisiteFor,

    #[serde(rename = "PROVIDED_DEPENDENCY_OF")]
    ProvidedDependencyOf,

    #[serde(rename = "RUNTIME_DEPENDENCY_OF")]
    RuntimeDependencyOf,

    #[serde(rename = "STATIC_LINK")]
    StaticLink,

    #[serde(rename = "TEST_CASE_OF")]
    TestCaseOf,

    #[serde(rename = "TEST_DEPENDENCY_OF")]
    TestDependencyOf,

    #[serde(rename = "TEST_OF")]
    TestOf,

    #[serde(rename = "TEST_TOOL_OF")]
    TestToolOf,

    #[serde(rename = "VARIANT_OF")]
    VariantOf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct File {
    /// Provide additional information about an SpdxElement.
    #[serde(rename = "annotations", skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Vec<FileAnnotation>>,

    /// This field provides a place for the SPDX data creator to record acknowledgements that may
    /// be required to be communicated in some contexts. This is not meant to include theactual
    /// complete license text (see licenseConculded and licenseDeclared), and may or may not
    /// include copyright notices (see also copyrightText). The SPDX data creator may use this
    /// field to record other acknowledgements, such as particular clauses from license texts,
    /// which may be necessary or desirable to reproduce.
    #[serde(rename = "attributionTexts", skip_serializing_if = "Option::is_none")]
    pub attribution_texts: Option<Vec<String>>,

    /// The checksum property provides a mechanism that can be used to verify that the contents
    /// of a File or Package have not changed.
    #[serde(rename = "checksums", skip_serializing_if = "Option::is_none")]
    pub checksums: Option<Vec<FileChecksum>>,

    #[serde(rename = "comment", skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    /// The text of copyright declarations recited in the Package or File.
    #[serde(rename = "copyrightText")]
    pub copyright_text: String,

    /// This field provides a place for the SPDX file creator to record file contributors.
    /// Contributors could include names of copyright holders and/or authors who may not be
    /// copyright holders yet contributed to the file content.
    #[serde(rename = "fileContributors", skip_serializing_if = "Option::is_none")]
    pub file_contributors: Option<Vec<String>>,

    #[serde(rename = "fileDependencies", skip_serializing_if = "Option::is_none")]
    pub file_dependencies: Option<Vec<String>>,

    /// The name of the file relative to the root of the package.
    #[serde(rename = "fileName")]
    pub file_name: String,

    /// The type of the file.
    #[serde(rename = "fileTypes", skip_serializing_if = "Option::is_none")]
    pub file_types: Option<Vec<FileType>>,

    /// The licenseComments property allows the preparer of the SPDX document to describe why the
    /// licensing in spdx:licenseConcluded was chosen.
    #[serde(rename = "licenseComments", skip_serializing_if = "Option::is_none")]
    pub license_comments: Option<String>,

    /// License expression for licenseConcluded.  The licensing that the preparer of this SPDX
    /// document has concluded, based on the evidence, actually applies to the package.
    #[serde(rename = "licenseConcluded")]
    pub license_concluded: String,

    /// Licensing information that was discovered directly in the subject file. This is also
    /// considered a declared license for the file.
    #[serde(rename = "licenseInfoInFiles", skip_serializing_if = "Option::is_none")]
    pub license_info_in_files: Option<Vec<String>>,

    /// This field provides a place for the SPDX file creator to record potential legal notices
    /// found in the file. This may or may not include copyright statements.
    #[serde(rename = "noticeText", skip_serializing_if = "Option::is_none")]
    pub notice_text: Option<String>,

    /// Uniquely identify any element in an SPDX document which may be referenced by other
    /// elements.
    #[serde(rename = "SPDXID")]
    pub spdxid: String,
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
    let mut file = fs::File::open(path)?;
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
