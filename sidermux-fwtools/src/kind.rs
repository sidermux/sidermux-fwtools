use std::fmt;

use serde::Serialize;

/// The kind of file an [`crate::inspect`] operation looked at.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize)]
pub enum ImageKind {
    /// An ELF executable — a packaging source, not an unpack target.
    #[serde(rename = "elf")]
    Elf,
    /// One declared boot ROM image.
    #[serde(rename = "bootrom")]
    BootRom,
    /// A multi-slot redundant boot container.
    #[serde(rename = "preloader")]
    Preloader,
    /// A complete MBR disk image with a boot container.
    #[serde(rename = "sd")]
    SdImage,
}

impl fmt::Display for ImageKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Elf => "elf",
            Self::BootRom => "bootrom",
            Self::Preloader => "preloader",
            Self::SdImage => "sd",
        };
        f.write_str(name)
    }
}

/// Whether [`ImageKind`] came from structural detection or an explicit override.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DetectionSource {
    /// Detected structurally from the input bytes.
    Auto,
    /// Forced by an explicit option.
    Override,
}

/// A format the detector considers plausible, together with the reasons why.
#[derive(Clone, Debug)]
pub struct DetectionCandidate {
    /// The plausible format.
    pub kind: ImageKind,
    /// Why the detector considers it plausible.
    pub reasons: Vec<String>,
}

/// Outcome of a named validation check.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    /// The check passed.
    Pass,
    /// The check failed.
    Fail,
    /// The check could not run (e.g. verification was skipped).
    Warn,
}

/// A single named validation result for an inspected image.
#[derive(Clone, Debug, Serialize)]
pub struct Check {
    /// Stable check name (e.g. `"header checksum"`).
    pub name: String,
    /// Outcome of the check.
    pub status: CheckStatus,
    /// Human-readable explanation.
    pub detail: String,
}

/// Integrity state of a boot image's CRC region.
///
/// Distinct from a simple boolean so a structural-only inspection can report
/// "not checked" instead of implying that validation passed.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrcStatus {
    /// The stored CRC matched the computed CRC over the declared image.
    Passed,
    /// The stored CRC did not match.
    Failed,
    /// Integrity verification was not requested.
    NotChecked,
    /// The CRC region could not be read (truncated or malformed image).
    Unreadable,
    /// The extracted data has no boot-image CRC semantics (e.g. an MBR).
    NotApplicable,
}

impl Check {
    pub fn new(name: impl Into<String>, status: CheckStatus, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status,
            detail: detail.into(),
        }
    }

    /// A check that passes or fails outright.
    pub fn binary(name: impl Into<String>, ok: bool, fail_detail: impl Into<String>) -> Self {
        let detail = if ok {
            "ok".to_string()
        } else {
            fail_detail.into()
        };
        Self::new(
            name,
            if ok {
                CheckStatus::Pass
            } else {
                CheckStatus::Fail
            },
            detail,
        )
    }
}
