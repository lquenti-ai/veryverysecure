use std::fmt;

use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

use crate::DbError;

const NAME_MAX_BYTES: usize = 255;

fn validate_name(s: &str) -> Result<String, &'static str> {
    let normalized: String = s.nfc().collect();
    if normalized.is_empty() {
        return Err("empty");
    }
    if normalized.len() > NAME_MAX_BYTES {
        return Err("too long");
    }
    if normalized.chars().any(|c| c.is_control()) {
        return Err("contains control characters");
    }
    Ok(normalized)
}

/// A username. NFC-normalized at construction.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Username(String);

impl Username {
    /// Validate, NFC-normalize, and construct a `Username`.
    pub fn new<S: AsRef<str>>(s: S) -> Result<Self, DbError> {
        validate_name(s.as_ref())
            .map(Self)
            .map_err(DbError::InvalidUsername)
    }

    /// Borrow the canonical string form (suitable for SQL binding).
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Username {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A project name. NFC-normalized at construction.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Projectname(String);

impl Projectname {
    /// Validate, NFC-normalize, and construct a `Projectname`.
    pub fn new<S: AsRef<str>>(s: S) -> Result<Self, DbError> {
        validate_name(s.as_ref())
            .map(Self)
            .map_err(DbError::InvalidProjectname)
    }

    /// Borrow the canonical string form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Projectname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Server-generated identifier for a key (UUIDv4).
///
/// Client-supplied IDs are rejected at the API layer; [`KeyId::new`] is the
/// only way to mint a fresh one. [`KeyId::parse`] is used on inbound API
/// paths and when decoding DB rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeyId(Uuid);

impl KeyId {
    /// Generate a new random KeyId.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Parse from a hyphenated UUID string.
    pub fn parse(s: &str) -> Result<Self, DbError> {
        Ok(Self(Uuid::parse_str(s)?))
    }

    /// Return the underlying UUID.
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }

    /// Canonical hyphenated string form, used for SQL binding.
    pub fn hyphenated(&self) -> String {
        self.0.hyphenated().to_string()
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.hyphenated())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_trims_nothing_but_normalizes_to_nfc() {
        // "é" as NFD (e + combining acute) should round-trip to NFC.
        let nfd = "e\u{0301}ve";
        let u = Username::new(nfd).unwrap();
        assert_eq!(u.as_str(), "\u{00e9}ve");
    }

    #[test]
    fn username_rejects_empty() {
        assert!(matches!(
            Username::new("").unwrap_err(),
            DbError::InvalidUsername(_)
        ));
    }

    #[test]
    fn username_rejects_control_chars() {
        assert!(matches!(
            Username::new("bad\x00name").unwrap_err(),
            DbError::InvalidUsername(_)
        ));
        assert!(matches!(
            Username::new("tab\there").unwrap_err(),
            DbError::InvalidUsername(_)
        ));
    }

    #[test]
    fn projectname_rejects_empty() {
        assert!(matches!(
            Projectname::new("").unwrap_err(),
            DbError::InvalidProjectname(_)
        ));
    }

    #[test]
    fn keyid_new_returns_distinct_values() {
        let a = KeyId::new();
        let b = KeyId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn keyid_parse_round_trip() {
        let a = KeyId::new();
        let s = a.hyphenated();
        let b = KeyId::parse(&s).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn keyid_parse_rejects_garbage() {
        assert!(matches!(
            KeyId::parse("not-a-uuid").unwrap_err(),
            DbError::InvalidKeyId(_)
        ));
    }
}
