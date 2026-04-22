use thiserror::Error;

/// Errors returned by the `db` crate.
///
/// Callers should match on these variants for flow control; `Sqlx` and
/// `Migrate` are opaque pass-throughs for the remaining failures.
#[derive(Debug, Error)]
pub enum DbError {
    /// A primary-key or unique-index constraint would have been violated.
    #[error("record already exists")]
    AlreadyExists,
    /// The row the caller named does not exist.
    #[error("record not found")]
    NotFound,
    /// The caller holds a Permission row but it is not the owner row.
    #[error("caller is not the owner of this key")]
    NotOwner,
    /// Ownership transfer target has no Permission row to promote.
    #[error("recipient does not have a Permission row for this key")]
    MissingRecipientRow,
    /// Username failed validation at construction time.
    #[error("invalid username: {0}")]
    InvalidUsername(&'static str),
    /// Projectname failed validation at construction time.
    #[error("invalid project name: {0}")]
    InvalidProjectname(&'static str),
    /// A stored or supplied KeyId could not be parsed as a UUID.
    #[error("invalid KeyId: {0}")]
    InvalidKeyId(#[from] uuid::Error),
    /// Pass-through for unexpected sqlx failures.
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    /// Pass-through for migration errors.
    #[error(transparent)]
    Migrate(#[from] sqlx::migrate::MigrateError),
}
