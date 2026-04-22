//! Database layer for veryverysecure.
//!
//! Typed CRUD over the SQLite schema in `migrations/`. BLOB columns are
//! passed as `&[u8]` / `Vec<u8>` — this crate is deliberately agnostic of
//! the crypto layer, so schema and crypto can evolve independently.
//!
//! All string-keyed names enter the system through [`Username`] /
//! [`Projectname`], which NFC-normalize at construction to prevent Unicode
//! confusion attacks (§Security Invariant #5 in the README).

#![forbid(unsafe_code)]

mod error;
mod permissions;
mod pool;
mod projects;
mod types;
mod users;

#[cfg(test)]
pub(crate) mod test_support;

pub use error::DbError;
pub use permissions::{
    PermissionRow, get as get_permission, get_owner, insert as insert_permission, is_owner,
    list_grantees, revoke_all, revoke_user, transfer_ownership,
};
pub use pool::Db;
pub use projects::{add_member, create_project, is_member, project_exists};
pub use types::{KeyId, Projectname, Username};
pub use users::{UserAuthRow, create_user, get_priv_enc_and_pub, get_pub, update_priv_enc};
