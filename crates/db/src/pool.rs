use std::path::Path;

use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};

use crate::DbError;

/// Handle to the KMS database. Cheap to clone? No — callers should hold one
/// `Db` per process and pass references.
#[derive(Debug)]
pub struct Db {
    pub(crate) pool: SqlitePool,
}

impl Db {
    /// Open (or create) a SQLite database at `path` and run embedded
    /// migrations.
    ///
    /// Every connection is configured with:
    /// - `foreign_keys = ON` (schema FKs are advisory in SQLite otherwise)
    /// - `journal_mode = WAL` (concurrent readers, single writer)
    /// - `synchronous = FULL` (durable against power loss; KMS priority)
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, DbError> {
        let options = SqliteConnectOptions::new()
            .filename(path.as_ref())
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full);

        let pool = SqlitePoolOptions::new().connect_with(options).await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool })
    }

    /// Close the underlying pool. Idempotent; safe to drop `Db` without
    /// calling this.
    pub async fn close(self) {
        self.pool.close().await;
    }
}
