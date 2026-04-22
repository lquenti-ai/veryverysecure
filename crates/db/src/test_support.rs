use tempfile::TempDir;

use crate::Db;

/// Wraps a `Db` opened against a fresh tempfile. The `TempDir` is held for
/// the lifetime of `TestDb` so the file sticks around until the test drops
/// the handle.
pub(crate) struct TestDb {
    pub db: Db,
    _tempdir: TempDir,
}

impl TestDb {
    pub async fn new() -> Self {
        let tempdir = TempDir::new().expect("create tempdir");
        let path = tempdir.path().join("vvs-test.db");
        let db = Db::open(&path).await.expect("open test db");
        Self {
            db,
            _tempdir: tempdir,
        }
    }
}
