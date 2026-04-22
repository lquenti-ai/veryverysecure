use crate::{Db, DbError, Username};

/// Raw bytes returned by [`get_priv_enc_and_pub`]. Both fields are encrypted
/// or public material — never plaintext secrets — and thus not zeroized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAuthRow {
    /// XChaCha20-Poly1305 wrapped `UserServerPriv` (nonce || ciphertext).
    pub priv_enc: Vec<u8>,
    /// Raw X25519 public key bytes.
    pub pub_key: Vec<u8>,
}

/// Insert a new User row. Fails with [`DbError::AlreadyExists`] if the
/// username is taken.
pub async fn create_user(
    db: &Db,
    username: &Username,
    user_server_priv_enc: &[u8],
    user_server_pub: &[u8],
) -> Result<(), DbError> {
    let result = sqlx::query(
        "INSERT INTO User (Username, UserServerPrivEnc, UserServerPub) VALUES (?, ?, ?)",
    )
    .bind(username.as_str())
    .bind(user_server_priv_enc)
    .bind(user_server_pub)
    .execute(&db.pool)
    .await;

    match result {
        Ok(_) => Ok(()),
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => Err(DbError::AlreadyExists),
        Err(e) => Err(DbError::Sqlx(e)),
    }
}

/// Fetch a user's public key if the user exists.
pub async fn get_pub(db: &Db, username: &Username) -> Result<Option<Vec<u8>>, DbError> {
    let row: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT UserServerPub FROM User WHERE Username = ?")
            .bind(username.as_str())
            .fetch_optional(&db.pool)
            .await?;
    Ok(row.map(|(b,)| b))
}

/// Fetch both the encrypted private key and the public key for auth flows.
pub async fn get_priv_enc_and_pub(
    db: &Db,
    username: &Username,
) -> Result<Option<UserAuthRow>, DbError> {
    let row: Option<(Vec<u8>, Vec<u8>)> =
        sqlx::query_as("SELECT UserServerPrivEnc, UserServerPub FROM User WHERE Username = ?")
            .bind(username.as_str())
            .fetch_optional(&db.pool)
            .await?;
    Ok(row.map(|(priv_enc, pub_key)| UserAuthRow { priv_enc, pub_key }))
}

/// Replace a user's wrapped private key (CLI rewrap flow). The public key
/// and DEK shares are untouched. Fails with [`DbError::NotFound`] if the
/// user does not exist.
pub async fn update_priv_enc(
    db: &Db,
    username: &Username,
    new_priv_enc: &[u8],
) -> Result<(), DbError> {
    let r = sqlx::query("UPDATE User SET UserServerPrivEnc = ? WHERE Username = ?")
        .bind(new_priv_enc)
        .bind(username.as_str())
        .execute(&db.pool)
        .await?;
    if r.rows_affected() == 0 {
        return Err(DbError::NotFound);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestDb;

    async fn user(name: &str) -> Username {
        Username::new(name).unwrap()
    }

    #[tokio::test]
    async fn create_then_get_pub_round_trips() {
        let t = TestDb::new().await;
        let u = user("alice").await;
        create_user(&t.db, &u, &[0xAA; 48], &[0xBB; 32])
            .await
            .unwrap();
        let got = get_pub(&t.db, &u).await.unwrap().unwrap();
        assert_eq!(got, vec![0xBB; 32]);
    }

    #[tokio::test]
    async fn create_duplicate_returns_already_exists() {
        let t = TestDb::new().await;
        let u = user("alice").await;
        create_user(&t.db, &u, &[0; 48], &[0; 32]).await.unwrap();
        let err = create_user(&t.db, &u, &[1; 48], &[1; 32])
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::AlreadyExists));
    }

    #[tokio::test]
    async fn get_pub_returns_none_for_missing_user() {
        let t = TestDb::new().await;
        let u = user("ghost").await;
        assert!(get_pub(&t.db, &u).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn get_priv_enc_and_pub_returns_both_halves() {
        let t = TestDb::new().await;
        let u = user("alice").await;
        create_user(&t.db, &u, &[0xAA; 48], &[0xBB; 32])
            .await
            .unwrap();
        let row = get_priv_enc_and_pub(&t.db, &u).await.unwrap().unwrap();
        assert_eq!(row.priv_enc, vec![0xAA; 48]);
        assert_eq!(row.pub_key, vec![0xBB; 32]);
    }

    #[tokio::test]
    async fn update_priv_enc_changes_priv_but_not_pub() {
        let t = TestDb::new().await;
        let u = user("alice").await;
        create_user(&t.db, &u, &[0xAA; 48], &[0xBB; 32])
            .await
            .unwrap();
        update_priv_enc(&t.db, &u, &[0xCC; 48]).await.unwrap();
        let row = get_priv_enc_and_pub(&t.db, &u).await.unwrap().unwrap();
        assert_eq!(row.priv_enc, vec![0xCC; 48]);
        assert_eq!(row.pub_key, vec![0xBB; 32]);
    }

    #[tokio::test]
    async fn update_priv_enc_for_missing_user_returns_not_found() {
        let t = TestDb::new().await;
        let u = user("ghost").await;
        let err = update_priv_enc(&t.db, &u, &[0; 48]).await.unwrap_err();
        assert!(matches!(err, DbError::NotFound));
    }
}
