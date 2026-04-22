use crate::{Db, DbError, KeyId, Projectname, Username};

/// A Permission row as returned from the DB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionRow {
    /// `SealedBox(DEK, UserServerPub)` raw bytes.
    pub value_enc: Vec<u8>,
    /// Whether this row is the (unique) owner row for `(Projectname, KeyId)`.
    pub is_owner: bool,
}

/// Insert a Permission row.
///
/// Unique-index enforcement (§ README partial index `OneOwnerPerKey`) means
/// only one row per `(Projectname, KeyId)` may have `is_owner = true`; a
/// second insert with `is_owner = true` fails with [`DbError::AlreadyExists`].
pub async fn insert(
    db: &Db,
    user: &Username,
    project: &Projectname,
    key_id: &KeyId,
    value_enc: &[u8],
    is_owner: bool,
) -> Result<(), DbError> {
    let result = sqlx::query(
        "INSERT INTO Permission (Username, Projectname, KeyId, ValueEnc, IsOwner) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(user.as_str())
    .bind(project.as_str())
    .bind(key_id.hyphenated())
    .bind(value_enc)
    .bind(if is_owner { 1i64 } else { 0 })
    .execute(&db.pool)
    .await;

    match result {
        Ok(_) => Ok(()),
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => Err(DbError::AlreadyExists),
        Err(e) => Err(DbError::Sqlx(e)),
    }
}

/// Fetch a single Permission row, if one exists for this `(user, project,
/// key_id)` triple.
pub async fn get(
    db: &Db,
    user: &Username,
    project: &Projectname,
    key_id: &KeyId,
) -> Result<Option<PermissionRow>, DbError> {
    let row: Option<(Vec<u8>, i64)> = sqlx::query_as(
        "SELECT ValueEnc, IsOwner FROM Permission \
         WHERE Username = ? AND Projectname = ? AND KeyId = ?",
    )
    .bind(user.as_str())
    .bind(project.as_str())
    .bind(key_id.hyphenated())
    .fetch_optional(&db.pool)
    .await?;
    Ok(row.map(|(value_enc, is_owner)| PermissionRow {
        value_enc,
        is_owner: is_owner != 0,
    }))
}

/// Return whether `user` is the owner row for `(project, key_id)`.
pub async fn is_owner(
    db: &Db,
    user: &Username,
    project: &Projectname,
    key_id: &KeyId,
) -> Result<bool, DbError> {
    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT IsOwner FROM Permission \
         WHERE Username = ? AND Projectname = ? AND KeyId = ?",
    )
    .bind(user.as_str())
    .bind(project.as_str())
    .bind(key_id.hyphenated())
    .fetch_optional(&db.pool)
    .await?;
    Ok(matches!(row, Some((1,))))
}

/// Return the current owner of `(project, key_id)`, if one exists.
pub async fn get_owner(
    db: &Db,
    project: &Projectname,
    key_id: &KeyId,
) -> Result<Option<Username>, DbError> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT Username FROM Permission \
         WHERE Projectname = ? AND KeyId = ? AND IsOwner = 1",
    )
    .bind(project.as_str())
    .bind(key_id.hyphenated())
    .fetch_optional(&db.pool)
    .await?;
    match row {
        Some((s,)) => Username::new(s).map(Some),
        None => Ok(None),
    }
}

/// List every Permission row for `(project, key_id)`.
pub async fn list_grantees(
    db: &Db,
    project: &Projectname,
    key_id: &KeyId,
) -> Result<Vec<(Username, Vec<u8>, bool)>, DbError> {
    let rows: Vec<(String, Vec<u8>, i64)> = sqlx::query_as(
        "SELECT Username, ValueEnc, IsOwner FROM Permission \
         WHERE Projectname = ? AND KeyId = ? ORDER BY Username",
    )
    .bind(project.as_str())
    .bind(key_id.hyphenated())
    .fetch_all(&db.pool)
    .await?;
    rows.into_iter()
        .map(|(u, v, i)| Username::new(u).map(|u| (u, v, i != 0)))
        .collect()
}

/// Delete a single user's Permission row for this key. Returns [`DbError::NotFound`]
/// if no such row existed.
pub async fn revoke_user(
    db: &Db,
    user: &Username,
    project: &Projectname,
    key_id: &KeyId,
) -> Result<(), DbError> {
    let r = sqlx::query(
        "DELETE FROM Permission \
         WHERE Username = ? AND Projectname = ? AND KeyId = ?",
    )
    .bind(user.as_str())
    .bind(project.as_str())
    .bind(key_id.hyphenated())
    .execute(&db.pool)
    .await?;
    if r.rows_affected() == 0 {
        return Err(DbError::NotFound);
    }
    Ok(())
}

/// Delete every Permission row for `(project, key_id)`. Returns the number
/// of rows removed.
pub async fn revoke_all(db: &Db, project: &Projectname, key_id: &KeyId) -> Result<u64, DbError> {
    let r = sqlx::query("DELETE FROM Permission WHERE Projectname = ? AND KeyId = ?")
        .bind(project.as_str())
        .bind(key_id.hyphenated())
        .execute(&db.pool)
        .await?;
    Ok(r.rows_affected())
}

/// Transfer ownership of a key from `from` to `to`.
///
/// Preconditions: both users have a Permission row for `(project, key_id)`
/// and `from` is the current owner. On any precondition failure the
/// transaction is rolled back and a typed error returned.
///
/// The two UPDATEs (unset `from.IsOwner`, set `to.IsOwner`) happen in one
/// transaction. Order matters: the `OneOwnerPerKey` partial index would
/// reject a moment with two owners, so we clear first and set second.
pub async fn transfer_ownership(
    db: &Db,
    project: &Projectname,
    key_id: &KeyId,
    from: &Username,
    to: &Username,
) -> Result<(), DbError> {
    let mut tx = db.pool.begin().await?;

    let from_row: Option<(i64,)> = sqlx::query_as(
        "SELECT IsOwner FROM Permission \
         WHERE Username = ? AND Projectname = ? AND KeyId = ?",
    )
    .bind(from.as_str())
    .bind(project.as_str())
    .bind(key_id.hyphenated())
    .fetch_optional(&mut *tx)
    .await?;

    match from_row {
        None => return Err(DbError::NotFound),
        Some((0,)) => return Err(DbError::NotOwner),
        Some(_) => {}
    }

    let to_row: Option<(i64,)> = sqlx::query_as(
        "SELECT 1 FROM Permission \
         WHERE Username = ? AND Projectname = ? AND KeyId = ?",
    )
    .bind(to.as_str())
    .bind(project.as_str())
    .bind(key_id.hyphenated())
    .fetch_optional(&mut *tx)
    .await?;
    if to_row.is_none() {
        return Err(DbError::MissingRecipientRow);
    }

    sqlx::query(
        "UPDATE Permission SET IsOwner = 0 \
         WHERE Username = ? AND Projectname = ? AND KeyId = ?",
    )
    .bind(from.as_str())
    .bind(project.as_str())
    .bind(key_id.hyphenated())
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        "UPDATE Permission SET IsOwner = 1 \
         WHERE Username = ? AND Projectname = ? AND KeyId = ?",
    )
    .bind(to.as_str())
    .bind(project.as_str())
    .bind(key_id.hyphenated())
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::projects::{add_member, create_project};
    use crate::test_support::TestDb;
    use crate::users::create_user;

    struct Fixture {
        db: TestDb,
        alice: Username,
        bob: Username,
        carol: Username,
        proj: Projectname,
        key_id: KeyId,
    }

    async fn fixture() -> Fixture {
        let db = TestDb::new().await;
        let alice = Username::new("alice").unwrap();
        let bob = Username::new("bob").unwrap();
        let carol = Username::new("carol").unwrap();
        let proj = Projectname::new("proj").unwrap();
        let key_id = KeyId::new();

        for (u, priv_tag, pub_tag) in [
            (&alice, 0xA1u8, 0xA2u8),
            (&bob, 0xB1, 0xB2),
            (&carol, 0xC1, 0xC2),
        ] {
            create_user(&db.db, u, &[priv_tag; 48], &[pub_tag; 32])
                .await
                .unwrap();
        }
        create_project(&db.db, &proj).await.unwrap();
        add_member(&db.db, &alice, &proj).await.unwrap();
        add_member(&db.db, &bob, &proj).await.unwrap();
        add_member(&db.db, &carol, &proj).await.unwrap();

        Fixture {
            db,
            alice,
            bob,
            carol,
            proj,
            key_id,
        }
    }

    #[tokio::test]
    async fn insert_then_get_round_trips() {
        let f = fixture().await;
        insert(&f.db.db, &f.alice, &f.proj, &f.key_id, &[0x55; 80], true)
            .await
            .unwrap();
        let row = get(&f.db.db, &f.alice, &f.proj, &f.key_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.value_enc, vec![0x55; 80]);
        assert!(row.is_owner);
    }

    #[tokio::test]
    async fn is_owner_reflects_flag() {
        let f = fixture().await;
        insert(&f.db.db, &f.alice, &f.proj, &f.key_id, &[0; 80], true)
            .await
            .unwrap();
        insert(&f.db.db, &f.bob, &f.proj, &f.key_id, &[0; 80], false)
            .await
            .unwrap();
        assert!(
            is_owner(&f.db.db, &f.alice, &f.proj, &f.key_id)
                .await
                .unwrap()
        );
        assert!(
            !is_owner(&f.db.db, &f.bob, &f.proj, &f.key_id)
                .await
                .unwrap()
        );
        assert!(
            !is_owner(&f.db.db, &f.carol, &f.proj, &f.key_id)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn duplicate_primary_key_returns_already_exists() {
        let f = fixture().await;
        insert(&f.db.db, &f.alice, &f.proj, &f.key_id, &[0; 80], true)
            .await
            .unwrap();
        let err = insert(&f.db.db, &f.alice, &f.proj, &f.key_id, &[1; 80], false)
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::AlreadyExists));
    }

    #[tokio::test]
    async fn second_owner_row_violates_partial_unique_index() {
        let f = fixture().await;
        insert(&f.db.db, &f.alice, &f.proj, &f.key_id, &[0; 80], true)
            .await
            .unwrap();
        let err = insert(&f.db.db, &f.bob, &f.proj, &f.key_id, &[0; 80], true)
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::AlreadyExists));
    }

    #[tokio::test]
    async fn multiple_non_owner_rows_are_allowed() {
        let f = fixture().await;
        insert(&f.db.db, &f.alice, &f.proj, &f.key_id, &[0; 80], true)
            .await
            .unwrap();
        insert(&f.db.db, &f.bob, &f.proj, &f.key_id, &[0; 80], false)
            .await
            .unwrap();
        insert(&f.db.db, &f.carol, &f.proj, &f.key_id, &[0; 80], false)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn get_owner_returns_the_owner() {
        let f = fixture().await;
        insert(&f.db.db, &f.alice, &f.proj, &f.key_id, &[0; 80], true)
            .await
            .unwrap();
        insert(&f.db.db, &f.bob, &f.proj, &f.key_id, &[0; 80], false)
            .await
            .unwrap();
        let owner = get_owner(&f.db.db, &f.proj, &f.key_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(owner, f.alice);
    }

    #[tokio::test]
    async fn list_grantees_returns_all_rows_sorted() {
        let f = fixture().await;
        insert(&f.db.db, &f.bob, &f.proj, &f.key_id, &[2; 80], false)
            .await
            .unwrap();
        insert(&f.db.db, &f.alice, &f.proj, &f.key_id, &[1; 80], true)
            .await
            .unwrap();
        insert(&f.db.db, &f.carol, &f.proj, &f.key_id, &[3; 80], false)
            .await
            .unwrap();
        let rows = list_grantees(&f.db.db, &f.proj, &f.key_id).await.unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].0, f.alice);
        assert_eq!(rows[1].0, f.bob);
        assert_eq!(rows[2].0, f.carol);
        assert!(rows[0].2 && !rows[1].2 && !rows[2].2);
    }

    #[tokio::test]
    async fn revoke_user_removes_one_row() {
        let f = fixture().await;
        insert(&f.db.db, &f.alice, &f.proj, &f.key_id, &[0; 80], true)
            .await
            .unwrap();
        insert(&f.db.db, &f.bob, &f.proj, &f.key_id, &[0; 80], false)
            .await
            .unwrap();
        revoke_user(&f.db.db, &f.bob, &f.proj, &f.key_id)
            .await
            .unwrap();
        assert!(
            get(&f.db.db, &f.bob, &f.proj, &f.key_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            get(&f.db.db, &f.alice, &f.proj, &f.key_id)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn revoke_user_missing_row_returns_not_found() {
        let f = fixture().await;
        let err = revoke_user(&f.db.db, &f.bob, &f.proj, &f.key_id)
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::NotFound));
    }

    #[tokio::test]
    async fn revoke_all_removes_every_row() {
        let f = fixture().await;
        insert(&f.db.db, &f.alice, &f.proj, &f.key_id, &[0; 80], true)
            .await
            .unwrap();
        insert(&f.db.db, &f.bob, &f.proj, &f.key_id, &[0; 80], false)
            .await
            .unwrap();
        insert(&f.db.db, &f.carol, &f.proj, &f.key_id, &[0; 80], false)
            .await
            .unwrap();
        let n = revoke_all(&f.db.db, &f.proj, &f.key_id).await.unwrap();
        assert_eq!(n, 3);
        assert!(
            list_grantees(&f.db.db, &f.proj, &f.key_id)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn transfer_ownership_happy_path() {
        let f = fixture().await;
        insert(&f.db.db, &f.alice, &f.proj, &f.key_id, &[0; 80], true)
            .await
            .unwrap();
        insert(&f.db.db, &f.bob, &f.proj, &f.key_id, &[0; 80], false)
            .await
            .unwrap();
        transfer_ownership(&f.db.db, &f.proj, &f.key_id, &f.alice, &f.bob)
            .await
            .unwrap();
        assert!(
            !is_owner(&f.db.db, &f.alice, &f.proj, &f.key_id)
                .await
                .unwrap()
        );
        assert!(
            is_owner(&f.db.db, &f.bob, &f.proj, &f.key_id)
                .await
                .unwrap()
        );
        assert_eq!(
            get_owner(&f.db.db, &f.proj, &f.key_id)
                .await
                .unwrap()
                .unwrap(),
            f.bob
        );
    }

    #[tokio::test]
    async fn transfer_ownership_from_missing_row_returns_not_found() {
        let f = fixture().await;
        insert(&f.db.db, &f.bob, &f.proj, &f.key_id, &[0; 80], false)
            .await
            .unwrap();
        let err = transfer_ownership(&f.db.db, &f.proj, &f.key_id, &f.alice, &f.bob)
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::NotFound));
    }

    #[tokio::test]
    async fn transfer_ownership_from_non_owner_returns_not_owner() {
        let f = fixture().await;
        insert(&f.db.db, &f.alice, &f.proj, &f.key_id, &[0; 80], true)
            .await
            .unwrap();
        insert(&f.db.db, &f.bob, &f.proj, &f.key_id, &[0; 80], false)
            .await
            .unwrap();
        insert(&f.db.db, &f.carol, &f.proj, &f.key_id, &[0; 80], false)
            .await
            .unwrap();
        let err = transfer_ownership(&f.db.db, &f.proj, &f.key_id, &f.bob, &f.carol)
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::NotOwner));
    }

    #[tokio::test]
    async fn transfer_ownership_to_missing_row_returns_missing_recipient_row() {
        let f = fixture().await;
        insert(&f.db.db, &f.alice, &f.proj, &f.key_id, &[0; 80], true)
            .await
            .unwrap();
        let err = transfer_ownership(&f.db.db, &f.proj, &f.key_id, &f.alice, &f.bob)
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::MissingRecipientRow));
        assert!(
            is_owner(&f.db.db, &f.alice, &f.proj, &f.key_id)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn after_transfer_exactly_one_owner_invariant_holds() {
        let f = fixture().await;
        insert(&f.db.db, &f.alice, &f.proj, &f.key_id, &[0; 80], true)
            .await
            .unwrap();
        insert(&f.db.db, &f.bob, &f.proj, &f.key_id, &[0; 80], false)
            .await
            .unwrap();
        transfer_ownership(&f.db.db, &f.proj, &f.key_id, &f.alice, &f.bob)
            .await
            .unwrap();

        let rows = list_grantees(&f.db.db, &f.proj, &f.key_id).await.unwrap();
        let owner_count = rows.iter().filter(|(_, _, is_o)| *is_o).count();
        assert_eq!(owner_count, 1);
    }

    #[tokio::test]
    async fn cascade_on_user_delete_removes_permissions() {
        let f = fixture().await;
        insert(&f.db.db, &f.alice, &f.proj, &f.key_id, &[0; 80], true)
            .await
            .unwrap();
        sqlx::query("DELETE FROM User WHERE Username = ?")
            .bind(f.alice.as_str())
            .execute(&f.db.db.pool)
            .await
            .unwrap();
        assert!(
            get(&f.db.db, &f.alice, &f.proj, &f.key_id)
                .await
                .unwrap()
                .is_none()
        );
    }
}
