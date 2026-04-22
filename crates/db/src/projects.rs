use crate::{Db, DbError, Projectname, Username};

/// Create a new project. Fails with [`DbError::AlreadyExists`] if the
/// name is taken.
pub async fn create_project(db: &Db, name: &Projectname) -> Result<(), DbError> {
    let result = sqlx::query("INSERT INTO Project (Projectname) VALUES (?)")
        .bind(name.as_str())
        .execute(&db.pool)
        .await;
    match result {
        Ok(_) => Ok(()),
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => Err(DbError::AlreadyExists),
        Err(e) => Err(DbError::Sqlx(e)),
    }
}

/// Return whether a project with this name exists.
pub async fn project_exists(db: &Db, name: &Projectname) -> Result<bool, DbError> {
    let row: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM Project WHERE Projectname = ?")
        .bind(name.as_str())
        .fetch_optional(&db.pool)
        .await?;
    Ok(row.is_some())
}

/// Add an existing user to a project. Both user and project must exist
/// (the FKs bubble up as `Sqlx` if they don't).
pub async fn add_member(db: &Db, user: &Username, project: &Projectname) -> Result<(), DbError> {
    let result = sqlx::query("INSERT INTO UserProject (Username, Projectname) VALUES (?, ?)")
        .bind(user.as_str())
        .bind(project.as_str())
        .execute(&db.pool)
        .await;
    match result {
        Ok(_) => Ok(()),
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => Err(DbError::AlreadyExists),
        Err(e) => Err(DbError::Sqlx(e)),
    }
}

/// Return whether a user is a member of a project.
pub async fn is_member(db: &Db, user: &Username, project: &Projectname) -> Result<bool, DbError> {
    let row: Option<(i64,)> =
        sqlx::query_as("SELECT 1 FROM UserProject WHERE Username = ? AND Projectname = ?")
            .bind(user.as_str())
            .bind(project.as_str())
            .fetch_optional(&db.pool)
            .await?;
    Ok(row.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestDb;
    use crate::users::create_user;

    async fn setup_user(t: &TestDb, name: &str) -> Username {
        let u = Username::new(name).unwrap();
        create_user(&t.db, &u, &[0; 48], &[0; 32]).await.unwrap();
        u
    }

    async fn setup_project(t: &TestDb, name: &str) -> Projectname {
        let p = Projectname::new(name).unwrap();
        create_project(&t.db, &p).await.unwrap();
        p
    }

    #[tokio::test]
    async fn create_and_exists_round_trip() {
        let t = TestDb::new().await;
        let p = Projectname::new("proj").unwrap();
        assert!(!project_exists(&t.db, &p).await.unwrap());
        create_project(&t.db, &p).await.unwrap();
        assert!(project_exists(&t.db, &p).await.unwrap());
    }

    #[tokio::test]
    async fn create_duplicate_project_returns_already_exists() {
        let t = TestDb::new().await;
        let p = setup_project(&t, "proj").await;
        let err = create_project(&t.db, &p).await.unwrap_err();
        assert!(matches!(err, DbError::AlreadyExists));
    }

    #[tokio::test]
    async fn add_member_and_is_member() {
        let t = TestDb::new().await;
        let u = setup_user(&t, "alice").await;
        let p = setup_project(&t, "proj").await;
        assert!(!is_member(&t.db, &u, &p).await.unwrap());
        add_member(&t.db, &u, &p).await.unwrap();
        assert!(is_member(&t.db, &u, &p).await.unwrap());
    }

    #[tokio::test]
    async fn add_duplicate_member_returns_already_exists() {
        let t = TestDb::new().await;
        let u = setup_user(&t, "alice").await;
        let p = setup_project(&t, "proj").await;
        add_member(&t.db, &u, &p).await.unwrap();
        let err = add_member(&t.db, &u, &p).await.unwrap_err();
        assert!(matches!(err, DbError::AlreadyExists));
    }

    #[tokio::test]
    async fn add_member_with_missing_user_is_fk_error() {
        let t = TestDb::new().await;
        let p = setup_project(&t, "proj").await;
        let ghost = Username::new("ghost").unwrap();
        let err = add_member(&t.db, &ghost, &p).await.unwrap_err();
        assert!(matches!(err, DbError::Sqlx(_)));
    }

    #[tokio::test]
    async fn add_member_with_missing_project_is_fk_error() {
        let t = TestDb::new().await;
        let u = setup_user(&t, "alice").await;
        let ghost = Projectname::new("ghost").unwrap();
        let err = add_member(&t.db, &u, &ghost).await.unwrap_err();
        assert!(matches!(err, DbError::Sqlx(_)));
    }
}
