use chrono::Utc;
use diesel::prelude::*;

use crate::dao::models::LoginSessionEntity;
use crate::dao::schema::login_sessions;
use crate::dao::schema::login_sessions::dsl::*;
use crate::dao::{DbConnection, DbPool, LoginSessionRepository};
use crate::domain::error::PassError;
use crate::domain::models::{LoginSession, PassResult};

#[derive(Clone)]
pub(crate) struct LoginSessionRepositoryImpl {
    pool: DbPool,
}

impl LoginSessionRepositoryImpl {
    pub(crate) fn new(pool: DbPool) -> Self {
        LoginSessionRepositoryImpl { pool }
    }
    fn connection(&self) -> PassResult<DbConnection> {
        self.pool.get().map_err(|err| {
            PassError::database(
                format!("failed to get pool connection due to {}", err).as_str(),
                None,
                true,
            )
        })
    }
}

impl LoginSessionRepository for LoginSessionRepositoryImpl {
    // create login_session.
    fn create(&self, login_session: &LoginSession) -> PassResult<usize> {
        let login_session_entity = LoginSessionEntity::new(login_session);
        let mut conn = self.connection()?;
        match diesel::insert_into(login_sessions::table)
            .values(login_session_entity)
            .execute(&mut conn)
        {
            Ok(size) => {
                if size > 0 {
                    log::debug!("created login_session {:?} {}", login_session, size);
                    Ok(size)
                } else {
                    Err(PassError::database(
                        format!("failed to insert {}", login_session.login_session_id).as_str(),
                        None,
                        false,
                    ))
                }
            }
            Err(err) => Err(PassError::from(err)),
        }
    }

    // get login_session by id
    fn get(&self, id: &str) -> PassResult<LoginSession> {
        let mut conn = self.connection()?;
        let mut items = login_sessions
            .filter(login_session_id.eq(id).and(signed_out_at.is_null()))
            .limit(2)
            .load::<LoginSessionEntity>(&mut conn)?;

        if items.len() > 1 {
            return Err(PassError::database(
                format!("too many login_sessions for {}", id).as_str(),
                None,
                false,
            ));
        } else if items.is_empty() {
            return Err(PassError::not_found(
                format!("login_sessions not found for {}", id).as_str(),
            ));
        }
        let entity = items.remove(0);
        Ok(entity.to_login_session())
    }

    // delete an existing login_session.
    fn delete(&self, id: &str) -> PassResult<usize> {
        let mut conn = self.connection()?;
        let size = diesel::update(
            login_sessions.filter(login_session_id.eq(id).and(signed_out_at.is_null())),
        )
        .set((signed_out_at.eq(Utc::now().naive_utc()),))
        .execute(&mut conn)?;
        if size > 0 {
            Ok(size)
        } else {
            Err(PassError::database(
                format!("failed to update login session {}", id,).as_str(),
                None,
                false,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto;
    use crate::dao::factory::{create_login_session_repository, create_user_repository};
    use crate::dao::models::UserContext;
    use crate::domain::models::{LoginSession, PassConfig, User};
    use uuid::Uuid;

    #[tokio::test]
    async fn test_should_create_login_sessions() {
        let config = PassConfig::new();
        // GIVEN a user and login_session repositories
        let user_repo = create_user_repository(&config).await.unwrap();
        let login_session_repo = create_login_session_repository(&config).await.unwrap();

        // Due to referential integrity, we must first create a valid user
        let username = Uuid::new_v4().to_string();
        let user = User::new(username.as_str(), None, None);
        let salt = hex::encode(crypto::generate_nonce());
        let pepper = hex::encode(crypto::generate_secret_key());

        let ctx =
            UserContext::default_new(&username, &user.user_id, &salt, &pepper, "password").unwrap();

        assert_eq!(1, user_repo.create(&ctx, &user).await.unwrap());

        // WHEN creating a login_session
        let login_session = LoginSession::new(&user.user_id);
        // THEN it should succeed
        assert_eq!(1, login_session_repo.create(&login_session).unwrap());

        // WHEN retrieving the login_session THEN it should return it
        let loaded = login_session_repo
            .get(&login_session.login_session_id)
            .unwrap();
        assert_eq!(loaded.user_id, user.user_id);
    }

    #[tokio::test]
    async fn test_should_create_delete_login_sessions() {
        let config = PassConfig::new();
        // GIVEN a user and login_session repositories
        let user_repo = create_user_repository(&config).await.unwrap();
        let login_session_repo = create_login_session_repository(&config).await.unwrap();

        let salt = hex::encode(crypto::generate_nonce());
        let pepper = hex::encode(crypto::generate_secret_key());
        // Due to referential integrity, we must first create a valid user
        let username = Uuid::new_v4().to_string();
        let user = User::new(username.as_str(), None, None);

        let ctx =
            UserContext::default_new(&username, &user.user_id, &salt, &pepper, "password").unwrap();

        assert_eq!(1, user_repo.create(&ctx, &user).await.unwrap());

        // WHEN creating a login_session
        let login_session = LoginSession::new(&user.user_id);
        // THEN it should succeed.
        assert_eq!(1, login_session_repo.create(&login_session).unwrap());

        // WHEN deleting the login session
        let deleted = login_session_repo
            .delete(&login_session.login_session_id)
            .unwrap();
        // THEN it should succeed.
        assert_eq!(1, deleted);

        // WHEN retrieving the login session after delete THEN it should fail.
        assert!(login_session_repo
            .get(&login_session.login_session_id)
            .is_err());
    }
}
