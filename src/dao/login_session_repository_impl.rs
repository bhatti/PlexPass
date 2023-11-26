use chrono::Utc;
use diesel::prelude::*;

use crate::dao::models::{LoginSessionEntity, UserContext};
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

    /// get login_session by user-id and session-id
    // Note: compare id with only latest record in case user signs in again and invalidate older session.
    fn get(&self, other_user_id: &str, other_session_id: &str) -> PassResult<LoginSession> {
        let mut conn = self.connection()?;
        let mut items = login_sessions
            .filter(user_id.eq(other_user_id))
            .limit(2)
            .order(login_sessions::created_at.desc())
            .load::<LoginSessionEntity>(&mut conn)?;

        if items.is_empty() {
            return Err(PassError::not_found(
                format!("login_sessions not found for {}", other_session_id).as_str(),
            ));
        }
        let entity = items.remove(0);
        if entity.login_session_id == other_session_id && entity.signed_out_at.is_none() {
            return Ok(entity.to_login_session());
        }
        return Err(PassError::not_found(
            format!("login_sessions did not match for {}", other_session_id).as_str(),
        ));
    }

    // update session by id
    fn mfa_succeeded(&self, other_user_id: &str, other_session_id: &str) -> PassResult<LoginSession> {
        let mut session = self.get(other_user_id, other_session_id)?;
        if !session.mfa_required {
            return Err(PassError::validation("mfa is not required", None));
        }
        if !session.verified_mfa() {
            return Err(PassError::validation("mfa cannot be updated for stale session", None));
        }

        let mut conn = self.connection()?;
        let size = diesel::update(
            login_sessions.filter(
                user_id.eq(other_user_id).and(login_session_id.eq(other_session_id).and(signed_out_at.is_null()))),
        )
            .set((mfa_verified_at.eq(Utc::now().naive_utc()), ))
            .execute(&mut conn)?;
        if size > 0 {
            Ok(session)
        } else {
            Err(PassError::database(
                format!("failed to update mfa status for login session {}", other_session_id, ).as_str(),
                None,
                false,
            ))
        }
    }

    // set light_model
    fn update_light_mode(&self, other_user_id: &str, other_session_id: &str, other_light_mode: bool) -> PassResult<usize> {
        let mut conn = self.connection()?;
        let size = diesel::update(
            login_sessions.filter(
                user_id.eq(other_user_id).and(login_session_id.eq(other_session_id).and(signed_out_at.is_null()))),
        )
            .set((light_mode.eq(other_light_mode), ))
            .execute(&mut conn)?;
        Ok(size)
    }

    // signout an existing login_session.
    fn signout(&self, other_user_id: &str, other_session_id: &str) -> PassResult<usize> {
        let mut conn = self.connection()?;
        let size = diesel::update(
            login_sessions.filter(
                user_id.eq(other_user_id).and(login_session_id.eq(other_session_id).and(signed_out_at.is_null()))))
            .set(signed_out_at.eq(Utc::now().naive_utc()))
            .execute(&mut conn)?;
        if size > 0 {
            Ok(size)
        } else {
            Err(PassError::database(
                format!("failed to update login session {}", other_session_id, ).as_str(),
                None,
                false,
            ))
        }
    }

    // delete_by_user_id delete all user sessions
    fn delete_by_user_id(&self,
                         ctx: &UserContext,
                         other_user_id: &str,
                         c: &mut DbConnection,
    ) -> Result<usize, diesel::result::Error> {
        // no acl check
        if let Ok(()) = ctx.validate_user_id(other_user_id, || false) {
            diesel::delete(login_sessions.filter(user_id.eq(other_user_id))).execute(c)
        } else {
            Ok(0)
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
        let login_session = LoginSession::new(&user);
        // THEN it should succeed
        assert_eq!(1, login_session_repo.create(&login_session).unwrap());

        // WHEN retrieving the login_session THEN it should return it
        let loaded = login_session_repo
            .get(&login_session.user_id, &login_session.login_session_id)
            .unwrap();
        assert_eq!(loaded.user_id, user.user_id);

        // Creating another session
        // WHEN creating a login_session
        let login_session2 = LoginSession::new(&user);
        // THEN it should succeed
        assert_eq!(1, login_session_repo.create(&login_session2).unwrap());

        // WHEN retrieving older login_session THEN it should fail it
        assert!(login_session_repo.get(&login_session.user_id, &login_session.login_session_id).is_err());

        // WHEN retrieving newer login_session THEN it should return it
        let loaded = login_session_repo
            .get(&login_session.user_id, &login_session2.login_session_id)
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
        let login_session = LoginSession::new(&user);
        // THEN it should succeed.
        assert_eq!(1, login_session_repo.create(&login_session).unwrap());

        // WHEN signing out the login session
        let deleted = login_session_repo
            .signout(&login_session.user_id, &login_session.login_session_id)
            .unwrap();
        // THEN it should succeed.
        assert_eq!(1, deleted);

        // WHEN retrieving the login session after delete THEN it should fail.
        assert!(login_session_repo
            .get(&login_session.user_id, &login_session.login_session_id)
            .is_err());
    }
}
