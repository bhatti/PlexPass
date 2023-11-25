use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use diesel::prelude::*;

use crate::dao::models::{AuditEntity, AuditKind, CryptoKeyEntity, UserContext, UserEntity};
use crate::dao::schema::users;
use crate::dao::schema::users::dsl::*;
use crate::dao::{AuditRepository, CryptoKeyRepository, DbConnection, LoginSessionRepository, Repository};
use crate::dao::{DbPool, UserRepository};
use crate::domain::error::PassError;
use crate::domain::models::{PaginatedResult, PassResult, User};

#[derive(Clone)]
pub(crate) struct UserRepositoryImpl {
    pool: DbPool,
    crypto_key_repository: Arc<dyn CryptoKeyRepository + Send + Sync>,
    session_repository: Arc<dyn LoginSessionRepository + Send + Sync>,
    audit_repository: Arc<dyn AuditRepository + Send + Sync>,
}

impl UserRepositoryImpl {
    pub(crate) fn new(
        pool: DbPool,
        crypto_key_repository: Arc<dyn CryptoKeyRepository + Send + Sync>,
        session_repository: Arc<dyn LoginSessionRepository + Send + Sync>,
        audit_repository: Arc<dyn AuditRepository + Send + Sync>,
    ) -> Self {
        UserRepositoryImpl {
            pool,
            crypto_key_repository,
            session_repository,
            audit_repository,
        }
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

#[async_trait]
impl UserRepository for UserRepositoryImpl {}

#[async_trait]
impl Repository<User, UserEntity> for UserRepositoryImpl {
    // create user entity from key context and user object.
    async fn create(&self, ctx: &UserContext, user: &User) -> PassResult<usize> {
        // no acl check
        ctx.validate_user_id(&user.user_id, || false)?;
        ctx.validate_username(&user.username)?;

        // checking existing usernamme
        let existing = self
            .find_one(
                ctx,
                HashMap::from([("username".into(), user.username.clone())]),
            )
            .await;
        if existing.is_ok() {
            return Err(PassError::duplicate_key("username is already defined"));
        }

        // sign up for user by creating new crypto keys
        let (user_entity, user_crypto_key) = UserEntity::new_signup(ctx, user)?;

        // inserting both user and keys in a transaction
        let mut conn = self.connection()?;

        // Create both user and crypto-key in a transaction.
        let size = conn.transaction(|c| {
            let _ = diesel::insert_into(users::table)
                .values(user_entity)
                .execute(c)?;
            let _ = self.crypto_key_repository.create(&user_crypto_key, c)?;
            self.audit_repository.create(&AuditEntity::new(
                ctx,
                AuditKind::Signup, &user.user_id, "user signup"),
                                                 c)
        })?;

        if size > 0 {
            Ok(size)
        } else {
            Err(PassError::database("failed to insert user", None, false))
        }
    }

    // updates existing user item
    async fn update(&self, ctx: &UserContext, user: &User) -> PassResult<usize> {
        // finding existing user
        let mut user_entity = self.get_entity(ctx, &user.user_id).await?;

        let user_crypto_key = self.get_crypto_key(ctx, &user.user_id).await?;

        // match version for optimistic concurrency control
        user_entity.match_version(user.version)?;

        // update user in memory
        let _ = user_entity.update_from_user(ctx, user, &user_crypto_key)?;

        // update user in database
        let mut conn = self.connection()?;
        let size = diesel::update(
            users.filter(
                user_id
                    .eq(&user_entity.user_id)
                    .and(version.eq(&user.version)),
            ),
        )
        .set((
            // username cannot be updated
            version.eq(user_entity.version + 1),
            nonce.eq(&user_entity.nonce),
            encrypted_value.eq(&user_entity.encrypted_value),
            updated_at.eq(&user_entity.updated_at),
        ))
        .execute(&mut conn)?;

        if size > 0 {
            let _ = self.audit_repository.create(&AuditEntity::new(
                ctx,
                AuditKind::UserUpdated, &user.user_id, "user updated"),
                                         &mut conn)?;
            Ok(size)
        } else {
            Err(PassError::database(
                        format!(
                            "failed to update user because couldn't find it with user-id {}, username {} and version {}",
                            user_entity.user_id, user_entity.username, user_entity.version,
                        )
                        .as_str(),
                        None,
                        false,
                    ))
        }
    }

    // find by key
    async fn get(&self, ctx: &UserContext, id: &str) -> PassResult<User> {
        let user_entity = self.get_entity(ctx, id).await?;
        let user_crypto_key = self.get_crypto_key(ctx, id).await?;
        user_entity.to_user(ctx, &user_crypto_key)
    }

    // delete user
    async fn delete(&self, ctx: &UserContext, id: &str) -> PassResult<usize> {
        let _ = self.get_entity(ctx, id).await?; // validate user exists and context can access it

        let mut conn = self.connection()?;
        let size: usize = conn.transaction(|c| {
            let _ = self.crypto_key_repository.delete(id, id, "User", c)?;
            let _ = self.session_repository.delete_by_user_id(ctx, id, c)?;
            let _ = self.audit_repository.delete_by_user_id(ctx, id, c)?;
            diesel::delete(users.filter(user_id.eq(id))).execute(c)
        })?;

        if size > 0 {
            Ok(size)
        } else {
            Err(PassError::database(
                format!("failed to delete user, user doesn't exist {}", id).as_str(),
                None,
                false,
            ))
        }
    }

    // get user crypto key
    async fn get_crypto_key(&self, ctx: &UserContext, id: &str) -> PassResult<CryptoKeyEntity> {
        let mut conn = self.connection()?;
        let crypto_key = self.crypto_key_repository.get(id, id, "User", &mut conn)?;

        // username in context must match user-id unless context is admin
        // no acl check
        let _ = ctx.validate_user_id(&crypto_key.user_id, || false)?;
        Ok(crypto_key)
    }

    // get user entity
    async fn get_entity(&self, ctx: &UserContext, id: &str) -> PassResult<UserEntity> {
        let mut conn = self.connection()?;
        let mut items = users
            .filter(user_id.eq(id))
            .limit(2)
            .load::<UserEntity>(&mut conn)?;

        if items.len() > 1 {
            return Err(PassError::database(
                format!("too many users for id {}", id).as_str(),
                None,
                false,
            ));
        } else if items.is_empty() {
            return Err(PassError::not_found(
                format!("user not found for key {}", id).as_str(),
            ));
        }

        let user_entity = items.remove(0);
        // username in context must match user-id unless context is admin -- no acl check
        let _ = ctx.validate_user_id(&user_entity.user_id, || false)?;
        Ok(user_entity)
    }
    // find one entity by predication -- must have only one record, i.e., it will throw error if 0 or 2+ records exist.
    async fn find_one(
        &self,
        ctx: &UserContext,
        predicates: HashMap<String, String>,
    ) -> PassResult<User> {
        let mut res = self.find(ctx, predicates, 0, 5).await?;
        if res.records.len() != 1 {
            return Err(PassError::authorization(
                format!("could not find user [{}]", res.records.len()).as_str(),
            ));
        }
        Ok(res.records.remove(0))
    }

    // find all entities with pagination
    async fn find(
        &self,
        ctx: &UserContext,
        predicates: HashMap<String, String>,
        offset: i64,
        page_size: usize,
    ) -> PassResult<PaginatedResult<User>> {
        let mut predicates = predicates.clone();
        // only admin can query all users
        if !ctx.is_admin() {
            predicates.insert("username".into(), ctx.username.clone());
        }

        let mut conn = self.connection()?;

        let entities = if ctx.is_admin() {
            let match_username = format!(
                "%{}%",
                predicates
                    .get("username")
                    .cloned()
                    .unwrap_or(String::from(""))
            );
            users
                .filter(username.like(match_username))
                .offset(offset)
                .limit(page_size as i64)
                .order(users::username)
                .load::<UserEntity>(&mut conn)?
        } else {
            let match_username = predicates
                .get("username")
                .cloned()
                .unwrap_or(String::from(""));
            users
                .filter(username.eq(match_username))
                .offset(offset)
                .limit(page_size as i64)
                .order(users::username)
                .load::<UserEntity>(&mut conn)?
        };

        let mut res = vec![];
        for entity in entities {
            ctx.validate_user_id(&entity.user_id, || false)?; // no acl check
            let user_crypto_key = self.get_crypto_key(ctx, &entity.user_id).await?;
            let mut user = entity.to_user(ctx, &user_crypto_key)?;
            user.version = entity.version;
            user.created_at = Some(entity.created_at);
            user.updated_at = Some(entity.updated_at);
            res.push(user);
        }

        Ok(PaginatedResult::new(offset, page_size, res))
    }

    async fn count(
        &self,
        ctx: &UserContext,
        predicates: HashMap<String, String>,
    ) -> PassResult<i64> {
        let mut predicates = predicates.clone();
        // only admin can count all users
        if !ctx.is_admin() {
            predicates.insert("username".into(), ctx.username.clone());
        }

        let mut conn = self.connection()?;

        let count = if ctx.is_admin() {
            let match_username = format!(
                "%{}%",
                predicates
                    .get("username")
                    .cloned()
                    .unwrap_or(String::from(""))
            );
            users
                .filter(username.like(match_username))
                .count()
                .get_result::<i64>(&mut conn)?
        } else {
            let match_username = predicates
                .get("username")
                .cloned()
                .unwrap_or(String::from(""));
            users
                .filter(username.eq(match_username))
                .count()
                .get_result::<i64>(&mut conn)?
        };
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use uuid::Uuid;

    use crate::crypto;
    use crate::dao::factory::create_user_repository;
    use crate::dao::models::UserContext;
    use crate::domain::models::{PassConfig, Roles, User, ADMIN_USER};

    #[tokio::test]
    async fn test_should_create_update_user() {
        let config = PassConfig::new();

        // GIVEN a user repository
        let user_repo = create_user_repository(&config).await.unwrap();
        let user_id = Uuid::new_v4().to_string();
        let mut user = User::new(&user_id, None, None);
        let salt = hex::encode(crypto::generate_nonce());
        let pepper = hex::encode(crypto::generate_secret_key());
        let ctx = UserContext::default_new(&user.username, &user.user_id, &salt, &pepper, "pass")
            .unwrap();

        // WHEN creating the user THEN it should succeed
        assert_eq!(1, user_repo.create(&ctx, &user).await.unwrap());

        user.email = Some("new-email".into());
        user.name = Some("new-name".into());

        // WHEN updating a user THEN it should succeed
        assert_eq!(1, user_repo.update(&ctx, &user).await.unwrap());

        // WHEN retrieving the user THEN it should match the updated values
        let loaded = user_repo.get(&ctx, &user.user_id).await.unwrap();
        assert_eq!(2, loaded.version);
        assert_eq!(Some("new-email".into()), loaded.email);
        assert_eq!(Some("new-name".into()), loaded.name);
    }

    #[tokio::test]
    async fn test_should_create_delete_user() {
        let config = PassConfig::new();
        // GIVEN a user repository
        let user_repo = create_user_repository(&config).await.unwrap();
        let user = User::new(&Uuid::new_v4().to_string(), None, None);
        let salt = hex::encode(crypto::generate_nonce());
        let pepper = hex::encode(crypto::generate_secret_key());
        let ctx = UserContext::default_new(&user.username, &user.user_id, &salt, &pepper, "pass")
            .unwrap();

        // WHEN creating the user THEN it should succeed
        assert_eq!(1, user_repo.create(&ctx, &user).await.unwrap());

        // WHEN deleting the user THEN it should succeed
        assert_eq!(1, user_repo.delete(&ctx, &user.user_id).await.unwrap());

        // WHEN retrieving the user after delete THEN it should fail
        assert!(user_repo.get(&ctx, &user.user_id).await.is_err());
    }

    #[tokio::test]
    async fn test_should_create_find_users() {
        let config = PassConfig::new();
        // GIVEN a user repository
        let user_repo = create_user_repository(&config).await.unwrap();
        let prefix1 = Uuid::new_v4().to_string();
        let prefix2 = format!("{}x", prefix1);
        let salt = hex::encode(crypto::generate_nonce());
        let pepper = hex::encode(crypto::generate_secret_key());

        let admin = User::new(prefix1.to_string().as_str(), None, None);
        let mut admin_ctx =
            UserContext::default_new(&admin.username, &admin.user_id, &salt, &pepper, "pass")
                .unwrap();
        admin_ctx.roles = Some(Roles::new(ADMIN_USER));
        assert_eq!(1, user_repo.create(&admin_ctx, &admin).await.unwrap());

        let mut user_ids = vec![];
        for i in 0..4 {
            if i % 2 == 0 {
                // WHEN creating the users with two different prefixes and a new suffix THEN it should succeed
                let user1 = User::new(format!("{}_{}", prefix1, i).as_str(), None, None);
                let ctx1 = UserContext::default_new(
                    &user1.username,
                    &user1.user_id,
                    &salt,
                    &pepper,
                    "pass",
                )
                .unwrap();
                assert_eq!(1, user_repo.create(&ctx1, &user1).await.unwrap());
                user_ids.push((user1.username.clone(), user1.user_id.clone()));
            } else {
                let user2 = User::new(format!("{}_{}", prefix2, i).as_str(), None, None);
                let ctx2 = UserContext::default_new(
                    &user2.username,
                    &user2.user_id,
                    &salt,
                    &pepper,
                    "pass",
                )
                .unwrap();
                assert_eq!(1, user_repo.create(&ctx2, &user2).await.unwrap());
                user_ids.push((user2.username.clone(), user2.user_id.clone()));
            }
        }

        // admin should fina all users
        let res = user_repo
            .find(
                &admin_ctx,
                HashMap::from([("username".into(), prefix1.clone())]),
                0,
                500,
            )
            .await
            .unwrap();
        assert_eq!(5, res.records.len());
        let count = user_repo
            .count(
                &admin_ctx,
                HashMap::from([("username".into(), prefix1.clone())]),
            )
            .await
            .unwrap();
        assert_eq!(5, count);

        for (username, user_id) in user_ids {
            // WHEN finding user by username then it should succeed.
            let ctx =
                UserContext::default_new(&username, &user_id, &salt, &pepper, "pass").unwrap();
            let res = user_repo
                .find(&ctx, HashMap::from([]), 0, 500)
                .await
                .unwrap();
            assert_eq!(1, res.records.len()); // only should return self

            // WHEN counting user by username then it should succeed.
            let count = user_repo.count(&ctx, HashMap::from([])).await.unwrap();
            assert_eq!(1, count);
        }
    }
}
