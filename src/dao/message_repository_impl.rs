use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use diesel::prelude::*;

use crate::dao::models::{CryptoKeyEntity, MessageEntity, UserContext};
use crate::dao::schema::messages;
use crate::dao::schema::messages::dsl::*;
use crate::dao::{DbConnection, DbPool, MessageRepository, Repository, UserRepository};
use crate::domain::error::PassError;
use crate::domain::models::{Message, PaginatedResult, PassResult, READ_FLAG};

#[derive(Clone)]
pub(crate) struct MessageRepositoryImpl {
    pool: DbPool,
    user_repository: Arc<dyn UserRepository + Send + Sync>,
}

impl MessageRepositoryImpl {
    pub(crate) fn new(
        pool: DbPool,
        user_repository: Arc<dyn UserRepository + Send + Sync>,
    ) -> Self {
        MessageRepositoryImpl {
            pool,
            user_repository,
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
impl MessageRepository for MessageRepositoryImpl {}

#[async_trait]
impl Repository<Message, MessageEntity> for MessageRepositoryImpl {
    // create message.
    async fn create(&self, ctx: &UserContext, message: &Message) -> PassResult<usize> {
        // ensure user-context and message user-id matches -- no acl check
        ctx.validate_user_id(&message.user_id, || false)?;

        let user_crypto_key = self
            .user_repository
            .get_crypto_key(ctx, &message.user_id)
            .await?;

        let message_entity =
            MessageEntity::new_from_context_message(ctx, &user_crypto_key, message)?;
        let mut conn = self.connection()?;
        let size = conn.transaction(|c| {
            diesel::insert_into(messages::table)
                .values(message_entity)
                .execute(c)
        })?;
        if size > 0 {
            log::info!("created message {} for user {}", &message.message_id, &message.user_id);
            Ok(size)
        } else {
            Err(PassError::database("failed to insert message", None, false))
        }
    }

    // updates existing message.
    async fn update(&self, ctx: &UserContext, message: &Message) -> PassResult<usize> {
        // ensure message belongs to user -- no acl check
        ctx.validate_user_id(&message.user_id, || false)?;

        let mut conn = self.connection()?;
        match diesel::update(
            messages.filter(
                user_id
                    .eq(&ctx.user_id)
                    .and(message_id.eq(&message.message_id)),
            ),
        )
        .set((
            flags.eq(&message.flags),
            updated_at.eq(Utc::now().naive_utc()),
        ))
        .execute(&mut conn)
        {
            Ok(size) => {
                if size > 0 {
                    Ok(size)
                } else {
                    Err(PassError::database(
                        format!("failed to update message {}", message.message_id).as_str(),
                        None,
                        false,
                    ))
                }
            }
            Err(err) => Err(PassError::from(err)),
        }
    }

    // get message by id
    async fn get(&self, ctx: &UserContext, id: &str) -> PassResult<Message> {
        let message_entity = self.get_entity(ctx, id).await?;
        let user_crypto_key = self
            .user_repository
            .get_crypto_key(ctx, &message_entity.user_id)
            .await?;

        message_entity.to_message(ctx, &user_crypto_key)
    }

    // delete an existing message.
    async fn delete(&self, ctx: &UserContext, id: &str) -> PassResult<usize> {
        // check existing message
        let _ = self.get_entity(ctx, id).await?;

        let mut conn = self.connection()?;
        let size = diesel::delete(messages.filter(user_id.eq(&ctx.user_id).and(message_id.eq(id))))
            .execute(&mut conn)?;
        if size > 0 {
            Ok(size)
        } else {
            Err(PassError::database(
                format!("failed to find records for deleting {}", id).as_str(),
                None,
                false,
            ))
        }
    }

    async fn get_crypto_key(&self, _ctx: &UserContext, _id: &str) -> PassResult<CryptoKeyEntity> {
        Err(PassError::validation("not implemented", None))
    }

    async fn get_entity(&self, ctx: &UserContext, id: &str) -> PassResult<MessageEntity> {
        let mut conn = self.connection()?;
        let mut items = messages
            .filter(user_id.eq(&ctx.user_id).and(message_id.eq(id)))
            .limit(2)
            .load::<MessageEntity>(&mut conn)?;
        if items.len() > 1 {
            return Err(PassError::database(
                format!("too many messages for {}", id).as_str(),
                None,
                false,
            ));
        } else if items.is_empty() {
            return Err(PassError::not_found(
                format!("message not found for {}", id).as_str(),
            ));
        }
        let entity = items.remove(0);
        // ensure message belongs to user -- no acl check
        ctx.validate_user_id(&entity.user_id, || false)?;
        Ok(entity)
    }

    // find one entity by predication -- must have only one record, i.e., it will throw error if 0 or 2+ records exist.
    async fn find_one(
        &self,
        ctx: &UserContext,
        predicates: HashMap<String, String>,
    ) -> PassResult<Message> {
        let mut res = self.find(ctx, predicates, 0, 5).await?;
        if res.records.len() != 1 {
            return Err(PassError::authorization(
                format!("could not find message - [{}]", res.records.len()).as_str(),
            ));
        }
        Ok(res.records.remove(0))
    }

    // find messages with pagination
    async fn find(
        &self,
        ctx: &UserContext,
        predicates: HashMap<String, String>,
        offset: i64,
        limit: usize,
    ) -> PassResult<PaginatedResult<Message>> {
        let mut predicates = predicates.clone();
        // only admin can query all users
        if !ctx.is_admin() {
            predicates.insert("user_id".into(), ctx.user_id.clone());
        }

        let mut conn = self.connection()?;
        let match_type = format!(
            "%{}%",
            predicates
                .get("kind")
                .cloned()
                .unwrap_or(String::from(""))
        );
        let match_flags = predicates.get("flags").unwrap_or(&String::from("0")).parse::<i64>().unwrap_or(READ_FLAG*10);
        let match_user_id = predicates
            .get("user_id")
            .cloned()
            .unwrap_or(String::from(""));
        let entities = messages
            .filter(user_id.eq(match_user_id).and(kind.like(match_type)).and(flags.le(match_flags)))
            .offset(offset)
            .limit(limit as i64)
            .order(messages::created_at.desc())
            .load::<MessageEntity>(&mut conn)?;
        let user_crypto_key = self
            .user_repository
            .get_crypto_key(ctx, &ctx.user_id)
            .await?;

        let mut res = vec![];
        for entity in entities {
            let message = entity.to_message(ctx, &user_crypto_key)?;
            res.push(message)
        }
        Ok(PaginatedResult::new(offset.clone(), limit.clone(), res))
    }

    async fn count(
        &self,
        ctx: &UserContext,
        predicates: HashMap<String, String>,
    ) -> PassResult<i64> {
        let mut predicates = predicates.clone();
        // only admin can query all users
        if !ctx.is_admin() {
            predicates.insert("user_id".into(), ctx.user_id.clone());
        }

        let mut conn = self.connection()?;
        let match_type = format!(
            "%{}%",
            predicates
                .get("kind")
                .cloned()
                .unwrap_or(String::from(""))
        );
        let match_flags = predicates.get("flags").unwrap_or(&String::from("0")).parse::<i64>().unwrap_or(READ_FLAG*10);
        let match_user_id = predicates
            .get("user_id")
            .cloned()
            .unwrap_or(String::from(""));
        match messages
            .filter(user_id.eq(match_user_id).and(kind.like(match_type)).and(flags.le(match_flags)))
            .count()
            .get_result::<i64>(&mut conn)
        {
            Ok(count) => Ok(count),
            Err(err) => Err(PassError::from(err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use uuid::Uuid;

    use crate::crypto;
    use crate::dao::factory::{create_message_repository, create_user_repository};
    use crate::dao::models::UserContext;
    use crate::domain::models::{Message, MessageKind, PassConfig, User};

    #[tokio::test]
    async fn test_should_create_update_messages() {
        let config = PassConfig::new();
        // GIVEN a user and message repositories
        let message_repo = create_message_repository(&config).await.unwrap();
        let user_repo = create_user_repository(&config).await.unwrap();
        // Due to referential integrity, we must first create a valid user
        let username = Uuid::new_v4().to_string();
        let user = User::new(username.as_str(), None, None);
        let salt = hex::encode(crypto::generate_nonce());
        let pepper = hex::encode(crypto::generate_secret_key());
        let ctx =
            UserContext::default_new(&username, &user.user_id, &salt, &pepper, "password").unwrap();

        assert_eq!(1, user_repo.create(&ctx, &user).await.unwrap());

        // WHEN creating a message
        let mut message = Message::new(&user.user_id, MessageKind::Broadcast, "subject", "data");
        // THEN it should succeed
        assert_eq!(1, message_repo.create(&ctx, &message).await.unwrap());

        // WHEN updating the message
        message.kind = MessageKind::Advisory;
        message.flags = 32;
        // THEN we should only be able to update flags and updated_at date - nothing else
        assert_eq!(1, message_repo.update(&ctx, &message).await.unwrap());

        // WHEN retrieving the message
        let loaded = message_repo.get(&ctx, &message.message_id).await.unwrap();
        // THEN we should find updated data
        assert_eq!(32, loaded.flags);
        assert_eq!(MessageKind::Broadcast, loaded.kind);
        assert_eq!(user.user_id, loaded.user_id);
    }

    #[tokio::test]
    async fn test_should_create_delete_messages() {
        let config = PassConfig::new();
        // GIVEN a user and message repositories
        let user_repo = create_user_repository(&config).await.unwrap();
        let message_repo = create_message_repository(&config).await.unwrap();

        let salt = hex::encode(crypto::generate_nonce());
        let pepper = hex::encode(crypto::generate_secret_key());
        // Due to referential integrity, we must first create a valid user
        let username = Uuid::new_v4().to_string();
        let user = User::new(username.as_str(), None, None);
        let ctx =
            UserContext::default_new(&username, &user.user_id, &salt, &pepper, "password").unwrap();
        assert_eq!(1, user_repo.create(&ctx, &user).await.unwrap());

        // WHEN creating a message
        let message = Message::new(&user.user_id, MessageKind::DM, "subject", "data");
        // THEN it should succeed
        assert_eq!(1, message_repo.create(&ctx, &message).await.unwrap());

        // WHEN deleting the message THEN it should succeed
        assert_eq!(
            1,
            message_repo
                .delete(&ctx, &message.message_id)
                .await
                .unwrap()
        );

        // WHEN retrieving the message after deleting it THEN it should fail
        assert!(message_repo.get(&ctx, &message.message_id).await.is_err());
    }

    #[tokio::test]
    async fn test_should_create_find_messages() {
        let config = PassConfig::new();
        // GIVEN a user and message repositories
        let user_repo = create_user_repository(&config).await.unwrap();
        let message_repo = create_message_repository(&config).await.unwrap();
        let salt = hex::encode(crypto::generate_nonce());
        let pepper = hex::encode(crypto::generate_secret_key());

        // Due to referential integrity, we must first create a valid user
        let username = Uuid::new_v4().to_string();
        let user = User::new(username.as_str(), None, None);
        let ctx =
            UserContext::default_new(&username, &user.user_id, &salt, &pepper, "password").unwrap();
        assert_eq!(1, user_repo.create(&ctx, &user).await.unwrap());

        for i in 0..3 {
            // WHEN creating a message with the same user_id
            let data = format!("{}_{}", username, i);
            let message = Message::new(&user.user_id, MessageKind::Advisory, "subject", &data);
            // THEN it should succeed
            assert_eq!(1, message_repo.create(&ctx, &message).await.unwrap());
        }

        // WHEN finding messages by the user_id
        let res = message_repo
            .find(
                &ctx,
                HashMap::from([("user_id".into(), user.user_id.clone())]),
                0,
                500,
            )
            .await
            .unwrap();
        // THEN it should succeed
        assert_eq!(3, res.records.len());

        // WHEN counting messages by the user_id
        let count = message_repo
            .count(
                &ctx,
                HashMap::from([("user_id".into(), user.user_id.clone())]),
            )
            .await
            .unwrap();
        // THEN it should succeed
        assert_eq!(3, count);
    }
}
