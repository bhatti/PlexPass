use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use prometheus::Registry;

use crate::dao::models::UserContext;
use crate::dao::MessageRepository;
use crate::domain::models::{Message, PaginatedResult, PassConfig, PassResult};
use crate::service::MessageService;
use crate::utils::metrics::PassMetrics;

#[derive(Clone)]
pub(crate) struct MessageServiceImpl {
    config: PassConfig,
    message_repository: Arc<dyn MessageRepository + Send + Sync>,
    metrics: PassMetrics,
}

impl MessageServiceImpl {
    pub(crate) fn new(
        config: &PassConfig,
        message_repository: Arc<dyn MessageRepository + Send + Sync>,
        registry: &Registry,
    ) -> PassResult<Self> {
        Ok(Self {
            config: config.clone(),
            message_repository,
            metrics: PassMetrics::new("message_service", registry)?,
        })
    }
}

#[async_trait]
impl MessageService for MessageServiceImpl {
    async fn create_message(&self, ctx: &UserContext, message: &Message) -> PassResult<usize> {
        let _ = self.metrics.new_metric("create_message");
        self.message_repository.create(ctx, message).await
    }

    // updates existing message flags
    async fn update_message(&self, ctx: &UserContext, message: &Message) -> PassResult<usize> {
        let _ = self.metrics.new_metric("update_message");
        self.message_repository.update(ctx, message).await
    }

    async fn delete_message(&self, ctx: &UserContext, id: &str) -> PassResult<usize> {
        let _ = self.metrics.new_metric("delete_message");
        self.message_repository.delete(ctx, id).await
    }

    async fn find_messages_by_user(
        &self,
        ctx: &UserContext,
        message_type: &str,
        offset: i64,
        limit: usize,
    ) -> PassResult<PaginatedResult<Message>> {
        let _ = self.metrics.new_metric("find_messages_by_user");
        self.message_repository
            .find(
                ctx,
                HashMap::from([
                    ("user_id".into(), ctx.user_id.clone()),
                    ("message_type".into(), message_type.to_string()),
                ]),
                offset,
                limit,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use crate::domain::models::{HSMProvider, Message, PassConfig, User};
    use crate::service::factory::{create_message_service, create_user_service};

    #[tokio::test]
    async fn test_should_create_update_message() {
        let mut config = PassConfig::new();
        config.hsm_provider = HSMProvider::EncryptedFile.to_string();
        // GIVEN user-service and message-service
        let user_service = create_user_service(&config).await.unwrap();
        let message_service = create_message_service(&config).await.unwrap();

        // Due to referential integrity, we must first create a valid user
        let user = User::new(Uuid::new_v4().to_string().as_str(), None, None);
        let ctx = user_service.signup_user(&user, "password").await.unwrap();

        let message_type = Uuid::new_v4().to_string();
        // WHEN creating a message
        let mut message = Message::new(&user.user_id, &message_type, "subject", "data");

        // THEN it should succeed
        assert_eq!(
            1,
            message_service
                .create_message(&ctx, &message)
                .await
                .unwrap()
        );

        // WHEN updating an message
        message.flags = 2;
        // THEN it should succeed updating.
        assert_eq!(
            1,
            message_service
                .update_message(&ctx, &message)
                .await
                .unwrap()
        );

        // WHEN retrieving the message
        let find_res = message_service
            .find_messages_by_user(&ctx, message_type.as_str(), 0, 1000)
            .await
            .unwrap();
        // THEN message should have updated attributes.
        for loaded in find_res.records {
            assert_eq!(2, loaded.flags);
            assert_eq!(message.user_id, loaded.user_id);
        }
    }

    #[tokio::test]
    async fn test_should_create_delete_messages() {
        let mut config = PassConfig::new();
        config.hsm_provider = HSMProvider::EncryptedFile.to_string();
        // GIVEN user-service and message-service
        let user_service = create_user_service(&config).await.unwrap();
        let message_service = create_message_service(&config).await.unwrap();

        // Due to referential integrity, we must first create a valid user
        let user = User::new(Uuid::new_v4().to_string().as_str(), None, None);
        let ctx = user_service.signup_user(&user, "password").await.unwrap();

        let message_type = Uuid::new_v4().to_string();
        // WHEN creating an message
        let message = Message::new(&user.user_id, &message_type, "subject", "data");

        // THEN it should succeed
        assert_eq!(
            1,
            message_service
                .create_message(&ctx, &message)
                .await
                .unwrap()
        );

        // WHEN deleting the message
        let deleted = message_service
            .delete_message(&ctx, message.message_id.as_str())
            .await
            .unwrap();
        // THEN it should succeed.
        assert_eq!(1, deleted);

        // WHEN retrieving the message after deleting it THEN it should not find it.
        let res = message_service
            .find_messages_by_user(&ctx, &message_type, 0, 500)
            .await
            .unwrap();
        assert_eq!(0, res.records.len());
    }

    #[tokio::test]
    async fn test_should_create_find_messages() {
        let mut config = PassConfig::new();
        config.hsm_provider = HSMProvider::EncryptedFile.to_string();
        // GIVEN user-service and message-service
        let user_service = create_user_service(&config).await.unwrap();
        let message_service = create_message_service(&config).await.unwrap();

        // Due to referential integrity, we must first create a valid user
        let user1 = User::new(Uuid::new_v4().to_string().as_str(), None, None);
        let ctx1 = user_service.signup_user(&user1, "password").await.unwrap();
        let user2 = User::new(Uuid::new_v4().to_string().as_str(), None, None);
        let ctx2 = user_service.signup_user(&user2, "password").await.unwrap();

        for _i in 0..5 {
            // WHEN creating an message
            let message = Message::new(&user1.user_id, "kind", "subject", "data");
            assert_eq!(
                1,
                message_service
                    .create_message(&ctx1, &message)
                    .await
                    .unwrap()
            );
        }

        let res1 = message_service
            .find_messages_by_user(&ctx1, "", 0, 500)
            .await
            .unwrap();
        assert_eq!(5, res1.records.len());
        // try changing user-id in context to non-existing
        let res2 = message_service
            .find_messages_by_user(&ctx2, "", 0, 500)
            .await
            .unwrap();
        assert_eq!(0, res2.records.len());
    }
}
