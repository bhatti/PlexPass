use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use prometheus::Registry;

use crate::dao::models::UserContext;
use crate::dao::AuditRepository;
use crate::domain::models::{AuditLog, PaginatedResult, PassConfig, PassResult};
use crate::service::AuditLogService;
use crate::utils::metrics::PassMetrics;

#[derive(Clone)]
pub(crate) struct AuditLogServiceImpl {
    audit_repository: Arc<dyn AuditRepository+ Send + Sync>,
    metrics: PassMetrics,
}

impl AuditLogServiceImpl {
    pub(crate) fn new(
        _config: &PassConfig,
        audit_repository: Arc<dyn AuditRepository+ Send + Sync>,
        registry: &Registry,
    ) -> PassResult<Self> {
        Ok(Self {
            audit_repository,
            metrics: PassMetrics::new("audit_log_service", registry)?,
        })
    }
}

#[async_trait]
impl AuditLogService for AuditLogServiceImpl {
    async fn find(&self,
            ctx: &UserContext,
            predicates: HashMap<String, String>,
            offset: i64,
            limit: usize,
    ) -> PassResult<PaginatedResult<AuditLog>> {
        let _ = self.metrics.new_metric("find");
        print!(" 11");
        let count = self.audit_repository.count(ctx, predicates.clone())?;
        print!(" count {}", count.clone());
        let mut result = self.audit_repository.find(ctx, predicates, offset, limit)?;
        result.total_records = Option::from(count);
        print!(" records {:?}", result.total_records.clone());
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use uuid::Uuid;

    use crate::domain::models::{HSMProvider, Message, MessageKind, PassConfig, User};
    use crate::service::factory::{create_audit_log_service, create_message_service, create_user_service};

    #[tokio::test]
    async fn test_should_find_audit_logs() {
        let mut config = PassConfig::new();
        config.hsm_provider = HSMProvider::EncryptedFile.to_string();
        // GIVEN user-service and message-service
        let user_service = create_user_service(&config).await.unwrap();
        let message_service = create_message_service(&config).await.unwrap();
        let audit_service = create_audit_log_service(&config).await.unwrap();

        // Due to referential integrity, we must first create a valid user
        let user1 = User::new(Uuid::new_v4().to_string().as_str(), None, None);
        let ctx1 = user_service.register_user(&user1, "cru5h&r]fIt@$@v!or", HashMap::new()).await.unwrap();
        let user2 = User::new(Uuid::new_v4().to_string().as_str(), None, None);
        let ctx2 = user_service.register_user(&user2, "cru5h&r]fIt@$@v!or", HashMap::new()).await.unwrap();

        for _i in 0..5 {
            // WHEN creating an message
            let message = Message::new(&user1.user_id, MessageKind::Advisory, "subject", "data");
            assert_eq!(
                1,
                message_service
                    .create_message(&ctx1, &message)
                    .await
                    .unwrap()
            );
        }

        let res1 = audit_service
            .find(&ctx1, HashMap::new(), 0, 500)
            .await
            .unwrap();
        for log in &res1.records {
            assert_eq!(&log.user_id, &ctx1.user_id);
        }
        assert_eq!(6, res1.records.len());

        let res2 = audit_service
            .find(&ctx2, HashMap::new(), 0, 500)
            .await
            .unwrap();
        for log in &res2.records {
            assert_eq!(&log.user_id, &ctx2.user_id);
        }
        assert_eq!(6, res2.records.len());
    }
}
