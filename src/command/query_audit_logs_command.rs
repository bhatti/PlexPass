use std::collections::HashMap;
use crate::domain::models::{AuditLog, PaginatedResult, PassConfig, PassResult};
use crate::service::locator::ServiceLocator;

pub async fn execute(
    config: PassConfig,
    username: &str,
    master_password: &str,
    offset: &Option<i64>,
    limit: &Option<usize>,
    q: &Option<String>,
) -> PassResult<PaginatedResult<AuditLog>> {
    let service_locator = ServiceLocator::new(&config).await?;
    let (ctx, _, _) = service_locator.user_service.signin_user(username, master_password, HashMap::new()).await?;
    let mut predicates = HashMap::new();
    if let Some(q) = q {
        predicates.insert("q".into(), q.clone());
    }
    service_locator.audit_log_service.find(&ctx, predicates, offset.unwrap_or(0), limit.unwrap_or(100)).await
}
