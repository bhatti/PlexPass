use std::collections::HashMap;
use crate::domain::args::ArgsContext;
use crate::domain::models::{AuditLog, PaginatedResult, PassResult};

/// Shows audit logs.
pub async fn execute(
    args_ctx: &ArgsContext,
    offset: &Option<i64>,
    limit: &Option<usize>,
    q: &Option<String>,
) -> PassResult<PaginatedResult<AuditLog>> {
    let mut predicates = HashMap::new();
    if let Some(q) = q {
        predicates.insert("q".into(), q.clone());
    }
    args_ctx.service_locator.audit_log_service.find(
        &args_ctx.user_context,
        predicates,
        offset.unwrap_or(0),
        limit.unwrap_or(100)).await
}
