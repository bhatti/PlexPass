use std::collections::HashMap;
use actix_web::{get, HttpResponse, web, Error};
use crate::controller::models::{Authenticated, PaginatedAuditLogResult, QueryAuditParams};
use crate::service::locator::ServiceLocator;

#[get("/api/v1/audit_logs")]
pub async fn audit_logs(
    service_locator: web::Data<ServiceLocator>,
    params: web::Query<QueryAuditParams>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let mut predicates = HashMap::new();
    if let Some(q) = &params.q {
        predicates.insert("q".into(), q.clone());
    }

    let logs = service_locator
        .audit_log_service
        .find(
            &auth.context,
            predicates,
            params.offset.unwrap_or(0),
            params.limit.unwrap_or(100),
        )
        .await?;
    let result = PaginatedAuditLogResult {
        offset: params.offset.unwrap_or(0),
        limit: params.limit.unwrap_or(100),
        total_records: logs.total_records,
        audit_logs: logs.records,
    };
    Ok(HttpResponse::Ok().json(result))
}

