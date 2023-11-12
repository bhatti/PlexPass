use std::collections::HashMap;

use actix_web::{Result, Responder, web};
use actix_web_lab::respond::Html;
use serde::{Deserialize};
use askama::Template;

use crate::controller::models::{Authenticated};
use crate::domain::models::{AuditLog, PaginatedResult};
use crate::service::locator::ServiceLocator;

#[derive(Debug, Clone, Template)]
#[template(path = "audit_logs.html")]
struct AuditLogTemplate {
    pub current_page: usize,
    pub total_pages: usize,
    pub pages: Vec<usize>,
    pub audit_logs: Vec<AuditLog>,
}

impl AuditLogTemplate {
    pub fn new(logs: &PaginatedResult<AuditLog>, current_page: usize, records_per_page: usize) -> Self {
        let total_records: usize = logs.total_records.unwrap_or(logs.records.len() as i64) as usize;
        let total_pages: usize = (total_records + records_per_page - 1) / records_per_page;
        let num_pages_to_display = 10;

        let start_page = if total_pages <= num_pages_to_display {
            1
        } else if current_page + num_pages_to_display / 2 >= total_pages {
            total_pages - num_pages_to_display + 1
        } else {
            current_page - num_pages_to_display / 2
        };

        let end_page = usize::min(start_page + num_pages_to_display - 1, total_pages);

        let x = Self {
            current_page,
            total_pages,
            pages: (start_page..=end_page).collect(),
            audit_logs: vec![],
        };
        println!("xxxxx {:?}", x);
        Self {
            current_page,
            total_pages,
            pages: (start_page..=end_page).collect(),
            audit_logs: logs.records.clone(),
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct AuditParams {
    pub q: Option<String>,
    pub page: Option<usize>,
}

pub async fn audit_logs(
    service_locator: web::Data<ServiceLocator>,
    query: web::Query<AuditParams>,
    auth: Authenticated,
) -> Result<impl Responder> {
    let mut predicates = HashMap::new();
    if let Some(q) = &query.q {
        predicates.insert("q".into(), q.to_string());
    }
    let page = query.page.unwrap_or(1);
    let limit = 50;
    let offset = (page-1) * limit;
    let logs = service_locator
        .audit_log_service
        .find(
            &auth.context,
            predicates,
            offset as i64,
            limit,
        )
        .await?;
    let template = AuditLogTemplate::new(&logs, page, limit);
    let html = template.render().expect("could not find audit logs template");
    Ok(Html(html))
}

