use std::collections::HashMap;
use crate::service::locator::ServiceLocator;
use actix_web::{post, web, Error, HttpResponse};
use actix_web::web::Bytes;
use serde_json::json;
use crate::controller::models::Authenticated;
use crate::domain::models::{EncodingScheme, ProgressStatus};
use serde::{Deserialize};

#[post("/api/v1/vaults/{id}/import")]
pub async fn import_accounts(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
    query: web::Query<HashMap<String, String>>,
    body: Bytes,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let vault_id = path.into_inner();
    let password = query.get("password").map(|s|s.into());
    let size = service_locator.import_export_service.import_accounts(
        &auth.context,
        Some(vault_id.clone()),
        None,
        password,
        EncodingScheme::Base64,
        &body,
        Box::new(|status| match status {
            ProgressStatus::Started { .. } => {}
            ProgressStatus::Updated { .. } => {}
            ProgressStatus::Completed => {}
            ProgressStatus::Failed(_) => {}
        }),
    ).await?;
    let data = json!({
        "imported": size,
    });
    Ok(HttpResponse::Ok().json(data))
}

#[derive(Deserialize)]
pub struct PasswordInfo {
    password: Option<String>,
}

#[post("/api/v1/vaults/{id}/export")]
pub async fn export_accounts(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
    auth: Authenticated,
    info: web::Json<PasswordInfo>,
) -> Result<HttpResponse, Error> {
    let vault_id = path.into_inner();
    let (_, bytes_csv) = service_locator.import_export_service.export_accounts(
        &auth.context,
        &vault_id,
        info.password.clone(),
        EncodingScheme::Base64,
        Box::new(|status| match status {
            ProgressStatus::Started { .. } => {}
            ProgressStatus::Updated { .. } => {}
            ProgressStatus::Completed => {}
            ProgressStatus::Failed(_) => {}
        }),
    ).await?;
    Ok(HttpResponse::Ok().body(Bytes::from(bytes_csv)))
}

// async fn download() -> Result<NamedFile, E> {
//     Ok(NamedFile::open(Path::new("path"))?)
// }