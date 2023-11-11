use actix_web::{HttpResponse, web, post, Error};
use serde_json::json;
use crate::controller::models::{Authenticated, ShareAccountParams, ShareVaultParams};
use crate::service::locator::ServiceLocator;

#[post("/api/v1/vaults/{vault_id}/share")]
pub async fn share_vault(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
    params: web::Json<ShareVaultParams>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let vault_id = path.into_inner();
    let size = service_locator
        .share_vault_account_service
        .share_vault(&auth.context, &vault_id, &params.target_username, params.read_only.unwrap_or(false))
        .await?;
    let data = json!({
        "shared": size > 0,
    });
    Ok(HttpResponse::Ok().json(data))
}

#[post("/api/v1/vaults/{vault_id}/accounts/{id}/share")]
pub async fn share_account(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<(String, String)>,
    params: web::Json<ShareAccountParams>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let path = path.into_inner();
    let _vault_id = path.0;
    let account_id = path.1;
    let size = service_locator
        .share_vault_account_service
        .share_account(&auth.context, &account_id, &params.target_username)
        .await?;
    let data = json!({
        "shared": size > 0,
    });
    Ok(HttpResponse::Ok().json(data))
}

