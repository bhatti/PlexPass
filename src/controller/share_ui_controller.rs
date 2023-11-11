use actix_web::{HttpResponse, web, Error};
use crate::controller::models::{Authenticated, ShareAccountParams, ShareVaultParams};
use crate::service::locator::ServiceLocator;

pub async fn share_vault(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
    params: web::Query<ShareVaultParams>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let vault_id = path.into_inner();
    let _ = service_locator
        .share_vault_account_service
        .share_vault(&auth.context, &vault_id, &params.target_username, params.read_only.unwrap_or(false))
        .await?;
    Ok(HttpResponse::Ok().finish())
}

pub async fn share_account(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<(String, String)>,
    params: web::Query<ShareAccountParams>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let path = path.into_inner();
    let _vault_id = path.0;
    let account_id = path.1;
    let _ = service_locator
        .share_vault_account_service
        .share_account(&auth.context, &account_id, &params.target_username)
        .await?;
    Ok(HttpResponse::Ok().finish())
}

