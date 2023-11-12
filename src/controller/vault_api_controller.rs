use crate::controller::models::{Authenticated, CreateVaultRequest, UpdateVaultRequest, VaultResponse};
use crate::service::locator::ServiceLocator;
use actix_web::{delete, get, post, put, web, Error, HttpResponse};

#[post("/api/v1/vaults")]
pub async fn create_vault(
    service_locator: web::Data<ServiceLocator>,
    payload: web::Json<CreateVaultRequest>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let vault = payload.to_vault(&auth.context.user_id);
    let _ = service_locator
        .vault_service
        .create_vault(&auth.context, &vault)
        .await?;
    Ok(HttpResponse::Ok().json(VaultResponse::new(&vault)))
}

#[put("/api/v1/vaults/{id}")]
pub async fn update_vault(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
    payload: web::Json<UpdateVaultRequest>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let id = path.into_inner();
    let mut vault = payload.to_vault(&auth.context.user_id);
    vault.vault_id = id.clone();
    let _ = service_locator
        .vault_service
        .update_vault(&auth.context, &vault)
        .await?;
    Ok(HttpResponse::Ok().finish())
}

#[post("/api/v1/vaults/{id}/analyze_passwords")]
pub async fn analyze_vault_passwords(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let id = path.into_inner();
    service_locator
        .password_service
        .schedule_analyze_vault_passwords(&auth.context, &id)
        .await?;
    Ok(HttpResponse::Accepted().finish())
}

#[get("/api/v1/vaults")]
pub async fn get_vaults(
    service_locator: web::Data<ServiceLocator>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let vaults: Vec<VaultResponse> = service_locator
        .vault_service
        .get_user_vaults(&auth.context)
        .await?
        .iter()
        .map(VaultResponse::new)
        .collect();
    Ok(HttpResponse::Ok().json(vaults))
}

#[get("/api/v1/vaults/{id}")]
pub async fn get_vault(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let id = path.into_inner();
    let vault = service_locator.vault_service.get_vault(&auth.context, &id).await?;
    Ok(HttpResponse::Ok().json(vault))
}

#[delete("/api/v1/vaults/{id}")]
pub async fn delete_vault(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let id = path.into_inner();
    let _ = service_locator
        .vault_service
        .delete_vault(&auth.context, &id)
        .await?;
    Ok(HttpResponse::Ok().finish())
}
