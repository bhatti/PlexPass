use crate::controller::get_session_context;
use crate::controller::models::{CreateVaultRequest, UpdateVaultRequest, VaultResponse};
use crate::service::locator::ServiceLocator;
use actix_session::Session;
use actix_web::{delete, get, post, put, web, Error, HttpResponse};

#[post("/api/v1/vaults")]
pub async fn create_vault(
    service_locator: web::Data<ServiceLocator>,
    payload: web::Json<CreateVaultRequest>,
    session: Session,
) -> Result<HttpResponse, Error> {
    let (_, ctx) = get_session_context(&session)?;
    let vault = payload.to_vault(&ctx.user_id);
    let _ = service_locator
        .vault_service
        .create_vault(&ctx, &vault)
        .await?;
    Ok(HttpResponse::Ok().json(VaultResponse::new(&vault)))
}

#[put("/api/v1/vaults/{id}")]
pub async fn update_vault(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
    payload: web::Json<UpdateVaultRequest>,
    session: Session,
) -> Result<HttpResponse, Error> {
    let id = path.into_inner();
    let (_, ctx) = get_session_context(&session)?;
    let mut vault = payload.to_vault(&ctx.user_id);
    vault.vault_id = id.clone();
    let _ = service_locator
        .vault_service
        .update_vault(&ctx, &vault)
        .await?;
    Ok(HttpResponse::Ok().finish())
}
#[get("/api/v1/vaults")]
pub async fn get_vaults(
    service_locator: web::Data<ServiceLocator>,
    session: Session,
) -> Result<HttpResponse, Error> {
    let (_, ctx) = get_session_context(&session)?;
    let vaults: Vec<VaultResponse> = service_locator
        .vault_service
        .get_user_vaults(&ctx)
        .await?
        .iter()
        .map(|v| VaultResponse::new(v))
        .collect();
    Ok(HttpResponse::Ok().json(vaults))
}

#[get("/api/v1/vaults/{id}")]
pub async fn get_vault(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
    session: Session,
) -> Result<HttpResponse, Error> {
    let id = path.into_inner();
    let (_, ctx) = get_session_context(&session)?;
    let vault = service_locator.vault_service.get_vault(&ctx, &id).await?;
    Ok(HttpResponse::Ok().json(vault))
}

#[delete("/api/v1/vaults/{id}")]
pub async fn delete_vault(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
    session: Session,
) -> Result<HttpResponse, Error> {
    let id = path.into_inner();
    let (_, ctx) = get_session_context(&session)?;
    let _ = service_locator
        .vault_service
        .delete_vault(&ctx, &id)
        .await?;
    Ok(HttpResponse::Ok().finish())
}
