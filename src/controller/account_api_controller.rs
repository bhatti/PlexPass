use std::collections::HashMap;

use actix_web::{delete, Error, get, HttpResponse, post, put, web};

use crate::controller::models::{AccountResponse, Authenticated, CreateAccountRequest, PaginatedAccountResult, QueryAccountParams, UpdateAccountRequest};
use crate::service::locator::ServiceLocator;

#[post("/api/v1/vaults/{vault_id}/accounts")]
pub async fn create_account(
    service_locator: web::Data<ServiceLocator>,
    payload: web::Json<CreateAccountRequest>,
    path: web::Path<String>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let vault_id = path.into_inner();
    let mut account = payload.to_account();
    account.vault_id = vault_id;
    let _ = service_locator
        .account_service
        .create_account(&auth.context, &account)
        .await?;
    Ok(HttpResponse::Ok().json(AccountResponse::new(&account)))
}

#[put("/api/v1/vaults/{vault_id}/accounts/{id}")]
pub async fn update_account(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<(String, String)>,
    payload: web::Json<UpdateAccountRequest>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let path = path.into_inner();
    let vault_id = path.0;
    let account_id = path.1;
    let mut account = payload.to_account();
    account.vault_id = vault_id.clone();
    account.details.account_id = account_id.clone();
    let _ = service_locator
        .account_service
        .update_account(&auth.context, &account)
        .await?;
    Ok(HttpResponse::Ok().finish())
}

#[get("/api/v1/vaults/{vault_id}/full_accounts")]
pub async fn get_full_accounts(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
    params: web::Query<QueryAccountParams>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let vault_id = path.into_inner();
    let mut predicates = HashMap::new();
    if let Some(q) = &params.q {
        predicates.insert("q".into(), q.clone());
    }
    let paginated_accounts = service_locator
        .account_service
        .find_accounts_by_vault(
            &auth.context,
            &vault_id,
            predicates,
            params.offset.unwrap_or(0),
            params.limit.unwrap_or(10),
        )
        .await?;
    Ok(HttpResponse::Ok().json(PaginatedAccountResult::new(&paginated_accounts)))
}

#[get("/api/v1/vaults/{vault_id}/accounts")]
pub async fn get_accounts(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
    params: web::Query<QueryAccountParams>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let vault_id = path.into_inner();
    let accounts = service_locator
        .vault_service
        .account_summaries_by_vault(
            &auth.context,
            &vault_id,
            params.q.clone(),
        )
        .await?;
    Ok(HttpResponse::Ok().json(&accounts))
}

#[get("/api/v1/vaults/{vault_id}/accounts/{id}")]
pub async fn get_account(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<(String, String)>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let path = path.into_inner();
    let _vault_id = path.0;
    let account_id = path.1;
    let account = service_locator
        .account_service
        .get_account(&auth.context, &account_id)
        .await?;
    let res = AccountResponse::new(&account);
    Ok(HttpResponse::Ok().json(res))
}

#[delete("/api/v1/vaults/{vault_id}/accounts/{id}")]
pub async fn delete_account(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<(String, String)>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let path = path.into_inner();
    let _vault_id = path.0;
    let account_id = path.1;
    let _ = service_locator
        .account_service
        .delete_account(&auth.context, &account_id)
        .await?;
    Ok(HttpResponse::Ok().finish())
}
