use actix_web::{delete, Error, get, HttpRequest, HttpResponse, put, web};
use serde::Deserialize;

use crate::controller::models::{Authenticated, UpdateUserRequest};
use crate::service::locator::ServiceLocator;
use crate::utils::is_private_ip;

#[get("/api/v1/users/{id}")]
pub async fn get_user(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let id = path.into_inner();
    let (_, user) = service_locator.user_service.get_user(&auth.context, &id).await?;
    Ok(HttpResponse::Ok().json(user))
}

#[derive(Deserialize)]
pub struct QueryUsernamesParams {
    q: String,
}

#[get("/api/v1/usernames")]
pub async fn search_usernames(
    service_locator: web::Data<ServiceLocator>,
    req: HttpRequest,
    query: web::Query<QueryUsernamesParams>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let mut results = vec![];
    // search-usernames is only enabled for local access
    if let Some(addr) = req.peer_addr() {
        if is_private_ip(addr.ip()) {
            results = service_locator.share_vault_account_service.lookup_usernames(&auth.context, &query.q).await?;
        } else {
            log::debug!("disabling auto-complete for {:?}", addr.ip().to_string());
        }
    }
    Ok(HttpResponse::Ok().json(results))
}

#[delete("/api/v1/users/{id}")]
pub async fn delete_user(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let id = path.into_inner();
    let _ = service_locator.user_service.delete_user(&auth.context, &id).await?;
    Ok(HttpResponse::Ok().finish())
}

#[put("/api/v1/users/{id}")]
pub async fn update_user(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
    payload: web::Json<UpdateUserRequest>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let id = path.into_inner();
    let mut user = payload.to_user();
    user.user_id = id.clone();
    let _ = service_locator
        .user_service
        .update_user(&auth.context, &user)
        .await?;
    Ok(HttpResponse::Ok().finish())
}
