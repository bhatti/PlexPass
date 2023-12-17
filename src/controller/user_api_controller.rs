use actix_web::{delete, Error, get, HttpRequest, HttpResponse, post, put, web};
use actix_web::web::Bytes;
use serde::Deserialize;

use crate::controller::models::{Authenticated, ChangePasswordParams, UpdateUserRequest, UserResponse};
use crate::domain::models::EncodingScheme;
use crate::service::locator::ServiceLocator;
use crate::utils::is_private_ip;

#[get("/api/v1/users/{id}")]
pub async fn get_user(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let mut id = path.into_inner();
    if id == "me" {
        id = auth.context.user_id.clone();
    }
    let (_, user) = service_locator.user_service.get_user(&auth.context, &id).await?;
    Ok(HttpResponse::Ok().json(UserResponse::new(&user)))
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
    let mut id = path.into_inner();
    if id == "me" {
        id = auth.context.user_id.clone();
    }
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
    let mut id = path.into_inner();
    if id == "me" {
        id = auth.context.user_id.clone();
    }
    let mut user = payload.to_user();
    user.user_id = id.clone();
    let _ = service_locator
        .user_service
        .update_user(&auth.context, &user)
        .await?;
    Ok(HttpResponse::Ok().finish())
}

#[put("/api/v1/users/{id}/change_password")]
pub async fn change_password(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
    params: web::Json<ChangePasswordParams>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let id = path.into_inner();
    if id != auth.context.user_id && id != "me" {
        return Ok(HttpResponse::BadRequest().body("user-id didn't match".to_string()));
    }
    match service_locator
        .auth_service
        .change_password(&auth.context, &params.old_password,
                         &params.new_password, &params.confirm_new_password,
                         &auth.user_token.login_session)
        .await {
        Ok(_) => {
            Ok(HttpResponse::Ok().finish())
        }
        Err(err) => {
            let err_msg = err.to_string();
            Ok(HttpResponse::BadRequest().body(err_msg))
        }
    }
}

#[post("/api/v1/users/asymmetric_encrypt/{username}")]
pub async fn asymmetric_user_encrypt(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
    body: Bytes,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let username = path.into_inner();
    let res = service_locator.user_service.asymmetric_user_encrypt(
        &auth.context,
        &username,
        body.to_vec(),
        EncodingScheme::Base64).await?;
    Ok(HttpResponse::Ok().body(Bytes::from(res)))
}

#[post("/api/v1/users/asymmetric_decrypt")]
pub async fn asymmetric_user_decrypt(
    service_locator: web::Data<ServiceLocator>,
    body: Bytes,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let res = service_locator.user_service.asymmetric_user_decrypt(
        &auth.context,
        body.to_vec(),
        EncodingScheme::Base64).await?;
    Ok(HttpResponse::Ok().body(Bytes::from(res)))
}

