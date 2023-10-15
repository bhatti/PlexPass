use crate::controller::models::{
    SigninUserRequest, SigninUserResponse, SignupUserRequest, SignupUserResponse, UpdateUserRequest,
};
use crate::controller::{get_session_context, USER_SESSION_KEY};
use crate::service::locator::ServiceLocator;
use actix_session::Session;
use actix_web::{delete, get, post, put, web, Error, HttpRequest, HttpResponse};
use std::collections::HashMap;

const ACCESS_TOKEN: &str = "ACCESS_TOKEN";

#[post("/api/v1/auth/signup")]
pub async fn signup_user(
    service_locator: web::Data<ServiceLocator>,
    payload: web::Json<SignupUserRequest>,
) -> Result<HttpResponse, Error> {
    let ctx = service_locator
        .user_service
        .signup_user(&payload.to_user(), &payload.master_password)
        .await?;
    let res = SignupUserResponse::new(&ctx.user_id);
    Ok(HttpResponse::Ok().json(res))
}

#[post("/api/v1/auth/signin")]
pub async fn signin_user(
    req: HttpRequest,
    service_locator: web::Data<ServiceLocator>,
    payload: web::Json<SigninUserRequest>,
) -> Result<HttpResponse, Error> {
    let mut context = HashMap::new();
    if let Some(addr) = req.peer_addr() {
        context.insert("ip_address".into(), addr.ip().to_string());
    };
    let (ctx, _user, token) = service_locator
        .user_service
        .signin_user(&payload.username, &payload.master_password, context)
        .await?;
    let res = SigninUserResponse::new(&ctx.user_id);
    let ser_token = token.encode_token(&service_locator.config)?;
    Ok(HttpResponse::Ok()
        .append_header((ACCESS_TOKEN, ser_token.as_str()))
        .json(res))
}

#[post("/api/v1/auth/signout")]
pub async fn signout_user(
    service_locator: web::Data<ServiceLocator>,
    session: Session,
) -> Result<HttpResponse, Error> {
    let (claims, ctx) = get_session_context(&session)?;
    let _ = service_locator
        .user_service
        .signout_user(&ctx, &claims.login_session)
        .await?;
    let _ = session.remove(USER_SESSION_KEY);
    Ok(HttpResponse::Ok().finish())
}

#[get("/api/v1/users/{id}")]
pub async fn get_user(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
    session: Session,
) -> Result<HttpResponse, Error> {
    let id = path.into_inner();
    let (_, ctx) = get_session_context(&session)?;
    let (_, user) = service_locator.user_service.get_user(&ctx, &id).await?;
    Ok(HttpResponse::Ok().json(user))
}

#[delete("/api/v1/users/{id}")]
pub async fn delete_user(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
    session: Session,
) -> Result<HttpResponse, Error> {
    let id = path.into_inner();
    let (_, ctx) = get_session_context(&session)?;
    let _ = service_locator.user_service.delete_user(&ctx, &id).await?;
    let _ = session.remove(USER_SESSION_KEY);
    Ok(HttpResponse::Ok().finish())
}

#[put("/api/v1/users/{id}")]
pub async fn update_user(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
    payload: web::Json<UpdateUserRequest>,
    session: Session,
) -> Result<HttpResponse, Error> {
    let id = path.into_inner();
    let (_, ctx) = get_session_context(&session)?;
    let mut user = payload.to_user();
    user.user_id = id.clone();
    let _ = service_locator
        .user_service
        .update_user(&ctx, &user)
        .await?;
    Ok(HttpResponse::Ok().finish())
}
