use actix_web::{Error, HttpRequest, HttpResponse, post, web};
use std::collections::HashMap;
use serde::Serialize;
use crate::controller::models::{Authenticated, SigninUserRequest, SigninUserResponse, SignupUserRequest, SignupUserResponse};
use crate::dao::models::CONTEXT_IP_ADDRESS;
use crate::domain::models::UserToken;
use crate::service::locator::ServiceLocator;

const ACCESS_TOKEN: &str = "ACCESS_TOKEN";

#[post("/api/v1/auth/signup")]
pub async fn signup_user(
    req: HttpRequest,
    service_locator: web::Data<ServiceLocator>,
    payload: web::Json<SignupUserRequest>,
) -> Result<HttpResponse, Error> {
    let context = build_context_with_ip_address(req);
    let (ctx, token) = service_locator
        .user_service
        .signup_user(&payload.to_user(), &payload.master_password, context)
        .await?;
    let res = SignupUserResponse::new(&ctx.user_id);
    ok_response_with_token(&service_locator, &token, res)
}

#[post("/api/v1/auth/signin")]
pub async fn signin_user(
    req: HttpRequest,
    service_locator: web::Data<ServiceLocator>,
    payload: web::Json<SigninUserRequest>,
) -> Result<HttpResponse, Error> {
    let context = build_context_with_ip_address(req);
    let (ctx, _user, token) = service_locator
        .user_service
        .signin_user(&payload.username, &payload.master_password, context)
        .await?;
    let res = SigninUserResponse::new(&ctx.user_id);
    ok_response_with_token(&service_locator, &token, res)
}

#[post("/api/v1/auth/signout")]
pub async fn signout_user(
    service_locator: web::Data<ServiceLocator>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let _ = service_locator
        .user_service
        .signout_user(&auth.context, &auth.user_token.login_session)
        .await?;
    Ok(HttpResponse::Ok().finish())
}

fn build_context_with_ip_address(req: HttpRequest) -> HashMap<String, String> {
    let mut context = HashMap::new();
    if let Some(addr) = req.peer_addr() {
        context.insert(CONTEXT_IP_ADDRESS.into(), addr.ip().to_string());
    }
    context
}

fn ok_response_with_token<T: Serialize>(
    service_locator: &ServiceLocator,
    token: &UserToken, res: T) -> Result<HttpResponse, Error> {
    let ser_token = token.encode_token(&service_locator.config)?;
    Ok(HttpResponse::Ok()
        .append_header((ACCESS_TOKEN, ser_token.as_str()))
        .json(res))
}

