use actix_web::{Error, HttpRequest, HttpResponse, post, Responder, web};
use std::collections::HashMap;
use serde::Serialize;
use crate::controller::models::{Authenticated, QueryRecoveryCode, SigninUserRequest, SigninUserResponse, SignupUserRequest, SignupUserResponse};
use crate::dao::models::CONTEXT_IP_ADDRESS;
use crate::domain::error::PassError;
use crate::domain::models::{SessionStatus, UserToken};
use crate::service::locator::ServiceLocator;

const ACCESS_TOKEN: &str = "ACCESS_TOKEN";

#[post("/api/v1/auth/signup")]
pub async fn signup_user(
    req: HttpRequest,
    service_locator: web::Data<ServiceLocator>,
    payload: web::Json<SignupUserRequest>,
) -> Result<HttpResponse, Error> {
    let context = build_context_with_ip_address(req);
    let ctx = service_locator
        .user_service
        .register_user(&payload.to_user(), &payload.master_password, context)
        .await?;
    let res = SignupUserResponse::new(&ctx.user_id);
    Ok(HttpResponse::Ok()
        .json(res))
}

#[post("/api/v1/auth/signin")]
pub async fn signin_user(
    req: HttpRequest,
    service_locator: web::Data<ServiceLocator>,
    payload: web::Json<SigninUserRequest>,
) -> Result<HttpResponse, Error> {
    let context = build_context_with_ip_address(req);
    let (ctx, _user, token, session_status) = service_locator
        .auth_service
        .signin_user(&payload.username.to_lowercase(), &payload.master_password, payload.otp_code, context)
        .await?;
    if session_status == SessionStatus::RequiresMFA {
        return Err(
            Error::from(
                PassError::authentication("signin requires multi-factor authentication, please add parameter for otp_code based that can be seen form the Web application.")));
    }
    let res = SigninUserResponse::new(&ctx.user_id);
    ok_response_with_token(&service_locator, &token, res)
}

#[post("/api/v1/auth/signout")]
pub async fn signout_user(
    service_locator: web::Data<ServiceLocator>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    service_locator
        .auth_service
        .signout_user(&auth.context, &auth.user_token.login_session)
        .await?;
    Ok(HttpResponse::Ok().finish())
}

#[post("/api/v1/auth/reset_mfa")]
pub async fn recover_mfa(
    service_locator: web::Data<ServiceLocator>,
    params: web::Json<QueryRecoveryCode>,
    auth: Authenticated,
) -> Result<impl Responder, Error> {
    service_locator.auth_service.reset_mfa_keys(
        &auth.context, &params.recovery_code, &auth.user_token.login_session).await?;
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

