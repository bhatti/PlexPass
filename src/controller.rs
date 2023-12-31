use actix_session::SessionExt;
use crate::controller::models::{Authenticated};
use crate::dao::models::{CONTEXT_IP_ADDRESS, UserContext};
use crate::domain::error::PassError;
use crate::domain::models::{LoginSession, PassConfig, PassResult, Roles, SessionStatus, USER_KEY_PARAMS_NAME, USER_SECRET_KEY_NAME, UserKeyParams, UserToken};
use crate::service::locator::ServiceLocator;
use actix_web::dev::ServiceRequest;
use actix_web::HttpMessage;
use actix_web::web::Data;

pub(crate) mod account_api_controller;
pub(crate) mod models;
pub(crate) mod password_api_controller;
pub(crate) mod user_api_controller;
pub(crate) mod vault_api_controller;
pub(crate) mod user_ui_controller;
pub(crate) mod auth_ui_controller;
pub(crate) mod auth_api_controller;
pub(crate) mod vault_ui_controller;
pub(crate) mod import_export_api_controller;
pub(crate) mod encryption_api_controller;
pub(crate) mod account_ui_controller;
pub(crate) mod share_ui_controller;
pub(crate) mod share_api_controller;
pub(crate) mod dashboard_ui_controller;
pub(crate) mod password_ui_controller;
pub(crate) mod categories_api_controller;
pub(crate) mod categories_ui_controller;
pub(crate) mod audit_api_controller;
pub(crate) mod audit_ui_controller;
pub(crate) mod otp_api_controller;
pub(crate) mod otp_ui_controller;
pub(crate) mod webauthn_ui_controller;
mod errors;

// Headers
pub const AUTHORIZATION: &str = "Authorization";
pub const USER_SESSION_KEY: &str = "USER_SESSION_KEY";

pub fn verify_session_cookie(
    req: &ServiceRequest,
    service_locator: &Data<ServiceLocator>,
) -> PassResult<SessionStatus> {
    // Check if the session contains user-token
    if let Ok(Some((user_id, session_id))) = req.get_session().get::<(String, String)>(USER_SESSION_KEY) {
        validate_database_session(req, service_locator, &user_id, &session_id)
    } else {
        Ok(SessionStatus::Invalid)
    }
}

pub fn verify_token_header(
    req: &ServiceRequest,
    service_locator: &Data<ServiceLocator>,
) -> PassResult<SessionStatus> {
    if let Some(claims) = get_token_header(req, &service_locator.config) {
        validate_database_session(req, service_locator, &claims.user_id, &claims.login_session)
    } else {
        Ok(SessionStatus::Invalid)
    }
}

// claims: &UserToke
fn validate_database_session(
    req: &ServiceRequest,
    service_locator: &Data<ServiceLocator>,
    user_id: &str,
    session_id: &str) -> PassResult<SessionStatus> {
    let session = service_locator.login_session_repository.get(user_id, session_id)?;
    let mut ctx = build_user_context_from_session(service_locator, &session)?;
    if let Some(addr) = req.peer_addr() {
        ctx.attributes.insert(CONTEXT_IP_ADDRESS.into(), addr.ip().to_string());
    };
    let claims = UserToken::from_session(&service_locator.config, &session);

    log::debug!("validate_database_session user {} session {} status {:?}", user_id, session_id, session.check_status());
    match session.check_status() {
        SessionStatus::Valid => {
            req.extensions_mut()
                .insert::<Authenticated>(Authenticated::new(claims.clone(), ctx, false));
            Ok(SessionStatus::Valid)
        }
        SessionStatus::Invalid => {
            Ok(SessionStatus::Invalid)
        }
        SessionStatus::RequiresMFA => {
            // temporary credentials to validate MFA
            req.extensions_mut()
                .insert::<Authenticated>(Authenticated::new(claims.clone(), ctx, true));
            Ok(SessionStatus::RequiresMFA)
        }
    }
}

// Retrieving secret key from HSM if exists and is not empty
// Empty implies user session is not active
fn get_secret_key(service_locator: &Data<ServiceLocator>, username: &str) -> PassResult<String> {
    let secret_key = service_locator
        .hsm_store
        .get_property(username, USER_SECRET_KEY_NAME)?;
    if secret_key.is_empty() {
        return Err(PassError::validation(
            "secret-key not available in active session",
            None,
        ));
    }
    Ok(secret_key)
}

// build user-context from user-token and HSM
fn build_user_context_from_session(
    service_locator: &Data<ServiceLocator>,
    session: &LoginSession,
) -> PassResult<UserContext> {
    // Retrieving salt/pepper from HSM
    let key_params = UserKeyParams::deserialize(
        &service_locator
            .hsm_store
            .get_property(&session.username, USER_KEY_PARAMS_NAME)?,
    )?;
    let ctx = UserContext::new(
        &session.username,
        &key_params.user_id,
        Some(Roles::new(session.roles)),
        session.light_mode,
        &key_params.pepper,
        &get_secret_key(service_locator, &session.username)?,
        service_locator.config.hash_algorithm(),
        service_locator.config.crypto_algorithm(),
    );
    Ok(ctx)
}

pub fn get_token_header(req: &ServiceRequest, config: &PassConfig) -> Option<UserToken> {
    if let Some(auth_header) = req.headers().get(AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("bearer") || auth_str.starts_with("Bearer") {
                let token = auth_str[6..auth_str.len()].trim();
                match UserToken::decode_token(config, token.to_string()) {
                    Ok(token_data) => {
                        return Some(token_data.claims);
                    }
                    Err(err) => {
                        log::warn!("failed to decode token {} due to {}", token, err);
                    }
                };
            }
        }
    }
    None
}
