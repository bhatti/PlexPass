use crate::controller::models::get_token_header;
use crate::dao::models::UserContext;
use crate::domain::error::PassError;
use crate::domain::models::{
    PassResult, Roles, UserKeyParams, UserToken, USER_KEY_PARAMS_NAME, USER_SECRET_KEY_NAME,
};
use crate::service::locator::ServiceLocator;
use actix_session::Session;
use actix_web::dev::ServiceRequest;
use actix_web::web::Data;

pub(crate) mod account_controller;
pub mod api_startup;
mod errors;
mod metrics_controller;
pub(crate) mod models;
mod password_controller;
pub(crate) mod user_controller;
pub(crate) mod vault_controller;

pub(crate) const USER_SESSION_KEY: &str = "USER_SESSION_KEY";

// Helper functions for session management
pub fn get_session_context(session: &Session) -> PassResult<(UserToken, UserContext)> {
    Ok(session
        .get::<(UserToken, UserContext)>(USER_SESSION_KEY)?
        .ok_or(PassError::authentication("no token in session"))?)
}

pub fn verify_token_header(
    req: &ServiceRequest,
    service_locator: &Data<ServiceLocator>,
    session: &Session,
) -> PassResult<bool> {
    if let Some(claims) = get_token_header(req, &service_locator.config) {
        let _ = service_locator
            .login_session_repository
            .get(&claims.login_session)?;
        let ctx = build_user_context_from_token(service_locator, &claims)?;
        let _ = session.insert(USER_SESSION_KEY, (claims, ctx))?;
        return Ok(true);
    }
    Ok(false)
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
fn build_user_context_from_token(
    service_locator: &Data<ServiceLocator>,
    token: &UserToken,
) -> PassResult<UserContext> {
    // Retrieving salt/pepper from HSM
    let key_params = UserKeyParams::deserialize(
        &service_locator
            .hsm_store
            .get_property(&token.username, USER_KEY_PARAMS_NAME)?,
    )?;
    let ctx = UserContext::new(
        &token.username,
        &key_params.user_id,
        Roles::new(token.roles.clone()),
        &key_params.pepper,
        &get_secret_key(service_locator, &token.username)?,
        service_locator.config.hash_algorithm(),
        service_locator.config.crypto_algorithm(),
    );
    Ok(ctx)
}
