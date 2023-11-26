use actix_multipart::Multipart;
use actix_web::{HttpRequest, HttpResponse, Responder, Result, Error, web, http};
use actix_web_lab::respond::Html;
use askama::Template;
use serde::Deserialize;
use serde_json::json;
use crate::controller::models::{Authenticated};
use crate::domain::models::{DEFAULT_LOCALES, User, UserLocale, UserToken};
use crate::service::locator::ServiceLocator;
use crate::utils::is_private_ip;

#[derive(Deserialize)]
pub struct QueryParams {
    term: String,
}

pub(crate) async fn autocomplete_users(
    req: HttpRequest,
    query: web::Query<QueryParams>,
    service_locator: web::Data<ServiceLocator>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let mut results = vec![];
    // auto-complete is only enabled for local access
    if let Some(addr) = req.peer_addr() {
        if is_private_ip(addr.ip()) {
            results = service_locator.share_vault_account_service.lookup_usernames(&auth.context, &query.term).await?;
        } else {
            log::debug!("disabling auto-complete for {:?}", addr.ip().to_string());
        }
    }
    Ok(HttpResponse::Ok().json(results))
}

pub(crate) async fn generate_api_token(
    service_locator: web::Data<ServiceLocator>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let token = UserToken::from_context(
        &auth.user_token.login_session,
        &auth.context,
        service_locator.config.jwt_max_age_minutes).encode_token(&service_locator.config)?;
    let data = json!({
        "token": token,
    });
    Ok(HttpResponse::Ok().json(data))
}

#[derive(Template)]
#[template(path = "user_profile.html")]
struct UserProfileTemplate {
    user: User,
    locales: Vec<UserLocale>,
    light_mode: bool,
}

impl UserProfileTemplate {
    fn new(user: User) -> Self {
        let light_mode = user.light_mode.unwrap_or_default();
        Self {
            user,
            locales: DEFAULT_LOCALES.to_vec(),
            light_mode,
        }
    }
}

pub async fn user_profile(
    service_locator: web::Data<ServiceLocator>,
    auth: Authenticated,
) -> Result<impl Responder> {
    let (_, user) = service_locator.user_service.get_user(
        &auth.context, &auth.context.user_id).await?;
    let html = UserProfileTemplate::new(user).render().expect("could not find user-profile template");
    Ok(Html(html))
}

pub async fn update_user_profile(
    service_locator: web::Data<ServiceLocator>,
    mut payload: Multipart,
    auth: Authenticated,
) -> Result<impl Responder> {
    let user = User::from_multipart(&mut payload,
                                    &auth.context.user_id,
                                    &auth.context.username,
                                    &auth.context.roles).await?;
    let _ = service_locator
        .user_service
        .update_user(&auth.context, &user)
        .await?;
    if user.light_mode.unwrap_or_default() != auth.context.light_mode {
        let _ = service_locator.auth_service.update_light_mode(
            &auth.context, &auth.user_token.login_session, user.light_mode.unwrap_or_default()).await?;
    }
    Ok(HttpResponse::Found().insert_header((http::header::LOCATION, "/ui/users/profile")).finish())
}

