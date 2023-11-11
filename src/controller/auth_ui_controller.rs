use std::collections::HashMap;

use actix_session::Session;
use actix_web::{http, HttpRequest, HttpResponse, Responder, web};
use actix_web_lab::respond::Html;
use askama::Template;
use serde::Deserialize;
use crate::controller::models::Authenticated;

use crate::controller::USER_SESSION_KEY;
use crate::dao::models::CONTEXT_IP_ADDRESS;
use crate::domain::models::User;
use crate::locales::safe_localized_message;
use crate::service::locator::ServiceLocator;

#[derive(Template, Debug, Clone)]
#[template(path = "signin.html")]
struct Sigin<'a> {
    tab_index: usize,
    name: &'a str,
    username: &'a str,
    signin_error: &'a str,
    signup_error: &'a str,
}

impl<'a> Sigin<'a> {
    fn new() -> Self {
        Self {
            tab_index: 0,
            name: "",
            username: "",
            signin_error: "",
            signup_error: "",
        }
    }

    fn signin_error(err: &'a str, params: &'a SigninParams) -> Self {
        Self {
            tab_index: 0,
            name: params.name.as_deref().unwrap_or(""),
            username: params.username.as_str(),
            signin_error: err,
            signup_error: "",
        }
    }

    fn signup_error(err: &'a str, params: &'a SigninParams) -> Self {
        Self {
            tab_index: 1,
            name: params.name.as_deref().unwrap_or(""),
            username: params.username.as_str(),
            signin_error: "",
            signup_error: err,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SigninParams {
    name: Option<String>,
    username: String,
    master_password: String,
    confirm_master_password: Option<String>,
}

pub async fn user_signin() -> actix_web::Result<impl Responder> {
    let html = Sigin::new().render().expect("template should be valid");
    Ok(Html(html))
}

/// Handle Signin POST request
pub async fn handle_user_signin(
    req: HttpRequest,
    service_locator: web::Data<ServiceLocator>,
    params: web::Form<SigninParams>,
    session: Session,
) -> actix_web::Result<impl Responder> {
    let mut context = HashMap::new();
    if let Some(addr) = req.peer_addr() {
        context.insert(CONTEXT_IP_ADDRESS.into(), addr.ip().to_string());
    }

    match service_locator
        .user_service
        .signin_user(&params.username, &params.master_password, context)
        .await {
        Ok((_, _, token)) => {
            let _ = session.insert(USER_SESSION_KEY, token)?;
            Ok(HttpResponse::Found().insert_header((http::header::LOCATION, "/")).finish())
        }
        Err(err) => {
            let err_msg = err.to_string();
            let html = Sigin::signin_error(&err_msg, &params);
            Ok(HttpResponse::Ok().body(html.render().expect("could not render template")))
        }
    }
}

/// Handle Signout GET request
pub async fn handle_user_signout(
    service_locator: web::Data<ServiceLocator>,
    auth: Authenticated,
    session: Session,
) -> actix_web::Result<impl Responder> {
    match service_locator
        .user_service
        .signout_user(&auth.context, &auth.user_token.login_session)
        .await {
        Ok(_) => {
            let _ = session.remove(USER_SESSION_KEY);
        }
        Err(err) => {
            log::warn!("could not logout {:?}", err);
        }
    }
    Ok(HttpResponse::Found().insert_header((http::header::LOCATION, "/")).finish())
}

/// Handle Signup POST request
pub async fn handle_user_signup(
    req: HttpRequest,
    service_locator: web::Data<ServiceLocator>,
    params: web::Form<SigninParams>,
    session: Session,
) -> actix_web::Result<HttpResponse> {
    if Some(params.master_password.clone()) != params.confirm_master_password {
        let err_msg = safe_localized_message("master-confirm-mismatch", None);
        let html = Sigin::signup_error(&err_msg, &params);
        return Ok(HttpResponse::Ok().body(html.render().expect("")));
    }

    let mut context = HashMap::new();
    if let Some(addr) = req.peer_addr() {
        context.insert(CONTEXT_IP_ADDRESS.into(), addr.ip().to_string());
    }

    let user = User::new(&params.username, params.name.clone(), None);
    match service_locator
        .user_service
        .signup_user(&user, &params.master_password, context)
        .await {
        Ok((_ctx, token)) => {
            let _ = session.insert(USER_SESSION_KEY, token)?;
            Ok(HttpResponse::Found().insert_header((http::header::LOCATION, "/")).finish())
        }
        Err(err) => {
            let err_msg = err.to_string();
            let html = Sigin::signup_error(&err_msg, &params);
            Ok(HttpResponse::Ok().body(html.render().expect("")))
        }
    }
}
