use std::collections::HashMap;

use actix_session::Session;
use actix_web::{http, HttpRequest, HttpResponse, Responder, web};
use actix_web_lab::respond::Html;
use askama::Template;
use serde::Deserialize;
use crate::controller::models::Authenticated;

use crate::controller::USER_SESSION_KEY;
use crate::dao::models::CONTEXT_IP_ADDRESS;
use crate::domain::models::{SessionStatus, User};
use crate::locales::safe_localized_message;
use crate::service::locator::ServiceLocator;

#[derive(Template, Debug, Clone)]
#[template(path = "signin.html")]
struct Sigin<'a> {
    username: &'a str,
    signin_error: &'a str,
}

impl<'a> Sigin<'a> {
    fn new() -> Self {
        Self {
            username: "",
            signin_error: "",
        }
    }

    fn signin_error(err: &'a str, params: &'a SigninParams) -> Self {
        Self {
            username: params.username.as_str(),
            signin_error: err,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SigninParams {
    username: String,
    master_password: String,
}

#[derive(Template, Debug, Clone)]
#[template(path = "signup.html")]
struct Sigup<'a> {
    name: &'a str,
    username: &'a str,
    signup_error: &'a str,
}

impl<'a> Sigup<'a> {
    fn new() -> Self {
        Self {
            name: "",
            username: "",
            signup_error: "",
        }
    }

    fn signup_error(err: &'a str, params: &'a SignupParams) -> Self {
        Self {
            name: params.name.as_deref().unwrap_or(""),
            username: params.username.as_str(),
            signup_error: err,
        }
    }
}

/// Show signin page
pub async fn user_signin() -> actix_web::Result<impl Responder> {
    let html = Sigin::new().render().expect("template should be valid");

    // Create a response with the custom header
    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .insert_header(("X-Signin", "required"))
        .body(html))
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
        .auth_service
        .signin_user(&params.username.to_lowercase(), &params.master_password, None, context)
        .await {
        Ok((_, _user, token, session_status)) => {
            session.insert(USER_SESSION_KEY, (token.user_id, token.login_session))?;
            if session_status == SessionStatus::RequiresMFA {
                Ok(HttpResponse::Found().insert_header((http::header::LOCATION, "/ui/mfa_signin")).finish())
            } else {
                Ok(HttpResponse::Found().insert_header((http::header::LOCATION, "/")).finish())
            }
        }
        Err(err) => {
            let err_msg = err.to_string();
            let html = Sigin::signin_error(&err_msg, &params);
            Ok(HttpResponse::Ok().body(html.render().expect("could not render template")))
        }
    }
}


#[derive(Debug, Clone, Deserialize)]
pub struct SignupParams {
    name: Option<String>,
    username: String,
    master_password: String,
    confirm_master_password: Option<String>,
}

pub async fn user_signup() -> actix_web::Result<impl Responder> {
    let html = Sigup::new().render().expect("template should be valid");
    Ok(Html(html))
}

/// Handle Signup POST request
pub async fn handle_user_signup(
    req: HttpRequest,
    service_locator: web::Data<ServiceLocator>,
    params: web::Form<SignupParams>,
) -> actix_web::Result<HttpResponse> {
    if Some(params.master_password.clone()) != params.confirm_master_password {
        let err_msg = safe_localized_message("master-confirm-mismatch", None);
        let html = Sigup::signup_error(&err_msg, &params);
        return Ok(HttpResponse::Ok().body(html.render().expect("")));
    }

    let mut context = HashMap::new();
    if let Some(addr) = req.peer_addr() {
        context.insert(CONTEXT_IP_ADDRESS.into(), addr.ip().to_string());
    }

    let user = User::new(&params.username.to_lowercase(), params.name.clone(), None);
    match service_locator
        .user_service
        .register_user(&user, &params.master_password, context)
        .await {
        Ok(_) => {
            Ok(HttpResponse::Found().insert_header((http::header::LOCATION, "/ui/signin")).finish())
        }
        Err(err) => {
            let err_msg = err.to_string();
            let html = Sigup::signup_error(&err_msg, &params);
            Ok(HttpResponse::Ok().body(html.render().expect("")))
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
        .auth_service
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

#[derive(Template, Debug, Clone)]
#[template(path = "mfa_signin.html")]
struct MFASigin {
    ccr: String,
}

impl MFASigin {
    fn new(ccr: String) -> Self {
        Self {
            ccr,
        }
    }
}


/// Show mfa-signin page
pub async fn user_mfa_signin(
    service_locator: web::Data<ServiceLocator>,
    auth: Authenticated,
) -> actix_web::Result<impl Responder> {
    let ccr = service_locator.auth_service.start_key_authentication(&auth.context).await?;
    let ccr_json = serde_json::to_string(&ccr)?;
    let html = MFASigin::new(ccr_json).render().expect("template should be valid");
    Ok(Html(html))
}

#[derive(Template, Debug, Clone)]
#[template(path = "mfa_recover.html")]
struct MFARecover {}


/// Show mfa-recover page
pub async fn user_mfa_recover(
) -> actix_web::Result<impl Responder> {
    let html = MFARecover{}.render().expect("template should be valid");
    Ok(Html(html))
}

