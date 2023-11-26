use actix_web::{HttpResponse, Responder, Result, web, Error};
use actix_web_lab::respond::Html;
use askama::Template;
use serde_json::json;
use crate::controller::models::{Authenticated, GeneratePasswordRequest};
use crate::service::locator::ServiceLocator;

#[derive(Template)]
#[template(path = "password_tools.html")]
struct GeneratePasswordTemplate {
    light_mode: bool,
}

pub async fn generate_password_page(
    auth: Authenticated,
) -> Result<impl Responder> {
    let html = GeneratePasswordTemplate{
        light_mode: auth.context.light_mode,
    }.render().expect("could not find generate-password template");
    Ok(Html(html))
}

pub async fn generate_password(
    service_locator: web::Data<ServiceLocator>,
    payload: web::Query<GeneratePasswordRequest>,
) -> Result<HttpResponse, Error> {
    let password = service_locator
        .password_service
        .generate_password(&payload.to_password_policy())
        .await;
    let data = json!({
        "password": password,
    });
    Ok(HttpResponse::Ok().json(data))
}

pub async fn password_compromised(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
) -> Result<HttpResponse, Error> {
    let password = path.into_inner();
    let compromised = service_locator
        .password_service
        .password_compromised(&password)
        .await?;
    let mut info = service_locator
        .password_service
        .password_info(&password)
        .await?;
    info.compromised = compromised;
    Ok(HttpResponse::Ok().json(info))
}

pub async fn email_compromised(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
) -> Result<HttpResponse, Error> {
    let email = path.into_inner();
    let res = service_locator
        .password_service
        .email_compromised(&email)
        .await?;
    let data = json!({
        "result": res,
    });
    Ok(HttpResponse::Ok().json(data))
}



pub async fn schedule_password_analysis(
    service_locator: web::Data<ServiceLocator>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    service_locator
        .password_service
        .schedule_analyze_all_vault_passwords(&auth.context)
        .await?;
    Ok(HttpResponse::Accepted().finish())
}
