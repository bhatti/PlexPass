use actix_web::{HttpResponse, Responder, Result, web, Error};
use actix_web_lab::respond::Html;
use askama::Template;
use serde_json::json;
use crate::controller::models::{Authenticated, GeneratePasswordRequest};
use crate::service::locator::ServiceLocator;

#[derive(Template)]
#[template(path = "generate_password.html")]
struct GeneratePasswordTemplate {
}

pub async fn generate_password_page(
) -> Result<impl Responder> {
    let html = GeneratePasswordTemplate{}.render().expect("could not find generate-password template");
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

pub async fn schedule_password_analysis(
    service_locator: web::Data<ServiceLocator>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let _ = service_locator
        .password_service
        .schedule_analyze_all_vault_passwords(&auth.context)
        .await?;
    Ok(HttpResponse::Accepted().finish())
}
