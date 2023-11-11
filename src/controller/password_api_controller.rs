use crate::service::locator::ServiceLocator;
use actix_web::{get, post, web, Error, HttpResponse};
use serde_json::json;
use crate::controller::models::{Authenticated, GeneratePasswordRequest};

#[post("/api/v1/password/memorable")]
pub async fn generate_memorable_password(
    service_locator: web::Data<ServiceLocator>,
    mut payload: web::Json<GeneratePasswordRequest>,
) -> Result<HttpResponse, Error> {
    payload.random = Some(false);
    let password = service_locator
        .password_service
        .generate_password(&payload.to_password_policy())
        .await;
    let data = json!({
        "password": password,
    });
    Ok(HttpResponse::Ok().json(data))
}

#[post("/api/v1/password/random")]
pub async fn generate_random_password(
    service_locator: web::Data<ServiceLocator>,
    mut payload: web::Json<GeneratePasswordRequest>,
) -> Result<HttpResponse, Error> {
    payload.random = Some(true);
    let password = service_locator
        .password_service
        .generate_password(&payload.to_password_policy())
        .await;
    let data = json!({
        "password": password,
    });
    Ok(HttpResponse::Ok().json(data))
}

#[get("/api/v1/password/{password}/compromised")]
pub async fn password_compromised(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
) -> Result<HttpResponse, Error> {
    let password = path.into_inner();
    let ok = service_locator
        .password_service
        .password_compromised(&password)
        .await?;
    let data = json!({
        "compromised": ok,
    });
    Ok(HttpResponse::Ok().json(data))
}

#[get("/api/v1/emails/{email}/compromised")]
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

#[get("/api/v1/password/{password}/strength")]
pub async fn check_password_strength(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
) -> Result<HttpResponse, Error> {
    let password = path.into_inner();
    let info = service_locator
        .password_service
        .password_info(&password)
        .await?;
    Ok(HttpResponse::Ok().json(info))
}

#[post("/api/v1/password/analyze_all_passwords")]
pub async fn analyze_all_passwords(
    service_locator: web::Data<ServiceLocator>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let _ = service_locator
        .password_service
        .schedule_analyze_all_vault_passwords(&auth.context)
        .await?;
    Ok(HttpResponse::Accepted().finish())
}
