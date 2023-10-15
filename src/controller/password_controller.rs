use crate::service::locator::ServiceLocator;
use actix_web::{get, web, Error, HttpResponse};
use serde_json::json;

#[get("/api/v1/password/memorable")]
pub async fn generate_memorable_password(
    service_locator: web::Data<ServiceLocator>,
) -> Result<HttpResponse, Error> {
    let password = service_locator
        .password_service
        .generate_memorable_password()
        .await;
    let data = json!({
        "password": password,
    });
    Ok(HttpResponse::Ok().json(data))
}

#[get("/api/v1/password/random")]
pub async fn generate_random_password(
    service_locator: web::Data<ServiceLocator>,
) -> Result<HttpResponse, Error> {
    let password = service_locator
        .password_service
        .generate_random_password()
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

#[get("/api/v1/password/{password}/analyze")]
pub async fn analyze_password(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
) -> Result<HttpResponse, Error> {
    let password = path.into_inner();
    let analysis = service_locator
        .password_service
        .analyze_password(&password)
        .await?;
    Ok(HttpResponse::Ok().json(analysis))
}
