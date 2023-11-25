use actix_web::{Error, HttpResponse, post, web};
use serde_json::json;
use crate::controller::models::{Authenticated, GenerateOTPRequest};
use crate::service::locator::ServiceLocator;

#[post("/api/v1/otp/generate")]
pub async fn generate_otp(
    service_locator: web::Data<ServiceLocator>,
    payload: web::Json<GenerateOTPRequest>,
) -> Result<HttpResponse, Error> {
    let code = service_locator.otp_service.generate_otp(
        &payload.otp_secret
    ).await?;
    let data = json!({
        "otp_code": code,
    });
    Ok(HttpResponse::Ok().json(data))
}

#[post("/api/v1/users/otp/generate")]
pub async fn generate_user_otp(
    service_locator: web::Data<ServiceLocator>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let code = service_locator.user_service.generate_user_otp(
        &auth.context).await?;
    let data = json!({
        "otp_code": code,
    });
    Ok(HttpResponse::Ok().json(data))
}

