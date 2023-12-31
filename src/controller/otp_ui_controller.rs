use actix_web::{Error, HttpResponse, web};
use serde_json::json;
use crate::controller::models::{GenerateOTPRequest};
use crate::service::locator::ServiceLocator;

pub async fn generate_otp(
    service_locator: web::Data<ServiceLocator>,
    payload: web::Query<GenerateOTPRequest>,
) -> Result<HttpResponse, Error> {
    let code = service_locator.otp_service.generate_otp(
        &payload.otp_secret
    ).await?;
    let data = json!({
        "otp_code": code,
    });
    Ok(HttpResponse::Ok().json(data))
}

