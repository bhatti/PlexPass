use crate::service::locator::ServiceLocator;
use actix_web::{post, web, Error, HttpResponse};
use actix_web::web::Bytes;
use serde_json::json;
use crate::domain::models::{EncodingScheme};
use serde::{Deserialize};

#[derive(Deserialize)]
pub struct OptPasswordInfo {
    password: Option<String>,
}

#[post("/api/v1/encryption/generate_keys")]
pub async fn generate_private_public_keys(
    service_locator: web::Data<ServiceLocator>,
    info: web::Json<OptPasswordInfo>,
) -> Result<HttpResponse, Error> {
    let (sk, pk) = service_locator.encryption_service.generate_private_public_keys(info.password.clone())?;
    let data = json!({
        "secret_key": sk,
        "public_key": pk,
    });
    Ok(HttpResponse::Ok().json(data))
}


#[post("/api/v1/encryption/asymmetric_encrypt/{pk}")]
pub async fn asymmetric_encrypt(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
    body: Bytes,
) -> Result<HttpResponse, Error> {
    let pk = path.into_inner();
    let res = service_locator.encryption_service.asymmetric_encrypt(
        &pk,
        (&body).to_vec(),
        EncodingScheme::Base64)?;
    Ok(HttpResponse::Ok().body(Bytes::from(res)))
}

#[post("/api/v1/encryption/asymmetric_decrypt/{sk}")]
pub async fn asymmetric_decrypt(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
    body: Bytes,
) -> Result<HttpResponse, Error> {
    let sk = path.into_inner();
    let res = service_locator.encryption_service.asymmetric_decrypt(
                          &sk,
                          (&body).to_vec(),
                          EncodingScheme::Base64)?;
    Ok(HttpResponse::Ok().body(Bytes::from(res)))
}


#[post("/api/v1/encryption/symmetric_encrypt/{secret}")]
pub async fn symmetric_encrypt(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
    body: Bytes,
) -> Result<HttpResponse, Error> {
    let secret = path.into_inner();
    let res = service_locator.encryption_service.symmetric_encrypt(
        "",
        "",
        &secret,
        (&body).to_vec(),
        EncodingScheme::Base64)?;
    Ok(HttpResponse::Ok().body(Bytes::from(res)))
}

#[post("/api/v1/encryption/symmetric_decrypt/{secret}")]
pub async fn symmetric_decrypt(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
    body: Bytes,
) -> Result<HttpResponse, Error> {
    let secret = path.into_inner();
    let res = service_locator.encryption_service.symmetric_decrypt(
        "",
        &secret,
        (&body).to_vec(),
        EncodingScheme::Base64)?;
    Ok(HttpResponse::Ok().body(Bytes::from(res)))
}

