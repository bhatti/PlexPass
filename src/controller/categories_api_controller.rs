use crate::controller::models::{Authenticated, CreateCategoryRequest};
use crate::service::locator::ServiceLocator;
use actix_web::{delete, get, post, web, Error, HttpResponse};
use crate::domain::models::{LookupKind};

#[post("/api/v1/categories")]
pub async fn create_category(
    service_locator: web::Data<ServiceLocator>,
    payload: web::Json<CreateCategoryRequest>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let lookup = payload.to_lookup(&auth.context.user_id);
    let _ = service_locator
        .lookup_service
        .create_lookup(&auth.context, &lookup)
        .await?;
    Ok(HttpResponse::Ok().finish())
}

#[get("/api/v1/categories")]
pub async fn get_categories(
    service_locator: web::Data<ServiceLocator>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let categories: Vec<String> = service_locator
        .lookup_service
        .get_lookups(&auth.context, LookupKind::CATEGORY)
        .await?
        .into_iter()
        .map(|l| l.name.to_string())
        .collect();
    Ok(HttpResponse::Ok().json(categories))
}

#[delete("/api/v1/categories/{name}")]
pub async fn delete_category(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let name = path.into_inner();
    let _ = service_locator
        .lookup_service
        .delete_lookup(&auth.context, LookupKind::CATEGORY, &name)
        .await?;
    Ok(HttpResponse::Ok().finish())
}
