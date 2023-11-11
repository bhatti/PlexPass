use actix_web::{HttpResponse, Responder, Result, web, Error};
use actix_web_lab::respond::Html;
use askama::Template;

use crate::controller::models::{Authenticated};
use crate::domain::models::{Lookup, LookupKind};
use crate::service::locator::ServiceLocator;

#[derive(Template)]
#[template(path = "categories.html")]
struct CategoryTemplate {
    categories: Vec<Lookup>,
}

impl CategoryTemplate {
    fn new(categories: Vec<Lookup>) -> Self {
        Self {
            categories,
        }
    }
}

pub async fn categories_page(
    service_locator: web::Data<ServiceLocator>,
    auth: Authenticated,
) -> Result<impl Responder> {
    let categories : Vec<Lookup> = service_locator
        .lookup_service
        .get_lookups(&auth.context, LookupKind::CATEGORY)
        .await?;
    let html = CategoryTemplate::new(categories)
        .render().expect("could not find categories template");
    Ok(Html(html))
}

pub async fn create_category(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let category: String = path.into_inner();
    let lookup = Lookup::new(&auth.context.user_id, LookupKind::CATEGORY, &category);
    let _ = service_locator
        .lookup_service
        .create_lookup(&auth.context, &lookup)
        .await?;
    Ok(HttpResponse::Ok().finish())
}

pub async fn delete_category(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let category: String = path.into_inner();
    let _ = service_locator
        .lookup_service
        .delete_lookup(&auth.context, LookupKind::CATEGORY, &category)
        .await?;
    Ok(HttpResponse::Ok().finish())
}

