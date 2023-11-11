use actix_web::{web, HttpResponse, Error, HttpRequest};
use serde::Deserialize;
use crate::controller::models::Authenticated;
use crate::service::locator::ServiceLocator;
use crate::utils::is_private_ip;

#[derive(Deserialize)]
pub struct QueryParams {
    term: String,
}

pub(crate) async fn autocomplete_users(
    req: HttpRequest,
    query: web::Query<QueryParams>,
    service_locator: web::Data<ServiceLocator>,
    auth: Authenticated,
) -> Result<HttpResponse, Error>  {
    let mut results = vec![];
    // auto-complete is only enabled for local access
    if let Some(addr) = req.peer_addr() {
        if is_private_ip(addr.ip()) {
            results = service_locator.share_vault_account_service.lookup_usernames(&auth.context, &query.term).await?;
        } else {
            log::debug!("disabling auto-complete for {:?}", addr.ip().to_string());
        }
    }
    Ok(HttpResponse::Ok().json(results))
}