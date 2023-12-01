use std::fs;
use actix_multipart::Multipart;
use actix_web::{Error, HttpResponse, Responder, Result, web};
use actix_web_lab::respond::Html;
use askama::Template;
use serde::Deserialize;

use itertools::{Itertools};
use uuid::Uuid;

use crate::controller::models::{Authenticated, VaultResponse};
use crate::domain::error::PassError;
use crate::domain::models::{AccountSummary, all_categories, LookupKind, top_categories, Vault};
use crate::service::locator::ServiceLocator;

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate<'a> {
    selected_vault: Vault,
    q: &'a str,
    vaults: Vec<VaultResponse>,
    accounts: Vec<AccountSummary>,
    top_categories: Vec<String>,
    all_categories: Vec<String>,
    username: String,
    light_mode: bool,
    build_version: &'a str,
    build_date: &'a str,
}

impl<'a> IndexTemplate<'a> {
    fn new(
        selected_vault: Vault,
        q: &'a str,
        vaults: Vec<VaultResponse>,
        accounts: Vec<AccountSummary>,
        username: &str,
        light_mode: bool,
        top_categories: Vec<String>,
        all_categories: Vec<String>,
        build_version: &'a str,
        build_date: &'a str,
    ) -> Self {
        Self {
            selected_vault,
            q,
            vaults,
            accounts,
            top_categories,
            all_categories,
            username: username.to_string(),
            light_mode,
            build_version,
            build_date,
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct HomeParams {
    selected_vault_id: Option<String>,
    q: Option<String>,
}


pub async fn home_page(
    service_locator: web::Data<ServiceLocator>,
    auth: Authenticated,
    query: web::Query<HomeParams>,
) -> Result<impl Responder> {
    let vaults: Vec<VaultResponse> = service_locator
        .vault_service
        .get_user_vaults(&auth.context)
        .await?
        .iter()
        .map(VaultResponse::new)
        .collect();
    let selected_vault_id = query.selected_vault_id.clone().unwrap_or(vaults[0].vault_id.clone());
    let selected_vault = vaults.iter()
        .find_or_first(|v| v.vault_id == selected_vault_id)
        .ok_or(PassError::not_found("could not find vault"))?;
    let vault = service_locator.vault_service.get_vault(&auth.context, &selected_vault.vault_id).await?;
    let accounts: Vec<AccountSummary> = if let Some(q) = query.q.clone() {
        vault.account_summaries().into_iter().filter(|a| a.matches(&q)).collect()
    } else {
        vault.account_summaries()
    };
    let user_with_all_categories = service_locator.lookup_service.get_categories(&auth.context).await?;
    let top_categories = if user_with_all_categories.len() == all_categories().len() {
        top_categories()
    } else {
        let mut user_categories = service_locator.lookup_service
            .get_lookups(&auth.context, LookupKind::CATEGORY).await?
            .into_iter().map(|l| l.name).collect::<Vec<String>>();
        if user_categories.len() > 5 {
            user_categories = user_categories[0..5].to_vec().iter().map(|s| s.to_string()).collect();
        }
        user_categories.sort();
        user_categories
    };
    let html = IndexTemplate::new(
        vault,
        &query.q.clone().unwrap_or_default(),
        vaults,
        accounts,
        &auth.context.username,
        auth.context.light_mode,
        top_categories,
        user_with_all_categories,
        crate::VERSION,
        crate::BUILD_DATE)
        .render().expect("could not find dashboard template");
    Ok(Html(html))
}

pub async fn create_vault(
    service_locator: web::Data<ServiceLocator>,
    mut payload: Multipart,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let mut vault = Vault::from_multipart(&mut payload, &auth.context.user_id,
                                          &service_locator.config).await?;
    vault.vault_id = Uuid::new_v4().to_string();
    vault.version = 0;
    let _ = service_locator
        .vault_service
        .create_vault(&auth.context, &vault)
        .await?;
    Ok(HttpResponse::Ok().json(VaultResponse::new(&vault)))
}

pub async fn update_vault(
    path: web::Path<String>,
    service_locator: web::Data<ServiceLocator>,
    mut payload: Multipart,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let vault_id = path.into_inner();
    let mut vault = Vault::from_multipart(&mut payload, &auth.context.user_id,
                                          &service_locator.config).await?;
    vault.vault_id = vault_id;
    let _ = service_locator
        .vault_service
        .update_vault(&auth.context, &vault)
        .await?;
    Ok(HttpResponse::Ok().finish())
}

pub async fn delete_vault(
    path: web::Path<String>,
    service_locator: web::Data<ServiceLocator>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let vault_id = path.into_inner();
    let _ = service_locator
        .vault_service
        .delete_vault(&auth.context, &vault_id)
        .await?;
    Ok(HttpResponse::Ok().finish())
}

pub async fn get_vault_icon(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>) -> impl Responder {
    let vault_id = path.into_inner();
    let file_path = service_locator.config.build_data_file(
        &format!("vault_{}.png", &vault_id));
    match fs::read(file_path) {
        Ok(data) => HttpResponse::Ok().content_type("image/png").body(data),
        Err(_) => HttpResponse::NotFound().finish(),
    }
}
