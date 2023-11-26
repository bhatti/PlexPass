use actix_web::{Responder, Result, web};
use actix_web_lab::respond::Html;
use askama::Template;
use serde::Deserialize;

use itertools::{Itertools};

use crate::controller::models::{Authenticated, VaultResponse};
use crate::domain::error::PassError;
use crate::domain::models::{AccountSummary, all_categories, LookupKind, top_categories};
use crate::service::locator::ServiceLocator;

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate<'a> {
    selected_vault_id: &'a str,
    q: &'a str,
    vaults: Vec<VaultResponse>,
    accounts: Vec<AccountSummary>,
    top_categories: Vec<String>,
    all_categories: Vec<String>,
    username: String,
    light_mode: bool,
}

impl<'a> IndexTemplate<'a> {
    fn new(
        selected_vault_id: &'a str,
        q: &'a str,
        vaults: Vec<VaultResponse>,
        accounts: Vec<AccountSummary>,
        username: &str,
        light_mode: bool,
        top_categories: Vec<String>,
        all_categories: Vec<String>, ) -> Self {
        Self {
            selected_vault_id,
            q,
            vaults,
            accounts,
            top_categories,
            all_categories,
            username: username.to_string(),
            light_mode,
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
        &vault.vault_id,
        &query.q.clone().unwrap_or_default(),
        vaults,
        accounts,
        &auth.context.username,
        auth.context.light_mode,
        top_categories,
        user_with_all_categories)
        .render().expect("could not find dashboard template");
    Ok(Html(html))
}
