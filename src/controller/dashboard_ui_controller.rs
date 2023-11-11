use actix_web::{Responder, Result, web};
use actix_web_lab::respond::Html;
use askama::Template;

use crate::controller::models::{Authenticated, VaultResponse};
use crate::domain::models::{Vault, VaultAnalysis};
use crate::service::locator::ServiceLocator;

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTemplate {
    total_vaults: usize,
    summary: VaultAnalysis,
    vaults: Vec<VaultResponse>,
}

impl DashboardTemplate {
    fn new(summary: VaultAnalysis, vaults: Vec<Vault>) -> Self {
        let total_vaults = vaults.len();
        let vaults = vaults.into_iter()
            .filter(|v| v.total_accounts() > 0)
            .map(|v| VaultResponse::new(&v))
            .collect();
        Self {
            total_vaults,
            summary,
            vaults,
        }
    }
}


pub async fn dashboard_page(
    service_locator: web::Data<ServiceLocator>,
    auth: Authenticated,
) -> Result<impl Responder> {
    let partial_vaults: Vec<Vault> = service_locator
        .vault_service
        .get_user_vaults(&auth.context)
        .await?;
    // load full vaults for analysis
    let mut full_vaults = vec![];
    for vault in &partial_vaults {
        full_vaults.push(service_locator.vault_service.get_vault(&auth.context, &vault.vault_id).await?);
    }

    let mut summary = VaultAnalysis::new();
    for vault in &full_vaults {
        summary.add(vault.analysis.clone());
    }
    let html = DashboardTemplate::new(summary, full_vaults)
        .render().expect("could not find dashboard template");
    Ok(Html(html))
}
