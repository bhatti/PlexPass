use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use prometheus::Registry;

use crate::dao::models::UserContext;
use crate::dao::VaultRepository;
use crate::domain::error::PassError;
use crate::domain::models::{AccountSummary, PassConfig, PassResult, Vault};
use crate::service::VaultService;
use crate::utils::metrics::PassMetrics;

#[derive(Clone)]
pub(crate) struct VaultServiceImpl {
    config: PassConfig,
    vault_repository: Arc<dyn VaultRepository + Send + Sync>,
    metrics: PassMetrics,
}

impl VaultServiceImpl {
    pub(crate) fn new(
        config: &PassConfig,
        vault_repository: Arc<dyn VaultRepository + Send + Sync>,
        registry: &Registry,
    ) -> PassResult<Self> {
        Ok(Self {
            config: config.clone(),
            vault_repository,
            metrics: PassMetrics::new("vault_service", registry)?,
        })
    }
}

#[async_trait]
impl VaultService for VaultServiceImpl {
    async fn create_vault(&self, ctx: &UserContext, vault: &Vault) -> PassResult<usize> {
        let _ = self.metrics.new_metric("create_vault");
        match self.vault_repository.create(ctx, vault).await {
            Ok(size) => {
                Ok(size)
            }
            Err(err) => {
                if let PassError::DuplicateKey { .. } = err {
                    return Err(PassError::duplicate_key("duplicate vault name"));
                }
                Err(err)
            }
        }
    }

    async fn update_vault(&self, ctx: &UserContext, vault: &Vault) -> PassResult<usize> {
        let _ = self.metrics.new_metric("update_vault");
        self.vault_repository.update(ctx, vault).await
    }

    // get the vault by id.
    async fn get_vault(&self, ctx: &UserContext, id: &str) -> PassResult<Vault> {
        let _ = self.metrics.new_metric("get_vault");
        self.vault_repository.get(ctx, id).await
    }

    async fn delete_vault(&self, ctx: &UserContext, id: &str) -> PassResult<usize> {
        let _ = self.metrics.new_metric("delete_vault");
        self.vault_repository.delete(ctx, id).await
    }

    async fn get_user_vaults(&self, ctx: &UserContext) -> PassResult<Vec<Vault>> {
        let _ = self.metrics.new_metric("get_user_vaults");
        let res = self
            .vault_repository
            .find(
                ctx,
                HashMap::from([("user_id".into(), ctx.user_id.clone())]),
                0,
                self.config.max_vaults_per_user as usize,
            )
            .await?;
        Ok(res.records)
    }

    // account summaries.
    async fn account_summaries_by_vault(
        &self,
        ctx: &UserContext,
        vault_id: &str,
        q: Option<String>,
    ) -> PassResult<Vec<AccountSummary>> {
        let _ = self.metrics.new_metric("account_summaries_by_vault");
        let vault = self.vault_repository.get(ctx, vault_id).await?;
        let mut summaries = vault.account_summaries();
        if let Some(q) = q {
            summaries = summaries.into_iter().filter(|a| a.matches(&q)).collect::<Vec<AccountSummary>>();
        }
        Ok(summaries)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use uuid::Uuid;

    use crate::domain::models::{DEFAULT_VAULT_NAMES, HSMProvider, PassConfig, User, Vault, VaultKind};
    use crate::service::factory::{create_user_service, create_vault_service};

    #[tokio::test]
    async fn test_should_create_update_vault() {
        let mut config = PassConfig::new();
        config.hsm_provider = HSMProvider::EncryptedFile.to_string();
        // GIVEN user-service and vault-service
        let user_service = create_user_service(&config).await.unwrap();
        let vault_service = create_vault_service(&config).await.unwrap();

        // Due to referential integrity, we must first create a valid user
        let user = User::new(Uuid::new_v4().to_string().as_str(), None, None);
        let ctx = user_service.register_user(&user, "cru5h&r]fIt@$@v!or", HashMap::new()).await.unwrap();

        // WHEN creating a new vault
        let mut vault = Vault::new(&user.user_id, "title1", VaultKind::Logins);
        // THEN it should succeed
        assert_eq!(1, vault_service.create_vault(&ctx, &vault).await.unwrap());

        // WHEN updating the vault
        vault.title = "new-value".into();
        // THEN it should succeed
        assert_eq!(1, vault_service.update_vault(&ctx, &vault).await.unwrap());

        // WHEN retrieving the vault
        let loaded = vault_service
            .get_vault(&ctx, vault.vault_id.as_str())
            .await
            .unwrap();

        // THEN it should have updated values
        assert_eq!("new-value", loaded.title);
        assert_eq!(2, loaded.version);

        let summaries = vault_service.account_summaries_by_vault(&ctx, &vault.vault_id, None).await.unwrap();
        assert_eq!(0, summaries.len());
    }

    #[tokio::test]
    async fn test_should_create_delete_vault() {
        let mut config = PassConfig::new();
        config.hsm_provider = HSMProvider::EncryptedFile.to_string();
        // GIVEN user-service and vault-service
        let user_service = create_user_service(&config).await.unwrap();
        let vault_service = create_vault_service(&config).await.unwrap();

        // Due to referential integrity, we must first create a valid user
        let user = User::new(Uuid::new_v4().to_string().as_str(), None, None);
        let ctx = user_service.register_user(&user, "cru5h&r]fIt@$@v!or", HashMap::new()).await.unwrap();

        // WHEN creating a new vault
        let vault = Vault::new(&user.user_id, "title1", VaultKind::Logins);
        // THEN it should succeed
        assert_eq!(1, vault_service.create_vault(&ctx, &vault).await.unwrap());

        // WHEN deleting the vault THEN it should succeed
        assert_eq!(
            1,
            vault_service
                .delete_vault(&ctx, &vault.vault_id)
                .await
                .unwrap()
        );

        // WHEN retrieving the vault after deleting it
        let loaded = vault_service.get_vault(&ctx, vault.vault_id.as_str()).await;
        // THEN it should fail
        assert!(loaded.is_err());
    }

    #[tokio::test]
    async fn test_should_find_vaults() {
        let mut config = PassConfig::new();
        config.hsm_provider = HSMProvider::EncryptedFile.to_string();
        // GIVEN user-service and vault-service
        let user_service = create_user_service(&config).await.unwrap();
        let vault_service = create_vault_service(&config).await.unwrap();

        // Due to referential integrity, we must first create a valid user
        let user = User::new(Uuid::new_v4().to_string().as_str(), None, None);
        let ctx = user_service.register_user(&user, "cru5h&r]fIt@$@v!or", HashMap::new()).await.unwrap();

        for i in 0..5 {
            // WHEN creating a new vault
            let vault = Vault::new(&user.user_id, format!("title {}", i).as_str(), VaultKind::Logins);
            // THEN it should succeed
            assert_eq!(1, vault_service.create_vault(&ctx, &vault).await.unwrap());
        }
        // WHEN finding vaults for the user
        let all = vault_service.get_user_vaults(&ctx).await.unwrap();
        // THEN it should return all vaults
        assert_eq!(5 + DEFAULT_VAULT_NAMES.len(), all.len());
    }
}
