use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use prometheus::Registry;

use crate::dao::models::UserContext;
use crate::dao::AccountRepository;
use crate::domain::error::PassError;
use crate::domain::models::{Account, PaginatedResult, PassConfig, PassResult};
use crate::service::AccountService;
use crate::utils::metrics::PassMetrics;

#[derive(Clone)]
pub(crate) struct AccountServiceImpl {
    account_repository: Arc<dyn AccountRepository + Send + Sync>,
    metrics: PassMetrics,
}

impl AccountServiceImpl {
    pub(crate) fn new(
        _: &PassConfig,
        account_repository: Arc<dyn AccountRepository + Send + Sync>,
        registry: &Registry,
    ) -> PassResult<Self> {
        Ok(Self {
            account_repository,
            metrics: PassMetrics::new("account_service", registry)?,
        })
    }
}

#[async_trait]
impl AccountService for AccountServiceImpl {
    async fn create_account(&self, ctx: &UserContext, account: &Account) -> PassResult<usize> {
        let _ = self.metrics.new_metric("create_account");
        match self.account_repository.create(ctx, account).await {
            Ok(size) => {
                Ok(size)
            }
            Err(err) => {
                if let PassError::DuplicateKey { .. } = err {
                    return Err(PassError::duplicate_key("duplicate account"));
                }
                Err(err)
            }
        }
    }

    async fn update_account(&self, ctx: &UserContext, account: &Account) -> PassResult<usize> {
        let _ = self.metrics.new_metric("update_account");
        self.account_repository.update(ctx, account).await
    }

    async fn get_account(&self, ctx: &UserContext, id: &str) -> PassResult<Account> {
        let _ = self.metrics.new_metric("get_account");
        self.account_repository.get(ctx, id).await
    }

    async fn delete_account(&self, ctx: &UserContext, id: &str) -> PassResult<usize> {
        let _ = self.metrics.new_metric("delete_account");
        self.account_repository.delete(ctx, id).await
    }

    async fn find_accounts_by_vault(
        &self,
        ctx: &UserContext,
        vault_id: &str,
        predicates: HashMap<String, String>,
        offset: i64,
        limit: usize,
    ) -> PassResult<PaginatedResult<Account>> {
        let _ = self.metrics.new_metric("find_accounts_by_vault");
        let mut predicates = predicates.clone();
        predicates.insert("vault_id".into(), vault_id.into());
        self.account_repository
            .find(ctx, predicates, offset, limit)
            .await
    }

    // count all accounts by vault.
    async fn count_accounts_by_vault(
        &self,
        ctx: &UserContext,
        vault_id: &str,
        predicates: HashMap<String, String>,
    ) -> PassResult<i64> {
        let _ = self.metrics.new_metric("count_accounts_by_vault");
        let mut predicates = predicates.clone();
        predicates.insert("vault_id".into(), vault_id.into());
        self.account_repository
            .count(ctx, predicates)
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use uuid::Uuid;

    use crate::domain::models::{Account, AccountKind, HSMProvider, PassConfig, User, Vault, VaultKind};
    use crate::service::factory::{
        create_account_service, create_user_service, create_vault_service,
    };

    #[tokio::test]
    async fn test_should_create_update_account() {
        let mut config = PassConfig::new();
        config.hsm_provider = HSMProvider::EncryptedFile.to_string();

        // GIVEN user-service, vault-service and account-service
        let user_service = create_user_service(&config).await.unwrap();
        let vault_service = create_vault_service(&config).await.unwrap();
        let account_service = create_account_service(&config).await.unwrap();

        // Due to referential integrity, we must first create a valid user
        let user = User::new(Uuid::new_v4().to_string().as_str(), None, None);
        // Signup with weak password such as `password` should fail
        assert!(user_service.signup_user(&user, "password", HashMap::new()).await.is_err());

        // But with strong password should succeed
        let (ctx, _) = user_service.signup_user(&user, "cru5h&r]fIt@$@v", HashMap::new()).await.unwrap();

        // Create dependent vault
        let vault = Vault::new(&user.user_id, "title1", VaultKind::Logins);
        assert_eq!(1, vault_service.create_vault(&ctx, &vault).await.unwrap());

        // WHEN creating a new account
        let mut account = Account::new(&vault.vault_id, AccountKind::Login);
        account.details.username = Some("user".into());
        account.credentials.password = Some("pass".into());
        // THEN it should succeed
        assert_eq!(
            1,
            account_service
                .create_account(&ctx, &account)
                .await
                .unwrap()
        );

        // WHEN updating the account
        account.details.username = Some("user1".into());
        account.credentials.password = Some("pass1".into());
        account.credentials.notes = Some("note1".into());
        // THEN it should succeed
        assert_eq!(
            1,
            account_service
                .update_account(&ctx, &account)
                .await
                .unwrap()
        );

        // WHEN retrieving the account
        let loaded = account_service
            .get_account(&ctx, account.details.account_id.as_str())
            .await
            .unwrap();

        // THEN it should have updated values
        assert_eq!(Some("user1".into()), loaded.details.username);
        assert_eq!(Some("pass1".into()), loaded.credentials.password);
        assert_eq!(Some("note1".into()), loaded.credentials.notes);
    }

    #[tokio::test]
    async fn test_should_create_delete_account() {
        let mut config = PassConfig::new();
        config.hsm_provider = HSMProvider::EncryptedFile.to_string();
        // GIVEN user-service, vault-service and account-service
        let user_service = create_user_service(&config).await.unwrap();
        let vault_service = create_vault_service(&config).await.unwrap();
        let account_service = create_account_service(&config).await.unwrap();

        // Due to referential integrity, we must first create a valid user
        let user = User::new(Uuid::new_v4().to_string().as_str(), None, None);
        let (ctx, _) = user_service.signup_user(&user, "cru5h&r]fIt@$@v", HashMap::new()).await.unwrap();

        // Create dependent vault
        let vault = Vault::new(&user.user_id, "title1", VaultKind::Logins);
        assert_eq!(1, vault_service.create_vault(&ctx, &vault).await.unwrap());

        // WHEN creating a new account
        let mut account = Account::new(&vault.vault_id, AccountKind::Login);
        account.details.username = Some("user".into());
        account.credentials.password = Some("pass".into());
        // THEN it should succeed
        assert_eq!(
            1,
            account_service
                .create_account(&ctx, &account)
                .await
                .unwrap()
        );

        // WHEN deleting the vault THEN it should succeed
        assert_eq!(
            1,
            account_service
                .delete_account(&ctx, &account.details.account_id)
                .await
                .unwrap()
        );

        // WHEN retrieving the vault after deleting it
        let loaded = account_service
            .get_account(&ctx, account.vault_id.as_str())
            .await;
        // THEN it should fail
        assert!(loaded.is_err());
    }

    #[tokio::test]
    async fn test_should_find_accounts() {
        let mut config = PassConfig::new();
        config.hsm_provider = HSMProvider::EncryptedFile.to_string();
        // GIVEN user-service, vault-service and account-service
        let user_service = create_user_service(&config).await.unwrap();
        let vault_service = create_vault_service(&config).await.unwrap();
        let account_service = create_account_service(&config).await.unwrap();

        // Due to referential integrity, we must first create a valid user
        let user = User::new(Uuid::new_v4().to_string().as_str(), None, None);
        let (ctx, _) = user_service.signup_user(&user, "cru5h&r]fIt@$@v", HashMap::new()).await.unwrap();

        // Create dependent vault
        let vault = Vault::new(&user.user_id, "title1", VaultKind::Logins);
        assert_eq!(1, vault_service.create_vault(&ctx, &vault).await.unwrap());

        for i in 0..5 {
            // WHEN creating a new account
            let mut account = Account::new(&vault.vault_id, AccountKind::Login);
            account.details.username = Some(format!("user_{}", i));
            account.details.category = Some("cat1".into());
            account.details.tags = vec!["tag1".into(), "tag2".into()];
            account.credentials.password = Some(format!("pass_{}", i));
            account.credentials.notes = Some(format!("note_{}", i));
            // THEN it should succeed
            assert_eq!(
                1,
                account_service
                    .create_account(&ctx, &account)
                    .await
                    .unwrap()
            );
        }
        // WHEN finding accounts for the user
        let all = account_service
            .find_accounts_by_vault(&ctx, &vault.vault_id, HashMap::new(), 0, 1000)
            .await
            .unwrap();
        // THEN it should return all accounts
        assert_eq!(5, all.records.len());

        // WHEN counting accounts
        let count = account_service
            .count_accounts_by_vault(&ctx, &vault.vault_id, HashMap::new())
            .await
            .unwrap();
        // THEN it should return count of accounts
        assert_eq!(5 as i64, count);

        // Verify summary in vault
        let loaded = vault_service
            .get_vault(&ctx, vault.vault_id.as_str())
            .await
            .unwrap();
        assert_eq!(5, loaded.entries.unwrap().len());
    }
}
