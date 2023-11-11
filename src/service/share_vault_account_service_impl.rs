use std::sync::Arc;

use async_trait::async_trait;
use prometheus::Registry;

use crate::dao::models::UserContext;
use crate::dao::ShareVaultAccountRepository;
use crate::domain::models::{PassConfig, PassResult};
use crate::service::ShareVaultAccountService;
use crate::utils::metrics::PassMetrics;

#[derive(Clone)]
pub(crate) struct ShareVaultAccountServiceImpl {
    share_vault_account_repository: Arc<dyn ShareVaultAccountRepository + Send + Sync>,
    metrics: PassMetrics,
}

impl ShareVaultAccountServiceImpl {
    pub(crate) fn new(
        _config: &PassConfig,
        share_vault_account_repository: Arc<dyn ShareVaultAccountRepository + Send + Sync>,
        registry: &Registry,
    ) -> PassResult<Self> {
        Ok(Self {
            share_vault_account_repository,
            metrics: PassMetrics::new("share_vault_account_service", registry)?,
        })
    }
}

#[async_trait]
impl ShareVaultAccountService for ShareVaultAccountServiceImpl {
    async fn share_vault(&self, ctx: &UserContext, vault_id: &str, target_username: &str, read_only: bool) -> PassResult<usize> {
        let _ = self.metrics.new_metric("share_vault");
        self.share_vault_account_repository.share_vault(ctx, vault_id, target_username, read_only).await
    }

    async fn share_account(&self, ctx: &UserContext, account_id: &str, target_username: &str) -> PassResult<usize> {
        let _ = self.metrics.new_metric("share_account");
        self.share_vault_account_repository.share_account(ctx, account_id, target_username).await
    }

    async fn lookup_usernames(&self, ctx: &UserContext, q: &str) -> PassResult<Vec<String>> {
        let _ = self.metrics.new_metric("lookup_usernames");
        self.share_vault_account_repository.lookup_usernames(ctx, q).await
    }

    async fn handle_shared_vaults_accounts(&self, ctx: &UserContext) -> PassResult<(usize, usize)> {
        let _ = self.metrics.new_metric("handle_shared_vaults_accounts");
        self.share_vault_account_repository.handle_shared_vaults_accounts(ctx).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use itertools::Itertools;
    use uuid::Uuid;

    use crate::domain::models::{Account, AccountKind, PassConfig, User, Vault, VaultKind};
    use crate::service::factory::{create_account_service, create_share_vault_account_service, create_user_service, create_vault_service};

    #[tokio::test]
    async fn test_should_create_update_share_vaults() {
        let config = PassConfig::new();
        // GIVEN user-service, vault-service, account-service and share account/vault service
        let user_service = create_user_service(&config).await.unwrap();
        let vault_service = create_vault_service(&config).await.unwrap();
        let account_service = create_account_service(&config).await.unwrap();
        let share_vault_account_service = create_share_vault_account_service(&config).await.unwrap();


        // Due to referential integrity, we must first create a valid user
        let user1 = User::new(Uuid::new_v4().to_string().as_str(), None, None);
        let (ctx1, _) = user_service.signup_user(&user1, "cru5h&r]fIt@$@v!or", HashMap::new()).await.unwrap();
        let user2 = User::new(Uuid::new_v4().to_string().as_str(), None, None);
        let (ctx2, _) = user_service.signup_user(&user2, "cru5h&r]fIt@$@v!or", HashMap::new()).await.unwrap();

        // Create dependent vault
        let vault = Vault::new(&user1.user_id, "title1", VaultKind::Logins);
        assert_eq!(1, vault_service.create_vault(&ctx1, &vault).await.unwrap());

        // WHEN creating a new accounts
        let account_names = ["user1", "user2"];
        for account_name in account_names {
            let mut account = Account::new(&vault.vault_id, AccountKind::Login);
            account.details.username = Some(account_name.into());
            account.credentials.password = Some("pass".into());
            // THEN it should succeed
            assert_eq!(
                1,
                account_service
                    .create_account(&ctx1, &account)
                    .await
                    .unwrap()
            );
        }

        // WHEN finding accounts for the user1
        let all = account_service
            .find_accounts_by_vault(&ctx1, &vault.vault_id, HashMap::new(), 0, 1000)
            .await
            .unwrap();
        // THEN it should return all accounts
        assert_eq!(2, all.records.len());

        // But WHEN finding accounts for the user2
        let all = account_service
            .find_accounts_by_vault(&ctx2, &vault.vault_id, HashMap::new(), 0, 1000)
            .await
            .unwrap();
        // THEN it should return 0 accounts
        assert_eq!(0, all.records.len());

        let size = share_vault_account_service.share_vault(&ctx1, &vault.vault_id, &user2.username, false).await.unwrap();
        assert_eq!(1, size);

        // invoke following method to read inbox
        let (vault_size, account_size) = share_vault_account_service.handle_shared_vaults_accounts(&ctx2).await.unwrap();
        assert_eq!(1, vault_size);
        assert_eq!(0, account_size);

        // WHEN accessing vault after sharing  THEN it should work
        let _ = vault_service
            .get_vault(
                &ctx2,
                &vault.vault_id,
            )
            .await
            .unwrap();

        // WHEN finding accounts for the user2 after sharing
        let all = account_service
            .find_accounts_by_vault(&ctx2, &vault.vault_id, HashMap::new(), 0, 1000)
            .await
            .unwrap();
        // THEN it should return 2 accounts
        assert_eq!(2, all.records.len());

        // User 2 should also be able to update and accounts for write permissions.
        for mut account in all.records {
            account.details.url = Some(Uuid::new_v4().to_string());
            assert_eq!(1, account_service.update_account(&ctx2, &account).await.unwrap());
            assert_eq!(1, account_service.delete_account(&ctx2, &account.details.account_id).await.unwrap());
        }

        // User 2 should also be able to create accounts for write permissions.
        for i in 0..2 {
            let mut account = Account::new(&vault.vault_id, AccountKind::Login);
            account.details.username = Some(format!("user_{}", i.clone()));
            account.details.email = Some(format!("email_{}@domain.io", i.clone()));
            account.credentials.password = Some(format!("pass_{}", i.clone()));
            assert_eq!(1, account_service.create_account(&ctx2, &account).await.unwrap());
        }
    }

    #[tokio::test]
    async fn test_should_create_update_share_account() {
        let config = PassConfig::new();
        // GIVEN user-service, vault-service, account-service and share account/vault service
        let user_service = create_user_service(&config).await.unwrap();
        let vault_service = create_vault_service(&config).await.unwrap();
        let account_service = create_account_service(&config).await.unwrap();
        let share_vault_account_service = create_share_vault_account_service(&config).await.unwrap();


        // Due to referential integrity, we must first create a valid user
        let user1 = User::new(Uuid::new_v4().to_string().as_str(), None, None);
        let (ctx1, _) = user_service.signup_user(&user1, "cru5h&r]fIt@$@v!or", HashMap::new()).await.unwrap();
        let user2 = User::new(Uuid::new_v4().to_string().as_str(), None, None);
        let (ctx2, _) = user_service.signup_user(&user2, "cru5h&r]fIt@$@v!or", HashMap::new()).await.unwrap();

        // Create dependent vault
        let vault = Vault::new(&user1.user_id, "title1", VaultKind::Logins);
        assert_eq!(1, vault_service.create_vault(&ctx1, &vault).await.unwrap());

        // WHEN creating a new accounts
        let account_names = ["user1", "user2"];
        for account_name in account_names {
            let mut account = Account::new(&vault.vault_id, AccountKind::Login);
            account.details.username = Some(account_name.into());
            account.credentials.password = Some("pass".into());
            // THEN it should succeed
            assert_eq!(
                1,
                account_service
                    .create_account(&ctx1, &account)
                    .await
                    .unwrap()
            );
        }

        // WHEN finding accounts for the user1
        let user1_accounts = account_service
            .find_accounts_by_vault(&ctx1, &vault.vault_id, HashMap::new(), 0, 1000)
            .await
            .unwrap();
        // THEN it should return all accounts
        assert_eq!(2, user1_accounts.records.len());

        // But WHEN finding accounts for the user2
        let user2_accounts = account_service
            .find_accounts_by_vault(&ctx2, &vault.vault_id, HashMap::new(), 0, 1000)
            .await
            .unwrap();
        // THEN it should return 0 accounts
        assert_eq!(0, user2_accounts.records.len());

        let size = share_vault_account_service.share_account(&ctx1, &user1_accounts.records[0].details.account_id, &user2.username).await.unwrap();
        assert_eq!(1, size);

        // invoke following method to read inbox as user2
        let (vault_size, account_size) = share_vault_account_service.handle_shared_vaults_accounts(&ctx2).await.unwrap();
        assert_eq!(0, vault_size);
        assert_eq!(1, account_size);

        // WHEN accessing vault after sharing account THEN it should FAIL
        assert!(vault_service
            .get_vault(
                &ctx2,
                &vault.vault_id,
            )
            .await
            .is_err());

        let user2_vaults = vault_service.get_user_vaults(&ctx2).await.unwrap().iter().find_or_first(|v|v.kind == VaultKind::Logins).unwrap().clone();
        // WHEN finding accounts for the user2 after sharing
        let user2_accounts = account_service
            .find_accounts_by_vault(&ctx2, &user2_vaults.vault_id, HashMap::new(), 0, 1000)
            .await
            .unwrap();
        // THEN it should return 1 accounts
        assert_eq!(1, user2_accounts.records.len());
        assert_eq!(&user1_accounts.records[0].details.username, &user2_accounts.records[0].details.username);

    }
}
