use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use crate::crypto;

use crate::dao::models::{CryptoKeyEntity, UserContext};
use crate::dao::{DbConnection, DbPool, ShareVaultAccountRepository, UserVaultRepository, UserRepository, CryptoKeyRepository, AuditRepository, VaultRepository, AccountRepository, MessageRepository};
use crate::dao::account_repository_impl::AccountRepositoryImpl;
use crate::dao::user_repository_impl::UserRepositoryImpl;
use crate::dao::vault_repository_impl::VaultRepositoryImpl;
use crate::domain::error::PassError;
use crate::domain::models::{PassResult, Message, MessageKind, ShareVaultPayload, ShareAccountPayload, READ_FLAG};

#[derive(Clone)]
pub(crate) struct ShareVaultAccountRepositoryImpl {
    pool: DbPool,
    message_repository: Arc<dyn MessageRepository + Send + Sync>,
    account_repository: Arc<dyn AccountRepository + Send + Sync>,
    vault_repository: Arc<dyn VaultRepository + Send + Sync>,
    user_vault_repository: Arc<dyn UserVaultRepository + Send + Sync>,
    user_repository: Arc<dyn UserRepository + Send + Sync>,
    crypto_key_repository: Arc<dyn CryptoKeyRepository + Send + Sync>,
    audit_repository: Arc<dyn AuditRepository + Send + Sync>,
}

impl ShareVaultAccountRepositoryImpl {
    pub(crate) fn new(pool: DbPool,
                      message_repository: Arc<dyn MessageRepository + Send + Sync>,
                      account_repository: Arc<dyn AccountRepository + Send + Sync>,
                      vault_repository: Arc<dyn VaultRepository + Send + Sync>,
                      user_vault_repository: Arc<dyn UserVaultRepository + Send + Sync>,
                      user_repository: Arc<dyn UserRepository + Send + Sync>,
                      crypto_key_repository: Arc<dyn CryptoKeyRepository + Send + Sync>,
                      audit_repository: Arc<dyn AuditRepository + Send + Sync>,
    ) -> Self {
        ShareVaultAccountRepositoryImpl {
            pool,
            message_repository,
            account_repository,
            vault_repository,
            user_vault_repository,
            user_repository,
            crypto_key_repository,
            audit_repository,
        }
    }

    fn connection(&self) -> PassResult<DbConnection> {
        self.pool.get().map_err(|err| {
            PassError::database(
                format!("failed to get pool connection due to {}", err).as_str(),
                None,
                true,
            )
        })
    }

    async fn get_vault_crypto_key(&self, ctx: &UserContext, id: &str) -> PassResult<CryptoKeyEntity> {
        let mut conn = self.connection()?;
        let crypto_key = self
            .crypto_key_repository
            .get(&ctx.user_id, id, "Vault", &mut conn)?;
        // only owner can share vault so not checking ACL
        ctx.validate_user_id(&crypto_key.user_id, || false)?;
        Ok(crypto_key)
    }

    fn get_user_id(&self, _ctx: &UserContext, username: &str) -> PassResult<String> {
        let mut conn = self.connection()?;
        UserRepositoryImpl::lookup_userid_by_username(username, &mut conn)
    }

    async fn handle_shared_vaults(&self, ctx: &&UserContext) -> PassResult<usize> {
        let vault_messages = self.message_repository
            .find(
                &ctx,
                HashMap::from([
                    ("user_id".into(), ctx.user_id.clone()),
                    ("kind".into(), MessageKind::ShareVault.to_string()),
                    ("flags".into(), "0".into()), // non-read
                ]),
                0,
                100,
            )
            .await?;
        let mut shared_vaults: usize = 0;
        for mut msg in vault_messages.records {
            let mut conn = self.connection()?;
            let message_payload: ShareVaultPayload = serde_json::from_str(&msg.data)?;
            match VaultRepositoryImpl::shared_create(
                ctx,
                &message_payload,
                self.user_repository.clone(),
                self.crypto_key_repository.clone(),
                self.user_vault_repository.clone(),
                self.audit_repository.clone(),
                &mut conn,
            ).await {
                Ok(size) => {
                    shared_vaults += size;
                }
                Err(err) => {
                    log::error!("failed to handle shared vault {} from user {:?} due to {:?}",
                        &message_payload.vault_id, &message_payload.from_username, err);
                }
            }

            // mark the message as READ so that we don't reprocess it
            msg.flags = READ_FLAG;
            let _ = self.message_repository.update(ctx, &msg).await?;
        }
        Ok(shared_vaults)
    }

    async fn handle_shared_accounts(&self, ctx: &&UserContext) -> PassResult<usize> {
        let account_messages = self.message_repository
            .find(
                &ctx,
                HashMap::from([
                    ("user_id".into(), ctx.user_id.clone()),
                    ("kind".into(), MessageKind::ShareAccount.to_string()),
                    ("flags".into(), "0".into()), // non-read
                ]),
                0,
                100,
            )
            .await?;
        let mut shared_accounts: usize = 0;
        for mut msg in account_messages.records {
            let message_payload: ShareAccountPayload = serde_json::from_str(&msg.data)?;
            match AccountRepositoryImpl::shared_create(
                ctx,
                &message_payload,
                self.user_repository.clone(),
                self.vault_repository.clone(),
                self.account_repository.clone(),
            ).await {
                Ok(size) => {
                    shared_accounts += size;
                }
                Err(err) => {
                    log::error!("failed to handle shared account {:?} due to {:?}", &message_payload.from_username, err);
                }
            }
            // mark the message as READ so that we don't reprocess it
            msg.flags = READ_FLAG;
            let _ = self.message_repository.update(ctx, &msg).await?;
        }
        Ok(shared_accounts)
    }
}

#[async_trait]
impl ShareVaultAccountRepository for ShareVaultAccountRepositoryImpl {
    async fn share_vault(
        &self,
        ctx: &UserContext,
        vault_id: &str,
        target_username: &str,
        read_only: bool,
    ) -> PassResult<usize> {
        if target_username == &ctx.username {
            return Err(PassError::validation("target username cannot be same as user's own username", None));
        }
        let target_user_id = self.get_user_id(ctx, target_username)?;
        let vault_entity = self.vault_repository.get_entity(ctx, vault_id).await?;
        if vault_entity.owner_user_id == target_user_id {
            return Err(PassError::validation("cannot share vault with the owner of vault", None));
        }

        // Only vault owner can share vault so not checking ACL
        if ctx.validate_user_id(&vault_entity.owner_user_id, || false).is_err() {
            return Err(PassError::validation(
                format!("Only owner of vault {}/{} can share it with other users",
                         &vault_entity.title, &vault_entity.vault_id).as_str(), None));
        }

        // getting user-crypto key of owner of vault
        let user_crypto_key = self
            .user_repository
            .get_crypto_key(ctx, &vault_entity.owner_user_id)
            .await?;
        let vault_crypto_key = self.get_vault_crypto_key(ctx, vault_id).await?;

        // Querying target user crypto key as admin
        let target_user_crypto_key = {
            let ctx = ctx.as_admin(); // keeping scope of modified context small
            self.user_repository.get_crypto_key(&ctx, &target_user_id).await?
        };

        let encrypted_vault_crypto_key = vault_crypto_key.encrypted_clone_for_sharing(
            ctx,
            &user_crypto_key,
            &target_user_id,
            &target_user_crypto_key,
            &vault_crypto_key.crypto_key_id)?;

        let message_payload = ShareVaultPayload::new(
            &vault_entity.vault_id,
            &vault_entity.title,
            &encrypted_vault_crypto_key,
            &ctx.user_id,
            &ctx.username,
            &target_user_id,
            read_only);
        let json_payload = serde_json::to_string(&message_payload)?;
        let message = Message::new(
            &target_user_id,
            MessageKind::ShareVault,
            format!("Sharing {} vault from user {}", &vault_entity.title, &ctx.username).as_str(),
            &json_payload,
        );
        // Add message to the target user inbox
        let size = {
            let ctx = UserContext::default_new("", &target_user_id, "", "", "")?;
            log::info!("shared vault {} from user {} to user {}", &vault_entity.title, &ctx.user_id, &target_username);
            self.message_repository.create(&ctx, &message).await?
        };
        Ok(size)
    }

    async fn share_account(
        &self,
        ctx: &UserContext,
        account_id: &str,
        target_username: &str) -> PassResult<usize> {
        if target_username == &ctx.username {
            return Err(PassError::validation("target username cannot be same as user's own username", None));
        }
        let target_user_id = self.get_user_id(ctx, target_username)?;

        let shared_account = self.account_repository.get(ctx, account_id).await?.clone_for_sharing();

        // make sure user has access to the vault
        let vault_entity = self.vault_repository.get_entity(ctx, &shared_account.vault_id).await?;
        let json_shared_account = serde_json::to_string(&shared_account)?;

        // Querying target user crypto key as admin
        let target_user_crypto_key = {
            let ctx = ctx.as_admin(); // keeping scope of modified context small
            self.user_repository.get_crypto_key(&ctx, &target_user_id).await?
        };

        // encrypt account with target user's public key
        let encrypted_shared_account = crypto::ec_encrypt_hex(&target_user_crypto_key.public_key, &json_shared_account)?;
        let message_payload = ShareAccountPayload::new(
            &vault_entity.vault_id,
            &vault_entity.title,
            &encrypted_shared_account,
            &ctx.user_id,
            &ctx.username,
            &target_user_id);
        let json_payload = serde_json::to_string(&message_payload)?;
        let message = Message::new(
            &target_user_id,
            MessageKind::ShareAccount,
            format!("Sharing account from user {}", &ctx.username).as_str(),
            &json_payload,
        );
        // Saving message in target message inbox
        let size = {
            let ctx = UserContext::default_new("", &target_user_id, "", "", "")?;
            log::info!("shared account {} from user {} to user {}", account_id, &ctx.username, &target_username);
            self.message_repository.create(&ctx, &message).await?
        };
        Ok(size)
    }

    async fn lookup_usernames(&self, ctx: &UserContext, q: &str) -> PassResult<Vec<String>> {
        let mut conn = self.connection()?;
        let mut usernames = UserRepositoryImpl::lookup_usernames(q, &mut conn)?;
        if let Some(index) = usernames.iter().position(|x| *x == ctx.username) {
            usernames.remove(index);
        }
        Ok(usernames)
    }

    async fn handle_shared_vaults_accounts(&self, ctx: &UserContext) -> PassResult<(usize, usize)> {
        let shared_vaults = self.handle_shared_vaults(&ctx).await?;
        let shared_accounts = self.handle_shared_accounts(&ctx).await?;
        log::info!("handle_shared_vaults_accounts {} shared vault {}, account {}", &ctx.user_id, shared_vaults.clone(), shared_accounts.clone());
        Ok((shared_vaults, shared_accounts))
    }
}


#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use uuid::Uuid;
    use crate::crypto;
    use crate::dao::factory::{create_account_repository, create_share_vault_account_repository, create_user_repository, create_vault_repository};
    use crate::dao::models::UserContext;
    use crate::domain::models::{Account, AccountKind, PassConfig, User, Vault, VaultKind};

    #[tokio::test]
    async fn test_should_share_vault() {
        let config = PassConfig::new();
        // GIVEN a user, vault and account repositories
        let user_repo = create_user_repository(&config).await.unwrap();
        let vault_repo = create_vault_repository(&config).await.unwrap();
        let account_repo = create_account_repository(&config).await.unwrap();
        let share_repo = create_share_vault_account_repository(&config).await.unwrap();

        // Due to referential integrity, we must first create a user and a vault.
        let username1 = Uuid::new_v4().to_string();
        let username2 = Uuid::new_v4().to_string();
        let user1 = User::new(username1.as_str(), None, None);
        let user2 = User::new(username2.as_str(), None, None);

        let ctx1 =
            UserContext::default_new(
                &username1,
                &user1.user_id,
                &hex::encode(crypto::generate_nonce()),
                &hex::encode(crypto::generate_secret_key()),
                "password1").unwrap();

        let ctx2 =
            UserContext::default_new(
                &username2,
                &user2.user_id,
                &hex::encode(crypto::generate_nonce()),
                &hex::encode(crypto::generate_secret_key()),
                "password2").unwrap();

        assert_eq!(1, user_repo.create(&ctx1, &user1).await.unwrap());
        assert_eq!(1, user_repo.create(&ctx2, &user2).await.unwrap());

        let vault = Vault::new(user1.user_id.as_str(), "title", VaultKind::Logins);
        assert_eq!(1, vault_repo.create(&ctx1, &vault).await.unwrap());

        for i in 0..2 {
            // WHEN creating an account
            let mut account = Account::new(&vault.vault_id, AccountKind::Login);
            account.details.username = Some(format!("user_{}", i.clone()));
            account.details.email = Some(format!("email_{}@domain.io", i.clone()));
            account.credentials.password = Some(format!("pass_{}", i.clone()));
            assert_eq!(1, account_repo.create(&ctx1, &account).await.unwrap());
        }

        // User 1 owns the accounts so it should be able to find the accounts
        let res1 = account_repo
            .find(
                &ctx1,
                HashMap::from([("vault_id".into(), vault.vault_id.clone())]),
                0,
                500,
            )
            .await
            .unwrap();
        assert_eq!(2, res1.records.len());

        // User 2 does not own the accounts so it should not be able to find the accounts
        let res2 = account_repo
            .find(
                &ctx2,
                HashMap::from([("vault_id".into(), vault.vault_id.clone())]),
                0,
                500,
            )
            .await
            .unwrap();
        assert_eq!(0, res2.records.len());
        // WHEN sharing vault with the same username then it should fail
        assert!(share_repo.share_vault(&ctx1, &vault.vault_id, &username1, false).await.is_err());

        // WHEN sharing vault with another user THEN it should succeed
        let size = share_repo.share_vault(&ctx1, &vault.vault_id, &username2, false).await.unwrap();
        assert_eq!(1, size);

        // invoke following method to read inbox
        let (vault_size, account_size) = share_repo.handle_shared_vaults_accounts(&ctx2).await.unwrap();
        assert_eq!(1, vault_size);
        assert_eq!(0, account_size);

        // User 2 should now have access to the vault.
        let _ = vault_repo
            .get(
                &ctx2,
                &vault.vault_id,
            )
            .await
            .unwrap();

        // User 2 should now have access to all accounts in shared vault.
        let res4 = account_repo
            .find(
                &ctx2,
                HashMap::from([("vault_id".into(), vault.vault_id.clone())]),
                0,
                500,
            )
            .await
            .unwrap();
        assert_eq!(2, res4.records.len());

        // User 2 should also be able to update and accounts for write permissions.
        for mut account in res4.records {
            account.details.url = Some(Uuid::new_v4().to_string());
            assert_eq!(1, account_repo.update(&ctx2, &account).await.unwrap());
            assert_eq!(1, account_repo.delete(&ctx2, &account.details.account_id).await.unwrap());
        }

        // User 2 should also be able to create accounts for write permissions.
        for i in 0..2 {
            let mut account = Account::new(&vault.vault_id, AccountKind::Login);
            account.details.username = Some(format!("user_{}", i.clone()));
            account.details.email = Some(format!("email_{}@domain.io", i.clone()));
            account.credentials.password = Some(format!("pass_{}", i.clone()));
            assert_eq!(1, account_repo.create(&ctx2, &account).await.unwrap());
        }
    }


    #[tokio::test]
    async fn test_should_share_vault_with_readonly() {
        let config = PassConfig::new();
        // GIVEN a user, vault and account repositories
        let user_repo = create_user_repository(&config).await.unwrap();
        let vault_repo = create_vault_repository(&config).await.unwrap();
        let account_repo = create_account_repository(&config).await.unwrap();
        let share_repo = create_share_vault_account_repository(&config).await.unwrap();

        // Due to referential integrity, we must first create a user and a vault.
        let username1 = Uuid::new_v4().to_string();
        let username2 = Uuid::new_v4().to_string();
        let user1 = User::new(username1.as_str(), None, None);
        let user2 = User::new(username2.as_str(), None, None);

        let ctx1 =
            UserContext::default_new(
                &username1,
                &user1.user_id,
                &hex::encode(crypto::generate_nonce()),
                &hex::encode(crypto::generate_secret_key()),
                "password1").unwrap();

        let ctx2 =
            UserContext::default_new(
                &username2,
                &user2.user_id,
                &hex::encode(crypto::generate_nonce()),
                &hex::encode(crypto::generate_secret_key()),
                "password2").unwrap();

        assert_eq!(1, user_repo.create(&ctx1, &user1).await.unwrap());
        assert_eq!(1, user_repo.create(&ctx2, &user2).await.unwrap());

        let vault = Vault::new(user1.user_id.as_str(), "title", VaultKind::Logins);
        assert_eq!(1, vault_repo.create(&ctx1, &vault).await.unwrap());

        for i in 0..2 {
            // WHEN creating an account
            let mut account = Account::new(&vault.vault_id, AccountKind::Login);
            account.details.username = Some(format!("user_{}", i.clone()));
            account.details.email = Some(format!("email_{}@domain.io", i.clone()));
            account.credentials.password = Some(format!("pass_{}", i.clone()));
            assert_eq!(1, account_repo.create(&ctx1, &account).await.unwrap());
        }

        // User 1 owns the accounts so it should be able to find the accounts
        let res1 = account_repo
            .find(
                &ctx1,
                HashMap::from([("vault_id".into(), vault.vault_id.clone())]),
                0,
                500,
            )
            .await
            .unwrap();
        assert_eq!(2, res1.records.len());

        // User 2 does not own the accounts so it should not be able to find the accounts
        let res2 = account_repo
            .find(
                &ctx2,
                HashMap::from([("vault_id".into(), vault.vault_id.clone())]),
                0,
                500,
            )
            .await
            .unwrap();
        assert_eq!(0, res2.records.len());
        let size = share_repo.share_vault(&ctx1, &vault.vault_id, &username2, true).await.unwrap();
        assert_eq!(1, size);

        // invoke following method to read inbox
        let (vault_size, account_size) = share_repo.handle_shared_vaults_accounts(&ctx2).await.unwrap();
        assert_eq!(1, vault_size);
        assert_eq!(0, account_size);

        // User 2 should now have access to the vault.
        let _ = vault_repo
            .get(
                &ctx2,
                &vault.vault_id,
            )
            .await
            .unwrap();

        // User 2 should now have access to all accounts in shared vault.
        let res4 = account_repo
            .find(
                &ctx2,
                HashMap::from([("vault_id".into(), vault.vault_id.clone())]),
                0,
                500,
            )
            .await
            .unwrap();
        assert_eq!(2, res4.records.len());

        // User 2 should not be able to update and accounts for read permissions.
        for mut account in res4.records {
            account.details.url = Some(Uuid::new_v4().to_string());
            assert!(account_repo.update(&ctx2, &account).await.is_err());
            assert!(account_repo.delete(&ctx2, &account.details.account_id).await.is_err());
        }

        // User 2 should not be able to create accounts for read permissions.
        for i in 0..2 {
            let mut account = Account::new(&vault.vault_id, AccountKind::Login);
            account.details.username = Some(format!("user_{}", i.clone()));
            account.details.email = Some(format!("email_{}@domain.io", i.clone()));
            account.credentials.password = Some(format!("pass_{}", i.clone()));
            assert!(account_repo.create(&ctx2, &account).await.is_err());
        }
    }

    #[tokio::test]
    async fn test_should_share_account() {
        let config = PassConfig::new();
        // GIVEN a user, vault and account repositories
        let user_repo = create_user_repository(&config).await.unwrap();
        let vault_repo = create_vault_repository(&config).await.unwrap();
        let account_repo = create_account_repository(&config).await.unwrap();
        let share_repo = create_share_vault_account_repository(&config).await.unwrap();

        // Due to referential integrity, we must first create a user and a vault.
        let username1 = Uuid::new_v4().to_string();
        let username2 = Uuid::new_v4().to_string();
        let user1 = User::new(username1.as_str(), None, None);
        let user2 = User::new(username2.as_str(), None, None);

        let ctx1 =
            UserContext::default_new(
                &username1,
                &user1.user_id,
                &hex::encode(crypto::generate_nonce()),
                &hex::encode(crypto::generate_secret_key()),
                "password1").unwrap();

        let ctx2 =
            UserContext::default_new(
                &username2,
                &user2.user_id,
                &hex::encode(crypto::generate_nonce()),
                &hex::encode(crypto::generate_secret_key()),
                "password2").unwrap();

        assert_eq!(1, user_repo.create(&ctx1, &user1).await.unwrap());
        assert_eq!(1, user_repo.create(&ctx2, &user2).await.unwrap());

        let vault = Vault::new(user1.user_id.as_str(), "title", VaultKind::Logins);
        assert_eq!(1, vault_repo.create(&ctx1, &vault).await.unwrap());

        for i in 0..2 {
            // WHEN creating an account
            let mut account = Account::new(&vault.vault_id, AccountKind::Login);
            account.details.username = Some(format!("user_{}", i.clone()));
            account.details.email = Some(format!("email_{}@domain.io", i.clone()));
            account.credentials.password = Some(format!("pass_{}", i.clone()));
            assert_eq!(1, account_repo.create(&ctx1, &account).await.unwrap());
        }

        // User 1 owns the accounts so it should be able to find the accounts
        let res1 = account_repo
            .find(
                &ctx1,
                HashMap::from([("vault_id".into(), vault.vault_id.clone())]),
                0,
                500,
            )
            .await
            .unwrap();
        assert_eq!(2, res1.records.len());

        // User 2 does not own the accounts so it should not be able to find the accounts
        let res2 = account_repo
            .find(
                &ctx2,
                HashMap::from([("vault_id".into(), vault.vault_id.clone())]),
                0,
                500,
            )
            .await
            .unwrap();
        assert_eq!(0, res2.records.len());
        // WHEN sharing account with the same username then it should fail
        assert!(share_repo.share_account(&ctx1, &res1.records[0].details.account_id, &username1).await.is_err());

        // WHEN sharing account with another user THEN it should succeed
        let size = share_repo.share_account(&ctx1, &res1.records[0].details.account_id, &username2).await.unwrap();
        assert_eq!(1, size);

        // invoke following method to read inbox
        // WHEN importing account without having a vault THEN it should not handle share
        let (vault_size, account_size) = share_repo.handle_shared_vaults_accounts(&ctx2).await.unwrap();
        assert_eq!(0, vault_size);
        assert_eq!(0, account_size);

        let vault2 = Vault::new(user2.user_id.as_str(), "title2", VaultKind::FormData);
        assert_eq!(1, vault_repo.create(&ctx2, &vault2).await.unwrap());

        // WHEN sharing account with another user THEN it should succeed
        let size = share_repo.share_account(&ctx1, &res1.records[0].details.account_id, &username2).await.unwrap();
        assert_eq!(1, size);

        // Now we should be able to import shared account
        let (vault_size, account_size) = share_repo.handle_shared_vaults_accounts(&ctx2).await.unwrap();
        assert_eq!(0, vault_size);
        assert_eq!(1, account_size);


        // User 2 should now have access to account in their vault.
        let _ = vault_repo
            .get(
                &ctx2,
                &vault2.vault_id,
            )
            .await
            .unwrap();

        // User 2 should now have access to all accounts in shared vault.
        let res4 = account_repo
            .find(
                &ctx2,
                HashMap::from([("vault_id".into(), vault2.vault_id.clone())]),
                0,
                500,
            )
            .await
            .unwrap();
        assert_eq!(1, res4.records.len());
        assert_eq!(&res1.records[0].details.username, &res4.records[0].details.username);
    }
}
