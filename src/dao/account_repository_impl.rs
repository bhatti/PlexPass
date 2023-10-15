use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use diesel::dsl::count;
use diesel::prelude::*;

use crate::dao::models::{AccountEntity, CryptoKeyEntity, UserContext};
use crate::dao::schema::accounts;
use crate::dao::schema::accounts::dsl::*;
use crate::dao::schema::archived_accounts;
use crate::dao::{
    AccountRepository, CryptoKeyRepository, DbConnection, DbPool, Repository, UserRepository,
    UserVaultRepository, VaultRepository,
};
use crate::domain::error::PassError;
use crate::domain::models::{Account, PaginatedResult, PassResult};

#[derive(Clone)]
pub(crate) struct AccountRepositoryImpl {
    max_vaults_per_user: u32,
    max_accounts_per_vault: u32,
    pool: DbPool,
    user_vault_repository: Arc<dyn UserVaultRepository + Send + Sync>,
    vault_repository: Arc<dyn VaultRepository + Send + Sync>,
    user_repository: Arc<dyn UserRepository + Send + Sync>,
    crypto_key_repository: Arc<dyn CryptoKeyRepository + Send + Sync>,
}

impl AccountRepositoryImpl {
    pub(crate) fn new(
        max_vaults_per_user: u32,
        max_accounts_per_vault: u32,
        pool: DbPool,
        user_vault_repository: Arc<dyn UserVaultRepository + Send + Sync>,
        vault_repository: Arc<dyn VaultRepository + Send + Sync>,
        user_repository: Arc<dyn UserRepository + Send + Sync>,
        crypto_key_repository: Arc<dyn CryptoKeyRepository + Send + Sync>,
    ) -> Self {
        AccountRepositoryImpl {
            max_vaults_per_user,
            max_accounts_per_vault,
            pool,
            user_vault_repository,
            vault_repository,
            user_repository,
            crypto_key_repository,
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

    async fn get_allowed_vault_ids(&self, ctx: &UserContext) -> PassResult<Vec<String>> {
        let vaults = self
            .vault_repository
            .find(
                ctx,
                HashMap::from([]),
                0,
                self.max_vaults_per_user.clone() as usize,
            )
            .await?;

        let vault_ids: Vec<String> = vaults
            .records
            .iter()
            .map(|v| v.vault_id.to_owned())
            .collect();
        Ok(vault_ids)
    }

    // verify that vault belongs to the user
    async fn validate_vault_belong_to_user(
        &self,
        ctx: &UserContext,
        other_user_id: &str,
        other_vault_id: &str,
    ) -> PassResult<()> {
        if ctx.is_admin() {
            return Ok(());
        }
        let mut conn = self.connection()?;

        let res = self.user_vault_repository.count(
            HashMap::from([
                ("user_id".into(), other_user_id.into()),
                ("vault_id".into(), other_vault_id.into()),
            ]),
            &mut conn,
        )?;

        if res == 0 {
            return Err(PassError::not_found(
                format!(
                    "vault {} not found for user {}",
                    other_vault_id, other_user_id
                )
                .as_str(),
            ));
        }
        Ok(())
    }

    // Update summary of accounts in vaults so that they can be displayed on the list view.
    async fn update_vault_account_entries(
        &self,
        ctx: &UserContext,
        account: &Account,
    ) -> PassResult<()> {
        let mut vault = self.vault_repository.get(ctx, &account.vault_id).await?;
        vault
            .entries
            .insert(account.details.account_id.clone(), account.details.clone());
        self.vault_repository.update(ctx, &vault).await?;
        Ok(())
    }

    // Update with deletion of account in vaults so that they can be displayed on the list view.
    async fn delete_vault_account_from_entries(
        &self,
        ctx: &UserContext,
        account: &Account,
    ) -> PassResult<()> {
        let mut vault = self.vault_repository.get(ctx, &account.vault_id).await?;
        vault.entries.remove(&account.details.account_id);
        self.vault_repository.update(ctx, &vault).await?;
        Ok(())
    }
}

#[async_trait]
impl AccountRepository for AccountRepositoryImpl {}

#[async_trait]
impl Repository<Account, AccountEntity> for AccountRepositoryImpl {
    // create account.
    async fn create(&self, ctx: &UserContext, account: &Account) -> PassResult<usize> {
        // ensure user can access vault
        let _ = self
            .validate_vault_belong_to_user(ctx, &ctx.user_id, &account.vault_id)
            .await?;

        // get crypto key from vault
        let vault_crypto_key = self
            .vault_repository
            .get_crypto_key(ctx, &account.vault_id)
            .await?;

        // checking existing accounts for the vault.
        let count = self
            .count(
                ctx,
                HashMap::from([("vault_id".into(), account.vault_id.clone())]),
            )
            .await?;
        if count > self.max_accounts_per_vault.clone() as i64 {
            return Err(PassError::validation(
                format!("too many accounts {} for the vault, please create a new vault for storing additional accounts.", count).as_str(),
                None,
            ));
        }

        let mut account = account.clone();
        account.before_save();

        let user_crypto_key = self
            .user_repository
            .get_crypto_key(ctx, &ctx.user_id)
            .await?;
        let (account_entity, account_crypto_key) = AccountEntity::from_context_vault_account(
            ctx,
            &user_crypto_key,
            &vault_crypto_key,
            &account,
        )?;

        let mut conn = self.connection()?;

        // add account and crypto key in a transaction
        let size = conn.transaction(|c| {
            let _ = diesel::insert_into(accounts::table)
                .values(&account_entity)
                .execute(c)?;
            self.crypto_key_repository.create(&account_crypto_key, c)
        })?;

        if size > 0 {
            log::debug!("created account {:?} {}", account_entity, size);
            let _ = self.update_vault_account_entries(ctx, &account).await?;
            Ok(size)
        } else {
            Err(PassError::database(
                format!("failed to insert {}", account_entity.account_id).as_str(),
                None,
                false,
            ))
        }
    }

    // updates existing account.
    async fn update(&self, ctx: &UserContext, account: &Account) -> PassResult<usize> {
        // validate vault id belongs to user
        let _ = self
            .validate_vault_belong_to_user(ctx, &ctx.user_id, &account.vault_id)
            .await?;

        let mut account = account.clone();
        account.before_save();

        // finding user crypto
        let user_crypto_key = self
            .user_repository
            .get_crypto_key(ctx, &ctx.user_id)
            .await?;

        // finding vault crypto
        let vault_crypto_key = self
            .vault_repository
            .get_crypto_key(ctx, &account.vault_id)
            .await?;

        let mut account_entity = self.get_entity(ctx, &account.details.account_id).await?;
        let account_crypto_key = self
            .get_crypto_key(ctx, &account.details.account_id)
            .await?;

        // checking version for concurrency control
        account_entity.match_version(account.details.version.clone())?;

        // update account
        account_entity.update_from_context_vault_account(
            ctx,
            &user_crypto_key,
            &vault_crypto_key,
            &account,
            &account_crypto_key,
        )?;

        let mut conn = self.connection()?;

        let size = conn.transaction(|c| {
            if let Some(other_credentials_updated_at) = account.details.credentials_updated_at {
                if other_credentials_updated_at.timestamp_millis()
                    > account_entity.credentials_updated_at.timestamp_millis()
                {
                    account_entity.credentials_updated_at = other_credentials_updated_at;
                    let archived = account_entity.to_archived(&account_crypto_key);
                    let _ = diesel::insert_into(archived_accounts::table)
                        .values(archived)
                        .execute(c)?;
                }
            }

            diesel::update(
                accounts.filter(
                    version
                        .eq(account.details.version.clone())
                        .and(account_id.eq(&account.details.account_id)),
                ),
            )
            .set((
                version.eq(account_entity.version.clone() + 1),
                archived_version.eq(&account_entity.archived_version),
                salt.eq(&account_entity.salt),
                nonce.eq(&account_entity.nonce),
                encrypted_value.eq(&account_entity.encrypted_value),
                archived_version.eq(&account_entity.archived_version),
                credentials_updated_at.eq(&account_entity.credentials_updated_at),
                updated_at.eq(Utc::now().naive_utc()),
            ))
            .execute(c)
        })?;

        if size > 0 {
            log::debug!("updated account {:?} {}", account, size);
            let _ = self.update_vault_account_entries(ctx, &account).await?;
            Ok(size)
        } else {
            Err(PassError::database(
                format!(
                    "failed to update account {} version {:?}",
                    account.details.account_id, account.details.version
                )
                .as_str(),
                None,
                false,
            ))
        }
    }

    // get account by id
    async fn get(&self, ctx: &UserContext, id: &str) -> PassResult<Account> {
        // finding account crypto
        let account_crypto_key = self.get_crypto_key(ctx, id).await?;

        let account_entity = self.get_entity(ctx, id).await?;
        // verify user has access to vault
        let _ = self
            .validate_vault_belong_to_user(ctx, &ctx.user_id, &account_entity.vault_id)
            .await?;

        // finding user crypto
        let user_crypto_key = self
            .user_repository
            .get_crypto_key(ctx, &ctx.user_id)
            .await?;

        // finding vault crypto
        let vault_crypto_key = self
            .vault_repository
            .get_crypto_key(ctx, &account_entity.vault_id)
            .await?;

        account_entity.to_account(
            ctx,
            &user_crypto_key,
            &vault_crypto_key,
            &account_crypto_key,
        )
    }

    // delete an existing account.
    async fn delete(&self, ctx: &UserContext, id: &str) -> PassResult<usize> {
        let account = self.get(ctx, id).await?;

        // verify user has access to vault
        let _ = self
            .validate_vault_belong_to_user(ctx, &ctx.user_id, &account.vault_id)
            .await?;

        let mut conn = self.connection()?;
        let size = diesel::delete(accounts.filter(account_id.eq(id))).execute(&mut conn)?;
        if size > 0 {
            log::debug!("deleted account {}", id);
            let _ = self
                .delete_vault_account_from_entries(ctx, &account)
                .await?;
            Ok(size)
        } else {
            Err(PassError::database(
                format!("failed to find records for deleting {}", id).as_str(),
                None,
                false,
            ))
        }
    }

    // find crypto key by id
    async fn get_crypto_key(&self, ctx: &UserContext, id: &str) -> PassResult<CryptoKeyEntity> {
        let mut conn = self.connection()?;
        let crypto_key = self
            .crypto_key_repository
            .get(&ctx.user_id, id, "Account", &mut conn)?;
        ctx.validate_user_id(&crypto_key.user_id)?;
        Ok(crypto_key)
    }

    // find account-entity by id
    async fn get_entity(&self, _: &UserContext, id: &str) -> PassResult<AccountEntity> {
        let mut conn = self.connection()?;
        let mut items = accounts
            .filter(account_id.eq(&id))
            .limit(2)
            .load::<AccountEntity>(&mut conn)?;

        if items.len() > 1 {
            return Err(PassError::database(
                format!("too many accounts for {}", id).as_str(),
                None,
                false,
            ));
        } else if items.is_empty() {
            return Err(PassError::not_found(
                format!("account not found for key {}", id).as_str(),
            ));
        }
        Ok(items.remove(0))
    }

    // find one entity by predication -- must have only one record, i.e., it will throw error if 0 or 2+ records exist.
    async fn find_one(
        &self,
        ctx: &UserContext,
        predicates: HashMap<String, String>,
    ) -> PassResult<Account> {
        let mut res = self.find(ctx, predicates, 0, 5).await?;
        if res.records.len() != 1 {
            return Err(PassError::authorization(
                format!(
                    "could not find account with predicates - [{}]",
                    res.records.len()
                )
                .as_str(),
            ));
        }

        Ok(res.records.remove(0))
    }

    // find accounts with pagination
    async fn find(
        &self,
        ctx: &UserContext,
        predicates: HashMap<String, String>,
        offset: i64,
        limit: usize,
    ) -> PassResult<PaginatedResult<Account>> {
        let vault_ids = self.get_allowed_vault_ids(ctx).await?;

        // finding user crypto
        let user_crypto_key = self
            .user_repository
            .get_crypto_key(ctx, &ctx.user_id)
            .await?;

        let mut conn = self.connection()?;
        let match_vault_id = format!(
            "%{}%",
            predicates
                .get("vault_id")
                .cloned()
                .unwrap_or(String::from(""))
        );

        let entities = accounts
            .filter(
                vault_id
                    .like(match_vault_id)
                    .and(vault_id.eq_any(vault_ids)),
            )
            .offset(offset)
            .limit(limit as i64)
            .order(accounts::created_at)
            .load::<AccountEntity>(&mut conn)?;
        let mut res = vec![];
        for entity in entities {
            // finding vault crypto
            let vault_crypto_key = self
                .vault_repository
                .get_crypto_key(ctx, &entity.vault_id)
                .await?;

            // finding account crypto
            let account_crypto_key = self.get_crypto_key(ctx, &entity.account_id).await?;
            res.push(entity.to_account(
                ctx,
                &user_crypto_key,
                &vault_crypto_key,
                &account_crypto_key,
            )?)
        }

        Ok(PaginatedResult::new(offset.clone(), limit.clone(), res))
    }

    async fn count(
        &self,
        ctx: &UserContext,
        predicates: HashMap<String, String>,
    ) -> PassResult<i64> {
        let vault_ids = self.get_allowed_vault_ids(ctx).await?;

        let match_vault_id = format!(
            "%{}%",
            predicates
                .get("vault_id")
                .cloned()
                .unwrap_or(String::from(""))
        );

        let mut conn = self.connection()?;
        match accounts
            .filter(
                vault_id
                    .like(match_vault_id)
                    .and(vault_id.eq_any(vault_ids)),
            )
            .select(count(account_id))
            .first::<i64>(&mut conn)
        {
            Ok(count) => Ok(count),
            Err(err) => Err(PassError::from(err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use uuid::Uuid;

    use crate::crypto;
    use crate::dao::factory::{
        create_account_repository, create_user_repository, create_vault_repository,
    };
    use crate::dao::models::UserContext;
    use crate::domain::models::{Account, PassConfig, User, Vault};

    #[tokio::test]
    async fn test_should_create_update_accounts() {
        let config = PassConfig::new();
        // GIVEN a user, vault and account repositories
        let user_repo = create_user_repository(&config).await.unwrap();
        let vault_repo = create_vault_repository(&config).await.unwrap();
        let account_repo = create_account_repository(&config).await.unwrap();

        // Due to referential integrity, we must first create a valid user and a vault
        let username = Uuid::new_v4().to_string();
        let user = User::new(username.as_str(), None, None);
        let salt = hex::encode(crypto::generate_nonce());
        let pepper = hex::encode(crypto::generate_secret_key());

        let ctx =
            UserContext::default_new(&username, &user.user_id, &salt, &pepper, "password").unwrap();
        assert_eq!(1, user_repo.create(&ctx, &user).await.unwrap());

        let vault = Vault::new(user.user_id.as_str(), "title");
        assert_eq!(1, vault_repo.create(&ctx, &vault).await.unwrap());

        // WHEN creating an account
        let mut account = Account::new(&vault.vault_id);

        // THEN it should succeed
        assert_eq!(1, account_repo.create(&ctx, &account).await.unwrap());

        // WHEN updating an account
        account.details.username = Some("new-user".into());
        account.credentials.password = Some("new-pass".into());
        // THEN it should succeed updating.
        assert_eq!(1, account_repo.update(&ctx, &account).await.unwrap());

        // WHEN retrieving the account
        let loaded = account_repo
            .get(&ctx, &account.details.account_id)
            .await
            .unwrap();

        // THEN account should have updated attributes.
        assert_eq!(2, loaded.details.version);
        assert_eq!(Some("new-user".into()), loaded.details.username);
        assert_eq!(Some("new-pass".into()), loaded.credentials.password);
        assert_eq!(vault.vault_id, loaded.vault_id);
    }

    #[tokio::test]
    async fn test_should_create_delete_accounts() {
        let config = PassConfig::new();
        // GIVEN a user, vault and account repositories
        let user_repo = create_user_repository(&config).await.unwrap();
        let vault_repo = create_vault_repository(&config).await.unwrap();
        let account_repo = create_account_repository(&config).await.unwrap();

        let salt = hex::encode(crypto::generate_nonce());
        let pepper = hex::encode(crypto::generate_secret_key());
        // Due to referential integrity, we must first create a valid user and a vault
        let username = Uuid::new_v4().to_string();
        let user = User::new(username.as_str(), None, None);

        let ctx =
            UserContext::default_new(&username, &user.user_id, &salt, &pepper, "password").unwrap();

        assert_eq!(1, user_repo.create(&ctx, &user).await.unwrap());

        let vault = Vault::new(user.user_id.as_str(), "title");
        assert_eq!(1, vault_repo.create(&ctx, &vault).await.unwrap());

        // WHEN creating an account
        let account = Account::new(&vault.vault_id);

        // THEN it should succeed
        assert_eq!(1, account_repo.create(&ctx, &account).await.unwrap());

        // WHEN deleting the account
        let deleted = account_repo
            .delete(&ctx, &account.details.account_id)
            .await
            .unwrap();
        // THEN it should succeed.
        assert_eq!(1, deleted);

        // WHEN retrieving the account after deleting it THEN it should fail.
        assert!(account_repo
            .get(&ctx, &account.details.account_id)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_should_create_find_accounts() {
        let config = PassConfig::new();
        // GIVEN a user, vault and account repositories
        let user_repo = create_user_repository(&config).await.unwrap();
        let vault_repo = create_vault_repository(&config).await.unwrap();
        let account_repo = create_account_repository(&config).await.unwrap();

        let salt = hex::encode(crypto::generate_nonce());
        let pepper = hex::encode(crypto::generate_secret_key());
        // Due to referential integrity, we must first create a user and a vault.
        let username = Uuid::new_v4().to_string();
        let user = User::new(username.as_str(), None, None);

        let ctx =
            UserContext::default_new(&username, &user.user_id, &salt, &pepper, "password").unwrap();

        assert_eq!(1, user_repo.create(&ctx, &user).await.unwrap());

        let vault = Vault::new(user.user_id.as_str(), "title");
        assert_eq!(1, vault_repo.create(&ctx, &vault).await.unwrap());

        for _i in 0..3 {
            // WHEN creating an account
            let account = Account::new(&vault.vault_id);
            // THEN it should succeed
            assert_eq!(1, account_repo.create(&ctx, &account).await.unwrap());
        }

        let res1 = account_repo
            .find(
                &ctx,
                HashMap::from([("vault_id".into(), vault.vault_id.clone())]),
                0,
                500,
            )
            .await
            .unwrap();
        assert_eq!(3, res1.records.len());
        let count1 = account_repo
            .count(
                &ctx,
                HashMap::from([("vault_id".into(), vault.vault_id.clone())]),
            )
            .await
            .unwrap();
        assert_eq!(3, count1);

        let res2 = account_repo
            .find(
                &ctx,
                HashMap::from([("vault_id".into(), "foo".into())]),
                0,
                500,
            )
            .await
            .unwrap();
        assert_eq!(0, res2.records.len());
        let count2 = account_repo
            .count(&ctx, HashMap::from([("vault_id".into(), "foo".into())]))
            .await
            .unwrap();
        assert_eq!(0, count2);
    }
}
