use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use diesel::r2d2::ConnectionManager;
use diesel::SqliteConnection;
use r2d2::{Pool, PooledConnection};
use rand::Rng;

use crate::dao::models::{AccountEntity, ACLEntity, AuditEntity, CryptoKeyEntity, LookupEntity, MessageEntity, SettingEntity, UserContext, UserEntity, UserVaultEntity, VaultEntity};
use crate::domain::error::PassError;
use crate::domain::models::{Account, AuditLog, LoginSession, Lookup, Message, PaginatedResult, PassConfig, PassResult, Setting, User, Vault};

pub mod account_repository_impl;
pub mod common;
mod crypto_key_repository_impl;
pub mod factory;
mod login_session_repository_impl;
pub mod lookup_repository_impl;
mod message_repository_impl;
pub mod models;
pub mod setting_repository_impl;
mod user_repository_impl;
pub mod vault_repository_impl;
pub mod share_vault_account_repository;
mod schema;
mod user_vault_repository_impl;
mod audit_repository_impl;
mod acl_repository_impl;

type DbPool = Pool<ConnectionManager<SqliteConnection>>;
pub type DbConnection = PooledConnection<ConnectionManager<SqliteConnection>>;

/// Base Repository interface.
#[async_trait]
pub trait Repository<T, E> {
    // create an entity.
    async fn create(&self, ctx: &UserContext, entity: &T) -> PassResult<usize>;

    // updates existing entity.
    async fn update(&self, ctx: &UserContext, entity: &T) -> PassResult<usize>;

    // get entity by id.
    async fn get(&self, ctx: &UserContext, id: &str) -> PassResult<T>;

    // delete the entity by id.
    async fn delete(&self, ctx: &UserContext, id: &str) -> PassResult<usize>;

    // get crypto key by id
    async fn get_crypto_key(&self, ctx: &UserContext, id: &str) -> PassResult<CryptoKeyEntity>;

    // get entity by id
    async fn get_entity(&self, ctx: &UserContext, id: &str) -> PassResult<E>;

    // find one entity by predication -- must have only one record, i.e., it will throw error if 0 or 2+ records exist.
    async fn find_one(
        &self,
        ctx: &UserContext,
        predicates: HashMap<String, String>,
    ) -> PassResult<T>;

    // find all entities by pagination.
    async fn find(
        &self,
        ctx: &UserContext,
        predicates: HashMap<String, String>,
        offset: i64,
        limit: usize,
    ) -> PassResult<PaginatedResult<T>>;

    // count all entities
    async fn count(
        &self,
        ctx: &UserContext,
        predicates: HashMap<String, String>,
    ) -> PassResult<i64>;
}

/// Repository interface for User.
#[async_trait]
pub trait UserRepository: Repository<User, UserEntity> {}

/// Repository interface for ACL.
#[async_trait]
pub trait ACLRepository: Repository<ACLEntity, ACLEntity> {}

/// Repository interface for LoginSession.
pub trait LoginSessionRepository {
    // create login session
    fn create(&self, session: &LoginSession) -> PassResult<usize>;

    // get crypto_key by id
    fn get(&self, id: &str) -> PassResult<LoginSession>;

    // delete an existing crypto_key.
    fn delete(&self, id: &str) -> PassResult<usize>;

    // delete_by_user_id delete all user audits
    fn delete_by_user_id(&self,
                         ctx: &UserContext,
                         user_id: &str,
                         c: &mut DbConnection,
    ) -> Result<usize, diesel::result::Error>;
}

/// Repository interface for Audit records.
pub trait AuditRepository {
    // create audit-record
    fn create(
        &self,
        entity: &AuditEntity,
        conn: &mut DbConnection,
    ) -> Result<usize, diesel::result::Error>;

    // find all
    fn find(
        &self,
        ctx: &UserContext,
        predicates: HashMap<String, String>,
        offset: i64,
        limit: usize,
    ) -> PassResult<PaginatedResult<AuditLog>>;

    fn count(
        &self,
        ctx: &UserContext,
        predicates: HashMap<String, String>,
    ) -> PassResult<i64>;

    // delete_by_user_id delete all user audits
    fn delete_by_user_id(&self,
                         ctx: &UserContext,
                         user_id: &str,
                         c: &mut DbConnection,
    ) -> Result<usize, diesel::result::Error>;
}

/// Repository interface for CryptoKey.
pub trait CryptoKeyRepository {
    // create crypto_key.
    fn create(
        &self,
        entity: &CryptoKeyEntity,
        conn: &mut DbConnection,
    ) -> Result<usize, diesel::result::Error>;

    // get crypto_key by id
    fn get(
        &self,
        match_user_id: &str,
        match_keyable_id: &str,
        match_keyable_type: &str,
        conn: &mut DbConnection,
    ) -> Result<CryptoKeyEntity, diesel::result::Error>;

    // delete an existing crypto_key.
    fn delete(
        &self,
        match_user_id: &str,
        match_keyable_id: &str,
        match_keyable_type: &str,
        conn: &mut DbConnection,
    ) -> Result<usize, diesel::result::Error>;
}

/// Repository interface for Vault.
#[async_trait]
pub trait VaultRepository: Repository<Vault, VaultEntity> {}

/// Repository interface for UserVault.
pub trait UserVaultRepository {
    // create user-vault
    fn create(
        &self,
        user_vault: &UserVaultEntity,
        conn: &mut DbConnection,
    ) -> Result<usize, diesel::result::Error>;

    // delete user-vault
    fn delete(
        &self,
        user_id: &str,
        vault_id: &str,
        conn: &mut DbConnection,
    ) -> Result<usize, diesel::result::Error>;

    // delete by vault-id user-vault
    fn delete_by_vault_id(
        &self,
        vault_id: &str,
        conn: &mut DbConnection,
    ) -> Result<usize, diesel::result::Error>;

    // find one entity by predication -- must have only one record, i.e., it will throw error if 0 or 2+ records exist.
    fn find_one(
        &self,
        predicates: HashMap<String, String>,
        conn: &mut DbConnection,
    ) -> PassResult<UserVaultEntity>;

    // find all
    fn find(
        &self,
        predicates: HashMap<String, String>,
        offset: i64,
        limit: usize,
        conn: &mut DbConnection,
    ) -> PassResult<PaginatedResult<UserVaultEntity>>;

    fn count(
        &self,
        predicates: HashMap<String, String>,
        conn: &mut DbConnection,
    ) -> PassResult<i64>;
}

/// Repository interface for sharing vaults or accounts.
#[async_trait]
pub trait ShareVaultAccountRepository {
    // share vault with another user
    async fn share_vault(
        &self,
        ctx: &UserContext,
        vault_id: &str,
        target_username: &str,
        read_only: bool,
    ) -> PassResult<usize>;

    // share account with another user
    async fn share_account(
        &self,
        ctx: &UserContext,
        account_id: &str,
        target_username: &str,
    ) -> PassResult<usize>;

    // lookup usernames
    async fn lookup_usernames(
        &self,
        ctx: &UserContext,
        q: &str,
    ) -> PassResult<Vec<String>>;

    // handle shared vaults and accounts from inbox of messages
    async fn handle_shared_vaults_accounts(
        &self,
        ctx: &UserContext,
    ) -> PassResult<(usize, usize)>;
}


/// Repository interface for Account.
#[async_trait]
pub trait AccountRepository: Repository<Account, AccountEntity> {}

/// Repository interface for Message.
#[async_trait]
pub trait MessageRepository: Repository<Message, MessageEntity> {}

/// Repository interface for Lookup.
#[async_trait]
pub trait LookupRepository: Repository<Lookup, LookupEntity> {}

/// Repository interface for Setting.
#[async_trait]
pub trait SettingRepository: Repository<Setting, SettingEntity> {}

#[derive(Clone)]
pub(crate) struct RetryableRepository<T, E> {
    config: PassConfig,
    delegate: Arc<dyn Repository<T, E> + Send + Sync>,
}

impl<T, E> RetryableRepository<T, E> {
    fn new(config: &PassConfig, delegate: Arc<dyn Repository<T, E> + Send + Sync>) -> Self {
        RetryableRepository {
            config: config.clone(),
            delegate,
        }
    }
}

#[async_trait]
impl<T: Sync + Send, E: Sync + Send> Repository<T, E> for RetryableRepository<T, E> {
    async fn create(&self, ctx: &UserContext, entity: &T) -> PassResult<usize> {
        invoke_with_retry_attempts(&self.config, "create", || async {
            self.delegate.create(ctx, entity).await
        })
            .await
    }

    async fn update(&self, ctx: &UserContext, entity: &T) -> PassResult<usize> {
        invoke_with_retry_attempts(&self.config, "update", || async {
            self.delegate.update(ctx, entity).await
        })
            .await
    }

    async fn get(&self, ctx: &UserContext, id: &str) -> PassResult<T> {
        invoke_with_retry_attempts(&self.config, "get", || async {
            self.delegate.get(ctx, id).await
        })
            .await
    }

    async fn delete(&self, ctx: &UserContext, id: &str) -> PassResult<usize> {
        invoke_with_retry_attempts(&self.config, "delete", || async {
            self.delegate.delete(ctx, id).await
        })
            .await
    }

    // get crypto key by id
    async fn get_crypto_key(&self, ctx: &UserContext, id: &str) -> PassResult<CryptoKeyEntity> {
        invoke_with_retry_attempts(&self.config, "get_crypto_key", || async {
            self.delegate.get_crypto_key(ctx, id).await
        })
            .await
    }

    // get entity by id
    async fn get_entity(&self, ctx: &UserContext, id: &str) -> PassResult<E> {
        invoke_with_retry_attempts(&self.config, "get_entity", || async {
            self.delegate.get_entity(ctx, id).await
        })
            .await
    }

    // find one entity by predication -- must have only one record, i.e., it will throw error if 0 or 2+ records exist.
    async fn find_one(
        &self,
        ctx: &UserContext,
        predicates: HashMap<String, String>,
    ) -> PassResult<T> {
        invoke_with_retry_attempts(&self.config, "find_one", || async {
            self.delegate.find_one(ctx, predicates.clone()).await
        })
            .await
    }

    // find all entities matching predicates with pagination
    async fn find(
        &self,
        ctx: &UserContext,
        predicates: HashMap<String, String>,
        offset: i64,
        limit: usize,
    ) -> PassResult<PaginatedResult<T>> {
        invoke_with_retry_attempts(&self.config, "find", || async {
            self.delegate
                .find(ctx, predicates.clone(), offset, limit)
                .await
        })
            .await
    }

    // count all entities
    async fn count(
        &self,
        ctx: &UserContext,
        predicates: HashMap<String, String>,
    ) -> PassResult<i64> {
        invoke_with_retry_attempts(&self.config, "count", || async {
            self.delegate.count(ctx, predicates.clone()).await
        })
            .await
    }
}

#[async_trait]
impl UserRepository for RetryableRepository<User, UserEntity> {}

#[async_trait]
impl ACLRepository for RetryableRepository<ACLEntity, ACLEntity> {}

#[async_trait]
impl VaultRepository for RetryableRepository<Vault, VaultEntity> {}

#[async_trait]
impl AccountRepository for RetryableRepository<Account, AccountEntity> {}

#[async_trait]
impl MessageRepository for RetryableRepository<Message, MessageEntity> {}

#[async_trait]
impl LookupRepository for RetryableRepository<Lookup, LookupEntity> {}

#[async_trait]
impl SettingRepository for RetryableRepository<Setting, SettingEntity> {}

#[derive(Clone)]
pub(crate) struct RetryableShareVaultAccountRepository {
    config: PassConfig,
    delegate: Arc<dyn ShareVaultAccountRepository + Sync + Send>,
}

impl RetryableShareVaultAccountRepository {
    fn new(config: &PassConfig, delegate: Arc<dyn ShareVaultAccountRepository + Sync + Send>) -> Self {
        Self {
            config: config.clone(),
            delegate,
        }
    }
}

#[async_trait]
impl ShareVaultAccountRepository for RetryableShareVaultAccountRepository {
    async fn share_vault(&self, ctx: &UserContext, vault_id: &str, target_user_id: &str, read_only: bool) -> PassResult<usize> {
        invoke_with_retry_attempts(&self.config, "share_vault", || async {
            self.delegate.share_vault(ctx, vault_id, target_user_id, read_only).await
        })
            .await
    }

    async fn share_account(&self, ctx: &UserContext, account_id: &str, target_user_id: &str) -> PassResult<usize> {
        invoke_with_retry_attempts(&self.config, "share_account", || async {
            self.delegate.share_account(ctx, account_id, target_user_id).await
        })
            .await
    }

    async fn lookup_usernames(&self, ctx: &UserContext, q: &str) -> PassResult<Vec<String>> {
        invoke_with_retry_attempts(&self.config, "lookup_usernames", || async {
            self.delegate.lookup_usernames(ctx, q).await
        })
            .await
    }

    async fn handle_shared_vaults_accounts(&self, ctx: &UserContext) -> PassResult<(usize, usize)> {
        invoke_with_retry_attempts(&self.config, "handle_shared_vaults_accounts", || async {
            self.delegate.handle_shared_vaults_accounts(ctx).await
        })
            .await
    }
}

async fn invoke_with_retry_attempts<T, F: Fn() -> R, R>(
    config: &PassConfig,
    msg: &str,
    f: F,
) -> PassResult<T>
    where
        R: Future<Output=PassResult<T>>,
{
    for i in 0..(config.max_retries) {
        match f().await {
            Ok(k) => {
                return Ok(k);
            }
            Err(err) => {
                if !err.retryable() || i == config.max_retries - 1 {
                    if let PassError::NotFound { .. } = err {} else {
                        log::debug!(
                            "error while invoking not retryable function {} due to {:?}",
                            msg,
                            err
                        );
                    }
                    return Err(err);
                }
                let jitter = rand::thread_rng().gen_range(10..(20 * (i + 1))) as u64;
                let delay = Duration::from_millis(
                    jitter + config.delay_between_retries * (i + 1) as u64,
                );
                log::debug!("error while invoking retryable function {} due to {:?}, will retry {}th time with delay {:?}", msg, err, i, delay);
                tokio::time::sleep(delay).await;
            }
        }
    }
    Err(PassError::runtime("error retrying", None))
}
