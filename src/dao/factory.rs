use std::sync::Arc;

use diesel::r2d2::ConnectionManager;
use diesel::SqliteConnection;
use lazy_static::lazy_static;
use r2d2::Pool;

use crate::dao::account_repository_impl::AccountRepositoryImpl;
use crate::dao::crypto_key_repository_impl::CryptoKeyRepositoryImpl;
use crate::dao::login_session_repository_impl::LoginSessionRepositoryImpl;
use crate::dao::lookup_repository_impl::LookupRepositoryImpl;
use crate::dao::message_repository_impl::MessageRepositoryImpl;
use crate::dao::setting_repository_impl::SettingRepositoryImpl;
use crate::dao::user_repository_impl::UserRepositoryImpl;
use crate::dao::user_vault_repository_impl::UserVaultRepositoryImpl;
use crate::dao::vault_repository_impl::VaultRepositoryImpl;
use crate::dao::{
    common, invoke_with_retry_attempts, CryptoKeyRepository, LoginSessionRepository,
    LookupRepository, MessageRepository, RetryableRepository, SettingRepository, UserRepository,
    UserVaultRepository,
};
use crate::dao::{AccountRepository, DbPool, VaultRepository};
use crate::domain::models::{PassConfig, PassResult};

lazy_static! {
    static ref POOL: DbPool = {
        let config = PassConfig::new();
        common::build_sqlite_pool(&config).expect("Failed to create db pool")
    };
}

// factory to method to create retryable user repository
pub async fn create_user_repository(
    config: &PassConfig,
) -> PassResult<Arc<dyn UserRepository + Send + Sync>> {
    Ok(Arc::new(RetryableRepository::new(
        config,
        Arc::new(UserRepositoryImpl::new(
            POOL.clone(),
            create_crypto_key_repository(config).await?,
        )),
    )))
}

// factory to method to create retryable login-session repository
pub async fn create_login_session_repository(
    _config: &PassConfig,
) -> PassResult<Arc<dyn LoginSessionRepository + Send + Sync>> {
    Ok(Arc::new(LoginSessionRepositoryImpl::new(POOL.clone())))
}

// factory to method to create retryable crypto-key repository
pub async fn create_crypto_key_repository(
    _: &PassConfig,
) -> PassResult<Arc<dyn CryptoKeyRepository + Send + Sync>> {
    Ok(Arc::new(CryptoKeyRepositoryImpl::new()))
}

// factory to method to create retryable vault repository
pub async fn create_vault_repository(
    config: &PassConfig,
) -> PassResult<Arc<dyn VaultRepository + Send + Sync>> {
    Ok(Arc::new(RetryableRepository::new(
        config,
        Arc::new(VaultRepositoryImpl::new(
            config.max_vaults_per_user.clone(),
            POOL.clone(),
            create_user_vault_repository(config).await?,
            create_user_repository(config).await?,
            create_crypto_key_repository(config).await?,
        )),
    )))
}

// factory to method to create retryable user-vault repository
pub async fn create_user_vault_repository(
    _config: &PassConfig,
) -> PassResult<Arc<dyn UserVaultRepository + Send + Sync>> {
    Ok(Arc::new(UserVaultRepositoryImpl::new()))
}

// factory to method to create retryable account repository
pub async fn create_account_repository(
    config: &PassConfig,
) -> PassResult<Arc<dyn AccountRepository + Send + Sync>> {
    Ok(Arc::new(RetryableRepository::new(
        config,
        Arc::new(AccountRepositoryImpl::new(
            config.max_vaults_per_user.clone(),
            config.max_accounts_per_vault.clone(),
            POOL.clone(),
            create_user_vault_repository(config).await?,
            create_vault_repository(config).await?,
            create_user_repository(config).await?,
            create_crypto_key_repository(config).await?,
        )),
    )))
}

// factory to method to create retryable lookup repository
pub async fn create_lookup_repository(
    config: &PassConfig,
) -> PassResult<Arc<dyn LookupRepository + Send + Sync>> {
    Ok(Arc::new(RetryableRepository::new(
        config,
        Arc::new(LookupRepositoryImpl::new(POOL.clone())),
    )))
}

// factory to method to create retryable setting repository
pub async fn create_setting_repository(
    config: &PassConfig,
) -> PassResult<Arc<dyn SettingRepository + Send + Sync>> {
    Ok(Arc::new(RetryableRepository::new(
        config,
        Arc::new(SettingRepositoryImpl::new(POOL.clone())),
    )))
}

// factory to method to create retryable message repository
pub async fn create_message_repository(
    config: &PassConfig,
) -> PassResult<Arc<dyn MessageRepository + Send + Sync>> {
    Ok(Arc::new(RetryableRepository::new(
        config,
        Arc::new(MessageRepositoryImpl::new(
            POOL.clone(),
            create_user_repository(config).await?,
        )),
    )))
}

async fn create_db_pool(config: &PassConfig) -> Pool<ConnectionManager<SqliteConnection>> {
    invoke_with_retry_attempts(config, "get_pool", || async {
        common::build_sqlite_pool(config)
    })
    .await
    .expect("failed to create db pool")
}
