use prometheus::default_registry;
use std::sync::Arc;

use crate::dao::factory::{
    create_account_repository, create_login_session_repository, create_lookup_repository,
    create_message_repository, create_setting_repository, create_user_repository,
    create_vault_repository,
};
use crate::domain::models::{PassConfig, PassResult};
use crate::service::account_service_impl::AccountServiceImpl;
use crate::service::lookup_service_impl::LookupServiceImpl;
use crate::service::message_service_impl::MessageServiceImpl;
use crate::service::password_service_impl::PasswordServiceImpl;
use crate::service::setting_service_impl::SettingServiceImpl;
use crate::service::user_service_impl::UserServiceImpl;
use crate::service::vault_service_impl::VaultServiceImpl;
use crate::service::{
    AccountService, LookupService, MessageService, PasswordService, SettingService, UserService,
    VaultService,
};
use crate::store::factory::create_hsm_store;

// factory to method to create user-service
pub async fn create_user_service(
    config: &PassConfig,
) -> PassResult<Arc<dyn UserService + Send + Sync>> {
    let hsm_store = create_hsm_store(config)?;
    let user_repository = create_user_repository(config).await?;
    let login_session_repository = create_login_session_repository(config).await?;
    Ok(Arc::new(UserServiceImpl::new(
        config,
        hsm_store,
        user_repository,
        login_session_repository,
        default_registry(),
    )?))
}

// factory to method to create vault-service
pub async fn create_vault_service(
    config: &PassConfig,
) -> PassResult<Arc<dyn VaultService + Send + Sync>> {
    let vault_repository = create_vault_repository(config).await?;
    Ok(Arc::new(VaultServiceImpl::new(
        config,
        vault_repository,
        default_registry(),
    )?))
}

// factory to method to create account-service
pub async fn create_account_service(
    config: &PassConfig,
) -> PassResult<Arc<dyn AccountService + Send + Sync>> {
    let account_repository = create_account_repository(config).await?;
    Ok(Arc::new(AccountServiceImpl::new(
        config,
        account_repository,
        default_registry(),
    )?))
}

// factory to method to create message-service
pub async fn create_message_service(
    config: &PassConfig,
) -> PassResult<Arc<dyn MessageService + Send + Sync>> {
    let message_repository = create_message_repository(config).await?;
    Ok(Arc::new(MessageServiceImpl::new(
        config,
        message_repository,
        default_registry(),
    )?))
}

// factory to method to create setting-service
pub async fn create_setting_service(
    config: &PassConfig,
) -> PassResult<Arc<dyn SettingService + Send + Sync>> {
    let setting_repository = create_setting_repository(config).await?;
    Ok(Arc::new(SettingServiceImpl::new(
        config,
        setting_repository,
        default_registry(),
    )?))
}

// factory to method to create lookup-service
pub async fn create_lookup_service(
    config: &PassConfig,
) -> PassResult<Arc<dyn LookupService + Send + Sync>> {
    let lookup_repository = create_lookup_repository(config).await?;
    Ok(Arc::new(LookupServiceImpl::new(
        config,
        lookup_repository,
        default_registry(),
    )?))
}

// factory to method to create password-service
pub async fn create_password_service(
    _config: &PassConfig,
) -> PassResult<Arc<dyn PasswordService + Send + Sync>> {
    Ok(Arc::new(PasswordServiceImpl::new()))
}
