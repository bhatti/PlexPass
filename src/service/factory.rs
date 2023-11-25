use prometheus::default_registry;
use std::sync::Arc;
use crate::background::Scheduler;

use crate::dao::factory::{create_account_repository, create_audit_repository, create_login_session_repository, create_lookup_repository, create_message_repository, create_setting_repository, create_share_vault_account_repository, create_user_lookup_repository, create_user_repository, create_vault_repository};
use crate::domain::models::{PassConfig, PassResult};
use crate::service::account_service_impl::AccountServiceImpl;
use crate::service::lookup_service_impl::LookupServiceImpl;
use crate::service::message_service_impl::MessageServiceImpl;
use crate::service::password_service_impl::PasswordServiceImpl;
use crate::service::setting_service_impl::SettingServiceImpl;
use crate::service::user_service_impl::UserServiceImpl;
use crate::service::vault_service_impl::VaultServiceImpl;
use crate::service::{AccountService, AuditLogService, EncryptionService, ImportExportService, LookupService, MessageService, OTPService, PasswordService, SettingService, ShareVaultAccountService, UserService, VaultService, AuthenticationService};
use crate::service::audit_service_impl::AuditLogServiceImpl;
use crate::service::encryption_service_impl::EncryptionServiceImpl;
use crate::service::import_export_service_impl::ImportExportServiceImpl;
use crate::service::otp_service_impl::OTPServiceImpl;
use crate::service::share_vault_account_service_impl::ShareVaultAccountServiceImpl;
use crate::service::authentication_service_impl::AuthenticationServiceImpl;
use crate::store::factory::create_hsm_store;

// factory to method to create user-service
pub async fn create_user_service(
    config: &PassConfig,
) -> PassResult<Arc<dyn UserService + Send + Sync>> {
    let hsm_store = create_hsm_store(config)?;
    let user_repository = create_user_repository(config).await?;
    let user_lookup_repository = create_user_lookup_repository(config).await?;
    let vault_repository = create_vault_repository(config).await?;
    Ok(Arc::new(UserServiceImpl::new(
        config,
        hsm_store,
        user_repository,
        user_lookup_repository,
        vault_repository,
        create_encryption_service(config).await?,
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

// factory to method to create encryption-service
pub async fn create_encryption_service(
    config: &PassConfig,
) -> PassResult<Arc<dyn EncryptionService + Send + Sync>> {
    Ok(Arc::new(EncryptionServiceImpl::new(
        config,
    )))
}

// factory to method to create share-vault-account-service
pub async fn create_share_vault_account_service(
    config: &PassConfig,
) -> PassResult<Arc<dyn ShareVaultAccountService + Send + Sync>> {
    let share_vault_account_repository = create_share_vault_account_repository(config).await?;
    Ok(Arc::new(ShareVaultAccountServiceImpl::new(
        config,
        share_vault_account_repository,
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

// factory to method to create import-export-service
pub async fn create_import_export_service(
    config: &PassConfig,
) -> PassResult<Arc<dyn ImportExportService + Send + Sync>> {
    let vault_service = create_vault_service(config).await?;
    let account_service = create_account_service(config).await?;
    let encryption_service = create_encryption_service(config).await?;
    Ok(Arc::new(ImportExportServiceImpl::new(
        vault_service,
        account_service,
        encryption_service,
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
    config: &PassConfig,
) -> PassResult<Arc<dyn PasswordService + Send + Sync>> {
    let scheduler = Arc::new(Scheduler::new());
    Ok(Arc::new(PasswordServiceImpl::new(
        config,
        create_vault_service(config).await?,
        create_account_service(config).await?,
        scheduler,
        default_registry(),
    )?))
}

// factory to method to create audit-log-service
pub async fn create_audit_log_service(
    config: &PassConfig,
) -> PassResult<Arc<dyn AuditLogService + Send + Sync>> {
    Ok(Arc::new(AuditLogServiceImpl::new(
        config,
        create_audit_repository(config).await?,
        default_registry(),
    )?))
}

// factory to method to create otp-service
pub async fn create_otp_service(
    config: &PassConfig,
) -> PassResult<Arc<dyn OTPService + Send + Sync>> {
    Ok(Arc::new(OTPServiceImpl::new(
        config,
        default_registry(),
    )?))
}

// factory to method to create webauthn-service
pub async fn create_auth_service(
    config: &PassConfig,
) -> PassResult<Arc<dyn AuthenticationService + Send + Sync>> {
    Ok(Arc::new(AuthenticationServiceImpl::new(
        config,
        create_hsm_store(config)?,
        create_user_repository(config).await?,
        create_login_session_repository(config).await?,
        create_share_vault_account_repository(config).await?,
        create_password_service(config).await?,
        default_registry(),
    )?))
}
