use std::sync::Arc;

use crate::background::Scheduler;
use crate::dao::factory::create_login_session_repository;
use crate::dao::LoginSessionRepository;
use crate::domain::models::{PassConfig, PassResult};
use crate::service::{AccountService, AuditLogService, EncryptionService, ImportExportService, LookupService, MessageService, OTPService, PasswordService, SettingService, ShareVaultAccountService, UserService, VaultService, AuthenticationService};
use crate::service::factory::{create_account_service, create_audit_log_service, create_encryption_service, create_import_export_service, create_lookup_service, create_message_service, create_otp_service, create_password_service, create_setting_service, create_share_vault_account_service, create_user_service, create_vault_service, create_auth_service};
use crate::store::factory::create_hsm_store;
use crate::store::HSMStore;

#[derive(Clone)]
pub struct ServiceLocator {
    pub config: PassConfig,
    pub user_service: Arc<dyn UserService + Send + Sync>,
    pub login_session_repository: Arc<dyn LoginSessionRepository + Send + Sync>,
    pub vault_service: Arc<dyn VaultService + Send + Sync>,
    pub account_service: Arc<dyn AccountService + Send + Sync>,
    pub message_service: Arc<dyn MessageService + Send + Sync>,
    pub setting_service: Arc<dyn SettingService + Send + Sync>,
    pub lookup_service: Arc<dyn LookupService + Send + Sync>,
    pub password_service: Arc<dyn PasswordService + Send + Sync>,
    pub import_export_service: Arc<dyn ImportExportService + Send + Sync>,
    pub encryption_service: Arc<dyn EncryptionService + Send + Sync>,
    pub share_vault_account_service: Arc<dyn ShareVaultAccountService + Send + Sync>,
    pub otp_service: Arc<dyn OTPService + Send + Sync>,
    pub auth_service: Arc<dyn AuthenticationService + Send + Sync>,
    pub audit_log_service: Arc<dyn AuditLogService + Send + Sync>,
    pub scheduler: Arc<Scheduler>,
    pub hsm_store: Arc<dyn HSMStore + Send + Sync>,
}

impl ServiceLocator {
    pub async fn new(config: &PassConfig) -> PassResult<Self> {
        Ok(Self {
            config: config.clone(),
            user_service: create_user_service(config).await?,
            login_session_repository: create_login_session_repository(config).await?,
            vault_service: create_vault_service(config).await?,
            account_service: create_account_service(config).await?,
            message_service: create_message_service(config).await?,
            setting_service: create_setting_service(config).await?,
            lookup_service: create_lookup_service(config).await?,
            password_service: create_password_service(config).await?,
            import_export_service: create_import_export_service(config).await?,
            encryption_service: create_encryption_service(config).await?,
            share_vault_account_service: create_share_vault_account_service(config).await?,
            audit_log_service: create_audit_log_service(config).await?,
            otp_service: create_otp_service(config).await?,
            auth_service: create_auth_service(config).await?,
            scheduler: Arc::new(Scheduler::new()),
            hsm_store: create_hsm_store(config)?,
        })
    }
}
