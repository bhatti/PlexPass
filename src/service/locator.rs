use crate::dao::factory::create_login_session_repository;
use crate::dao::LoginSessionRepository;
use std::sync::Arc;

use crate::domain::models::{PassConfig, PassResult};
use crate::service::factory::{
    create_account_service, create_lookup_service, create_message_service, create_password_service,
    create_setting_service, create_user_service, create_vault_service,
};
use crate::service::{
    AccountService, LookupService, MessageService, PasswordService, SettingService, UserService,
    VaultService,
};
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
            hsm_store: create_hsm_store(config)?,
        })
    }
}
