mod account_service_impl;
mod factory;
pub mod locator;
pub(crate) mod lookup_service_impl;
pub(crate) mod message_service_impl;
pub(crate) mod password_service_impl;
pub(crate) mod setting_service_impl;
pub(crate) mod user_service_impl;
pub(crate) mod vault_service_impl;
pub(crate) mod import_export_service_impl;
pub(crate) mod encryption_service_impl;
pub(crate) mod share_vault_account_service_impl;
pub(crate) mod audit_service_impl;
pub(crate) mod otp_service_impl;
pub(crate) mod authentication_service_impl;

use crate::dao::models::UserContext;
use crate::domain::models::{Account, AccountSummary, AuditLog, EncodingScheme, HardwareSecurityKey, ImportResult, Lookup, LookupKind, Message, MessageKind, PaginatedResult, PassResult, PasswordInfo, PasswordPolicy, PasswordSimilarity, ProgressStatus, SessionStatus, Setting, SettingKind, User, UserToken, Vault, VaultAnalysis, VaultKind};
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::Path;
use webauthn_rs::prelude::{CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse};
use crate::controller::models::{AccountResponse};

#[async_trait]
pub trait AuthenticationService {
    // signin and retrieve the user.
    async fn signin_user(
        &self,
        username: &str,
        master_password: &str,
        otp_code: Option<u32>,
        context: HashMap<String, String>,
    ) -> PassResult<(UserContext, User, UserToken, SessionStatus)>;

    // logout user
    async fn signout_user(&self, ctx: &UserContext, login_session_id: &str) -> PassResult<()>;

    // start registering MFA key
    async fn start_register_key(&self,
                                ctx: &UserContext,
    ) -> PassResult<CreationChallengeResponse>;

    // change password for the user.
    async fn change_password(
        &self,
        ctx: &UserContext,
        old_master_password: &str,
        new_master_password: &str,
        confirm_new_master_password: &str,
        login_session_id: &str,
    ) -> PassResult<usize>;

    // finish MFA registration and returns hardware key with recovery code
    async fn finish_register_key(&self,
                                 ctx: &UserContext,
                                 name: &str,
                                 req: &RegisterPublicKeyCredential) -> PassResult<HardwareSecurityKey>;

    // start MFA signin
    async fn start_key_authentication(&self,
                                      ctx: &UserContext,
    ) -> PassResult<RequestChallengeResponse>;

    // finish MFA signin
    async fn finish_key_authentication(&self,
                                       ctx: &UserContext,
                                       session_id: &str,
                                       auth: &PublicKeyCredential) -> PassResult<()>;
    // reset mfa keys
    async fn reset_mfa_keys(&self,
                            ctx: &UserContext,
                            recovery_code: &str,
                            session_id: &str) -> PassResult<()>;
    // update light mode
    async fn update_light_mode(&self,
                            ctx: &UserContext,
                            session_id: &str,
                            light_mode: bool) -> PassResult<usize>;
}

#[async_trait]
pub trait UserService {
    // signup and create a user.
    async fn register_user(&self,
                           user: &User,
                           master_password: &str,
                           context: HashMap<String, String>, ) -> PassResult<UserContext>;

    // get user by id.
    async fn get_user(&self, ctx: &UserContext, id: &str) -> PassResult<(UserContext, User)>;

    // updates existing user.
    async fn update_user(&self, ctx: &UserContext, user: &User) -> PassResult<usize>;

    // delete the user by id.
    async fn delete_user(&self, ctx: &UserContext, id: &str) -> PassResult<usize>;

    // encrypt asymmetric
    async fn asymmetric_user_encrypt(&self,
                                     ctx: &UserContext,
                                     target_username: &str,
                                     data: Vec<u8>,
                                     encoding: EncodingScheme,
    ) -> PassResult<Vec<u8>>;

    // decrypt asymmetric
    async fn asymmetric_user_decrypt(&self,
                                     ctx: &UserContext,
                                     data: Vec<u8>,
                                     encoding: EncodingScheme,
    ) -> PassResult<Vec<u8>>;

    /// Generate OTP
    async fn generate_user_otp(&self, ctx: &UserContext) -> PassResult<u32>;
}

#[async_trait]
pub trait VaultService {
    // create an vault.
    async fn create_vault(&self, ctx: &UserContext, vault: &Vault) -> PassResult<usize>;

    // updates existing vault.
    async fn update_vault(&self, ctx: &UserContext, vault: &Vault) -> PassResult<usize>;

    // get the vault by id.
    async fn get_vault(&self, ctx: &UserContext, id: &str) -> PassResult<Vault>;

    // delete the vault by id.
    async fn delete_vault(&self, ctx: &UserContext, id: &str) -> PassResult<usize>;

    // find all vaults by user_id without account summaries.
    async fn get_user_vaults(&self, ctx: &UserContext) -> PassResult<Vec<Vault>>;

    // account summaries.
    async fn account_summaries_by_vault(
        &self,
        ctx: &UserContext,
        vault_id: &str,
        q: Option<String>,
    ) -> PassResult<Vec<AccountSummary>>;
}

#[async_trait]
pub trait AccountService {
    // create an account.
    async fn create_account(&self, ctx: &UserContext, account: &Account) -> PassResult<usize>;

    // updates existing account.
    async fn update_account(&self, ctx: &UserContext, account: &Account) -> PassResult<usize>;

    // get account by id.
    async fn get_account(&self, ctx: &UserContext, id: &str) -> PassResult<Account>;

    // delete the account by id.
    async fn delete_account(&self, ctx: &UserContext, id: &str) -> PassResult<usize>;

    // find all accounts by vault.
    async fn find_accounts_by_vault(
        &self,
        ctx: &UserContext,
        vault_id: &str,
        predicates: HashMap<String, String>,
        offset: i64,
        limit: usize,
    ) -> PassResult<PaginatedResult<Account>>;

    // count all accounts by vault.
    async fn count_accounts_by_vault(
        &self,
        ctx: &UserContext,
        vault_id: &str,
        predicates: HashMap<String, String>,
    ) -> PassResult<i64>;
}

pub trait EncryptionService {
    // generate private public keys
    fn generate_private_public_keys(&self,
                                    secret: Option<String>,
    ) -> PassResult<(String, String)>;

    // encrypt asymmetric
    fn asymmetric_encrypt(&self,
                          pk: &str,
                          data: Vec<u8>,
                          encoding: EncodingScheme,
    ) -> PassResult<Vec<u8>>;

    // decrypt asymmetric
    fn asymmetric_decrypt(&self,
                          sk: &str,
                          data: Vec<u8>,
                          encoding: EncodingScheme,
    ) -> PassResult<Vec<u8>>;


    // encrypt symmetric
    fn symmetric_encrypt(&self,
                         salt: &str,
                         pepper: &str,
                         secret: &str,
                         data: Vec<u8>,
                         encoding: EncodingScheme,
    ) -> PassResult<Vec<u8>>;

    // decrypt symmetric
    fn symmetric_decrypt(&self,
                         pepper: &str,
                         secret: &str,
                         data: Vec<u8>,
                         encoding: EncodingScheme,
    ) -> PassResult<Vec<u8>>;
}

#[async_trait]
pub trait ImportExportService {
    // import accounts.
    #[allow(clippy::too_many_arguments)]
    async fn import_accounts(&self,
                             ctx: &UserContext,
                             vault_id: Option<String>,
                             vault_kind: Option<VaultKind>,
                             password: Option<String>,
                             encoding: EncodingScheme,
                             data: &[u8],
                             callback: Box<dyn Fn(ProgressStatus) + Send + Sync>,
    ) -> PassResult<ImportResult>;

    // export accounts.
    async fn export_accounts(&self,
                             ctx: &UserContext,
                             vault_id: &str,
                             password: Option<String>,
                             encoding: EncodingScheme,
                             callback: Box<dyn Fn(ProgressStatus) + Send + Sync>,
    ) -> PassResult<(String, Vec<u8>)>;
}

#[async_trait]
pub trait MessageService {
    // create an message.
    async fn create_message(&self, ctx: &UserContext, message: &Message) -> PassResult<usize>;

    // updates existing message flags
    async fn update_message(&self, ctx: &UserContext, message: &Message) -> PassResult<usize>;

    // delete the message by id.
    async fn delete_message(&self, ctx: &UserContext, id: &str) -> PassResult<usize>;

    // find all messages by vault.
    async fn find_messages_by_user(
        &self,
        ctx: &UserContext,
        kind: Option<MessageKind>,
        offset: i64,
        limit: usize,
    ) -> PassResult<PaginatedResult<Message>>;
}

#[async_trait]
pub trait PasswordService {
    // create strong password.
    async fn generate_password(&self, policy: &PasswordPolicy) -> Option<String>;

    // check strength of password.
    async fn password_info(&self, password: &str) -> PassResult<PasswordInfo>;

    // check strength of password.
    async fn password_compromised(&self, password: &str) -> PassResult<bool>;

    // check if email is compromised.
    async fn email_compromised(&self, email: &str) -> PassResult<String>;

    // check similarity of password.
    async fn password_similarity(&self, password1: &str, password2: &str) -> PassResult<PasswordSimilarity>;

    // analyze passwords and accounts of all accounts in given vault
    // It returns hashmap by account-id and password analysis
    async fn analyze_vault_passwords(&self, ctx: &UserContext, vault_id: &str, force: bool) -> PassResult<VaultAnalysis>;

    // analyze passwords and accounts of all accounts in all vaults
    // It returns hashmap by (vault-id, account-id) and password analysis
    async fn analyze_all_vault_passwords(&self, ctx: &UserContext, force: bool) -> PassResult<HashMap<String, VaultAnalysis>>;

    // schedule password analysis for vault
    async fn schedule_analyze_vault_passwords(&self, ctx: &UserContext, vault_id: &str, force: bool) -> PassResult<()>;

    // schedule password analysis for all vaults
    async fn schedule_analyze_all_vault_passwords(&self, ctx: &UserContext, force: bool) -> PassResult<()>;
}

#[async_trait]
pub trait LookupService {
    // create a lookup.
    async fn create_lookup(&self, ctx: &UserContext, lookup: &Lookup) -> PassResult<usize>;

    // delete the lookup by kind and name.
    async fn delete_lookup(
        &self,
        ctx: &UserContext,
        kind: LookupKind,
        name: &str,
    ) -> PassResult<usize>;


    // get default and user categories combined
    async fn get_categories(&self, ctx: &UserContext) -> PassResult<Vec<String>>;

    // get lookup by kind.
    async fn get_lookups(&self, ctx: &UserContext, kind: LookupKind) -> PassResult<Vec<Lookup>>;

    // get lookup by kind and name.
    async fn get_lookup(
        &self,
        ctx: &UserContext,
        kind: LookupKind,
        name: &str,
    ) -> PassResult<Lookup>;
}

/// Service interface for sharing vaults or accounts.
#[async_trait]
pub trait ShareVaultAccountService {
    // share vault with another user
    async fn share_vault(
        &self,
        ctx: &UserContext,
        vault_id: &str,
        target_username: &str,
        read_only: bool,
    ) -> PassResult<usize>;

    // unshare vault with another user
    async fn unshare_vault(
        &self,
        ctx: &UserContext,
        vault_id: &str,
        target_username: &str,
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

#[async_trait]
pub trait SettingService {
    // create a setting.
    async fn create_setting(&self, ctx: &UserContext, setting: &Setting) -> PassResult<usize>;

    // updates existing setting.
    async fn update_setting(&self, ctx: &UserContext, setting: &Setting) -> PassResult<usize>;

    // delete the setting by kind and name.
    async fn delete_setting(
        &self,
        ctx: &UserContext,
        kind: SettingKind,
        name: &str,
    ) -> PassResult<usize>;

    // get setting by kind.
    async fn get_settings(&self, ctx: &UserContext, kind: SettingKind) -> PassResult<Vec<Setting>>;

    // get setting by id.
    async fn get_setting(
        &self,
        ctx: &UserContext,
        kind: SettingKind,
        name: &str,
    ) -> PassResult<Setting>;
}

/// AuditLogService interface for showing audit logs.
#[async_trait]
pub trait AuditLogService {
    async fn find(&self,
                  ctx: &UserContext,
                  predicates: HashMap<String, String>,
                  offset: i64,
                  limit: usize,
    ) -> PassResult<PaginatedResult<AuditLog>>;
}

/// OTPService interface for managing one-time-passwords.
#[async_trait]
pub trait OTPService {
    /// Generate OTP
    async fn generate_otp(&self, secret: &str) -> PassResult<u32>;
    /// Extract OTP secret from QRCode
    async fn convert_from_qrcode(&self, ctx: &UserContext, image_data: &[u8]) -> PassResult<Vec<AccountResponse>>;
    /// Create QRCode image for OTP secrets
    async fn convert_to_qrcode(&self, ctx: &UserContext,
                               secrets: Vec<&str>,
    ) -> PassResult<Vec<u8>>;
    /// Extract OTP secret from QRCode file
    async fn convert_from_qrcode_file(&self, ctx: &UserContext,
                                      in_path: &Path) -> PassResult<Vec<AccountResponse>>;
    /// Create QRCode image file for OTP secrets
    async fn convert_to_qrcode_file(&self, ctx: &UserContext, secrets: Vec<&str>,
                                    out_path: &Path) -> PassResult<()>;
}


