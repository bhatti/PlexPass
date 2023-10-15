mod account_service_impl;
mod factory;
pub mod locator;
pub(crate) mod lookup_service_impl;
pub(crate) mod message_service_impl;
pub(crate) mod password_service_impl;
pub(crate) mod setting_service_impl;
pub(crate) mod user_service_impl;
pub(crate) mod vault_service_impl;

use crate::dao::models::UserContext;
use crate::domain::models::{
    Account, Lookup, LookupKind, Message, PaginatedResult, PassResult, PasswordAnalysis, Setting,
    SettingKind, User, UserToken, Vault,
};
use async_trait::async_trait;
use std::collections::HashMap;

#[async_trait]
pub trait UserService {
    // signup and create a user.
    async fn signup_user(&self, user: &User, master_password: &str) -> PassResult<UserContext>;

    // signin and retrieve the user.
    async fn signin_user(
        &self,
        username: &str,
        master_password: &str,
        context: HashMap<String, String>,
    ) -> PassResult<(UserContext, User, UserToken)>;

    // logout user
    async fn signout_user(&self, ctx: &UserContext, login_session_id: &str) -> PassResult<()>;

    // get user by id.
    async fn get_user(&self, ctx: &UserContext, id: &str) -> PassResult<(UserContext, User)>;

    // updates existing user.
    async fn update_user(&self, ctx: &UserContext, user: &User) -> PassResult<usize>;

    // delete the user by id.
    async fn delete_user(&self, ctx: &UserContext, id: &str) -> PassResult<usize>;
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
        message_type: &str,
        offset: i64,
        limit: usize,
    ) -> PassResult<PaginatedResult<Message>>;
}

#[async_trait]
pub trait PasswordService {
    // create strong memorable password.
    async fn generate_memorable_password(&self) -> Option<String>;

    // create strong random password.
    async fn generate_random_password(&self) -> Option<String>;

    // check strength of password.
    async fn analyze_password(&self, password: &str) -> PassResult<PasswordAnalysis>;

    // check strength of password.
    async fn password_compromised(&self, password: &str) -> PassResult<bool>;
}
