use actix_web::dev::ServiceRequest;
use chrono::NaiveDateTime;
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::domain::models::{
    Account, NameValue, PaginatedResult, PassConfig, PasswordPolicy, User, UserToken, Vault,
};

// Headers
pub const AUTHORIZATION: &str = "Authorization";

/// SignupUserRequest represents input request for signing up a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignupUserRequest {
    // The username of user.
    pub username: String,
    // The master-password of user.
    pub master_password: String,
    // The name of user.
    pub name: Option<String>,
    // The email of user.
    pub email: Option<String>,
    // The attributes of user.
    pub attributes: Option<HashMap<String, String>>,
}

impl SignupUserRequest {
    pub fn to_user(&self) -> User {
        let mut u = User::new(&self.username, self.name.clone(), self.email.clone());
        if let Some(attrs) = &self.attributes {
            for (k, v) in attrs {
                u.attributes.push(NameValue::new("", &k, &v));
            }
        }
        u
    }
}

/// SignupUserResponse represents response for signing up a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignupUserResponse {
    // The user_id of user.
    pub user_id: String,
}

impl SignupUserResponse {
    pub fn new(user_id: &str) -> Self {
        Self {
            user_id: user_id.into(),
        }
    }
}

/// SigninUserRequest represents input request for signing in a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigninUserRequest {
    // The username of user.
    pub username: String,
    // The master-password of user.
    pub master_password: String,
}

/// SigninUserResponse represents response for signing in a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigninUserResponse {
    // The user_id of user.
    pub user_id: String,
}

impl SigninUserResponse {
    pub fn new(user_id: &str) -> Self {
        Self {
            user_id: user_id.into(),
        }
    }
}

/// UpdateUserRequest represents input request for updating user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateUserRequest {
    // id of the user.
    pub user_id: String,
    // The version of the user in database.
    pub version: i64,
    // The username of user.
    pub username: String,
    // The name of user.
    pub name: Option<String>,
    // The email of user.
    pub email: Option<String>,
    // The attributes of user.
    pub attributes: Option<HashMap<String, String>>,
}

impl UpdateUserRequest {
    pub fn to_user(&self) -> User {
        let mut u = User::new(&self.username, self.name.clone(), self.email.clone());
        u.user_id = self.user_id.clone();
        u.version = self.version.clone();
        if let Some(attrs) = &self.attributes {
            for (k, v) in attrs {
                u.attributes.push(NameValue::new("", &k, &v));
            }
        }
        u
    }
}

/// CreateVaultRequest represents input request for vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateVaultRequest {
    // The title of vault.
    pub title: String,
}

impl CreateVaultRequest {
    pub fn to_vault(&self, user_id: &str) -> Vault {
        Vault::new(user_id, &self.title)
    }
}

/// VaultResponse represents response output for vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultResponse {
    // The key representing the vault
    pub vault_id: String,
    // version of vault.
    pub version: i64,
    // The owner_user_id of the vault
    pub owner_user_id: String,
    // The name of vault.
    pub title: String,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
}

impl VaultResponse {
    pub fn new(vault: &Vault) -> Self {
        Self {
            vault_id: vault.vault_id.clone(),
            version: vault.version.clone(),
            owner_user_id: vault.owner_user_id.clone(),
            title: vault.title.clone(),
            created_at: vault.created_at.clone(),
            updated_at: vault.updated_at.clone(),
        }
    }
}

/// UpdateVaultRequest represents input request for updating vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateVaultRequest {
    // The key representing the vault
    pub vault_id: String,
    // version of vault.
    pub version: i64,
    // The name of vault.
    pub title: String,
}

impl UpdateVaultRequest {
    pub fn to_vault(&self, user_id: &str) -> Vault {
        let mut vault = Vault::new(user_id, &self.title);
        vault.vault_id = self.vault_id.clone();
        vault.version = self.version.clone();
        vault
    }
}

/// CreateAccountRequest represents input request for creating account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAccountRequest {
    // The vault_id associated with account the vault.
    pub vault_id: String,
    // title of account.
    pub title: Option<String>,
    // favorite flag.
    pub favorite: Option<bool>,
    // The description of the account.
    pub description: Option<String>,
    // The username of the account.
    pub username: Option<String>,
    // The password of the account.
    pub password: Option<String>,
    // The email of the account.
    pub email: Option<String>,
    // The url of the account.
    pub url: Option<String>,
    // The categories of the account.
    pub categories: Option<Vec<String>>,
    // The tags of the account.
    pub tags: Option<Vec<String>>,
    // otp
    pub otp: Option<String>,
    // icon
    pub icon: Option<String>,
    // The form-fields of the account.
    pub form_fields: Option<HashMap<String, String>>,
    pub notes: Option<String>,

    // minimum number of upper_case letters should be included.
    pub password_min_uppercase: Option<usize>,
    // minimum number of lower_case letters should be included.
    pub password_min_lowercase: Option<usize>,
    // minimum number of digits should be included.
    pub password_min_digits: Option<usize>,
    // minimum number of symbols should be included.
    pub password_min_special_chars: Option<usize>,
    // minimum length of password.
    pub password_min_length: Option<usize>,
    // maximum length of password.
    pub password_max_length: Option<usize>,
    // renew interval
    pub renew_interval_days: Option<i32>,
}

impl CreateAccountRequest {
    pub fn new(vault_id: &str) -> Self {
        Self {
            vault_id: vault_id.into(),
            title: None,
            favorite: None,
            description: None,
            username: None,
            password: None,
            email: None,
            url: None,
            categories: vec![].into(),
            tags: vec![].into(),
            otp: None,
            icon: None,
            form_fields: None,
            notes: None,
            password_min_uppercase: None,
            password_min_lowercase: None,
            password_min_digits: None,
            password_min_special_chars: None,
            password_min_length: None,
            password_max_length: None,
            renew_interval_days: None,
        }
    }

    pub fn to_account(&self) -> Account {
        let mut account = Account::new(&self.vault_id);
        account.details.title = self.title.clone();
        account.details.favorite = self.favorite == Some(true);
        account.details.description = self.description.clone();
        account.details.username = self.username.clone();
        account.details.email = self.email.clone();
        account.details.url = self.url.clone();
        account.details.categories = self.categories.clone().unwrap_or(vec![]);
        account.details.tags = self.tags.clone().unwrap_or(vec![]);
        account.details.icon = self.icon.clone();

        account.credentials.password = self.password.clone();
        account.credentials.form_fields = self.form_fields.clone().unwrap_or(HashMap::new());
        account.credentials.notes = self.notes.clone();

        let mut password_policy = PasswordPolicy::new();

        if let Some(min_uppercase) = &self.password_min_uppercase {
            password_policy.min_uppercase = min_uppercase.clone();
        }
        if let Some(min_lowercase) = &self.password_min_lowercase {
            password_policy.min_lowercase = min_lowercase.clone();
        }
        if let Some(min_digits) = &self.password_min_digits {
            password_policy.min_digits = min_digits.clone();
        }
        if let Some(min_special_chars) = &self.password_min_special_chars {
            password_policy.min_special_chars = min_special_chars.clone();
        }
        if let Some(min_length) = &self.password_min_length {
            password_policy.min_length = min_length.clone();
        }
        if let Some(max_length) = &self.password_max_length {
            password_policy.max_length = max_length.clone();
        }
        password_policy.renew_interval_days = self.renew_interval_days.clone();
        account.credentials.password_policy = password_policy;
        account
    }
}

/// AccountResponse represents response output for account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountResponse {
    // The vault_id associated with account the vault.
    pub vault_id: String,
    // The key representing the account
    pub account_id: String,
    // version of account.
    pub version: i64,
    // title of account.
    pub title: Option<String>,
    // favorite flag.
    pub favorite: Option<bool>,
    // The description of the account.
    pub description: Option<String>,
    // The username of the account.
    pub username: Option<String>,
    // The password of the account.
    pub password: Option<String>,
    // The email of the account.
    pub email: Option<String>,
    // The url of the account.
    pub url: Option<String>,
    // The categories of the account.
    pub categories: Option<Vec<String>>,
    // The tags of the account.
    pub tags: Option<Vec<String>>,
    // otp
    pub otp: Option<String>,
    // icon
    pub icon: Option<String>,
    // The form-fields of the account.
    pub form_fields: Option<HashMap<String, String>>,
    pub notes: Option<String>,

    // minimum number of upper_case letters should be included.
    pub password_min_uppercase: Option<usize>,
    // minimum number of lower_case letters should be included.
    pub password_min_lowercase: Option<usize>,
    // minimum number of digits should be included.
    pub password_min_digits: Option<usize>,
    // minimum number of symbols should be included.
    pub password_min_special_chars: Option<usize>,
    // minimum length of password.
    pub password_min_length: Option<usize>,
    // maximum length of password.
    pub password_max_length: Option<usize>,
    // renew interval
    pub renew_interval_days: Option<i32>,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
}

impl AccountResponse {
    pub fn new(account: &Account) -> Self {
        Self {
            vault_id: account.vault_id.clone(),
            account_id: account.details.account_id.clone(),
            version: account.details.version.clone(),
            title: account.details.title.clone(),
            favorite: Some(account.details.favorite.clone()),
            description: account.details.description.clone(),
            username: account.details.username.clone(),
            password: account.credentials.password.clone(),
            email: account.details.email.clone(),
            url: account.details.url.clone(),
            categories: Some(account.details.categories.clone()),
            tags: Some(account.details.tags.clone()),
            otp: account.details.otp.clone(),
            icon: account.details.icon.clone(),
            form_fields: Some(account.credentials.form_fields.clone()),
            notes: account.credentials.notes.clone(),
            password_min_uppercase: Some(account.credentials.password_policy.min_uppercase.clone()),
            password_min_lowercase: Some(account.credentials.password_policy.min_lowercase.clone()),
            password_min_digits: Some(account.credentials.password_policy.min_digits.clone()),
            password_min_special_chars: Some(
                account
                    .credentials
                    .password_policy
                    .min_special_chars
                    .clone(),
            ),
            password_min_length: Some(account.credentials.password_policy.min_length.clone()),
            password_max_length: Some(account.credentials.password_policy.max_length.clone()),
            renew_interval_days: account
                .credentials
                .password_policy
                .renew_interval_days
                .clone(),
            created_at: account.created_at.clone(),
            updated_at: account.updated_at.clone(),
        }
    }
}

// It defines abstraction for paginated accounts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedAccountResult {
    // The page number or token
    pub offset: i64,
    // limit size
    pub limit: usize,
    pub total_records: Option<i64>,
    // list of records
    pub accounts: Vec<AccountResponse>,
}

impl PaginatedAccountResult {
    pub fn new(res: &PaginatedResult<Account>) -> Self {
        let accounts = res
            .records
            .iter()
            .map(|v| AccountResponse::new(v))
            .collect::<Vec<AccountResponse>>();
        Self {
            offset: res.offset.clone(),
            limit: res.limit.clone(),
            total_records: res.total_records.clone(),
            accounts,
        }
    }
}

/// UpdateAccountRequest represents input request for updating account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateAccountRequest {
    // The key representing the account
    pub account_id: String,
    // version of account.
    pub version: i64,
    // The vault_id associated with account the vault.
    pub vault_id: String,
    // title of account.
    pub title: Option<String>,
    // favorite flag.
    pub favorite: Option<bool>,
    // The description of the account.
    pub description: Option<String>,
    // The username of the account.
    pub username: Option<String>,
    // The password of the account.
    pub password: Option<String>,
    // The email of the account.
    pub email: Option<String>,
    // The url of the account.
    pub url: Option<String>,
    // The categories of the account.
    pub categories: Option<Vec<String>>,
    // The tags of the account.
    pub tags: Option<Vec<String>>,
    // otp
    pub otp: Option<String>,
    // icon
    pub icon: Option<String>,
    // The form-fields of the account.
    pub form_fields: Option<HashMap<String, String>>,
    pub notes: Option<String>,

    // minimum number of upper_case letters should be included.
    pub password_min_uppercase: Option<usize>,
    // minimum number of lower_case letters should be included.
    pub password_min_lowercase: Option<usize>,
    // minimum number of digits should be included.
    pub password_min_digits: Option<usize>,
    // minimum number of symbols should be included.
    pub password_min_special_chars: Option<usize>,
    // minimum length of password.
    pub password_min_length: Option<usize>,
    // maximum length of password.
    pub password_max_length: Option<usize>,
    // renew interval
    pub renew_interval_days: Option<i32>,
}

impl UpdateAccountRequest {
    pub fn new(vault_id: &str, account_id: &str) -> Self {
        Self {
            account_id: account_id.into(),
            version: 0,
            vault_id: vault_id.into(),
            title: None,
            favorite: None,
            description: None,
            username: None,
            password: None,
            email: None,
            url: None,
            categories: None,
            tags: None,
            otp: None,
            icon: None,
            form_fields: None,
            notes: None,
            password_min_uppercase: None,
            password_min_lowercase: None,
            password_min_digits: None,
            password_min_special_chars: None,
            password_min_length: None,
            password_max_length: None,
            renew_interval_days: None,
        }
    }

    pub fn to_account(&self) -> Account {
        let mut account = Account::new(&self.vault_id);
        account.details.account_id = self.account_id.clone();
        account.details.version = self.version.clone();
        account.details.title = self.title.clone();
        account.details.favorite = self.favorite == Some(true);
        account.details.description = self.description.clone();
        account.details.username = self.username.clone();
        account.details.email = self.email.clone();
        account.details.url = self.url.clone();
        account.details.categories = self.categories.clone().unwrap_or(vec![]);
        account.details.tags = self.tags.clone().unwrap_or(vec![]);
        account.details.icon = self.icon.clone();

        account.credentials.password = self.password.clone();
        account.credentials.form_fields = self.form_fields.clone().unwrap_or(HashMap::new());
        account.credentials.notes = self.notes.clone();

        let mut password_policy = PasswordPolicy::new();

        if let Some(min_uppercase) = &self.password_min_uppercase {
            password_policy.min_uppercase = min_uppercase.clone();
        }
        if let Some(min_lowercase) = &self.password_min_lowercase {
            password_policy.min_lowercase = min_lowercase.clone();
        }
        if let Some(min_digits) = &self.password_min_digits {
            password_policy.min_digits = min_digits.clone();
        }
        if let Some(min_special_chars) = &self.password_min_special_chars {
            password_policy.min_special_chars = min_special_chars.clone();
        }
        if let Some(min_length) = &self.password_min_length {
            password_policy.min_length = min_length.clone();
        }
        if let Some(max_length) = &self.password_max_length {
            password_policy.max_length = max_length.clone();
        }
        password_policy.renew_interval_days = self.renew_interval_days.clone();
        account.credentials.password_policy = password_policy;
        account
    }
}

/// QueryAccountParams parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryAccountParams {
    pub offset: Option<i64>,
    pub limit: Option<usize>,
    pub user_id: Option<String>,
    pub q: Option<String>,
}

pub fn get_token_header(req: &ServiceRequest, config: &PassConfig) -> Option<UserToken> {
    if let Some(auth_header) = req.headers().get(AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("bearer") || auth_str.starts_with("Bearer") {
                let token = auth_str[6..auth_str.len()].trim();
                let _ = match UserToken::decode_token(config, token.to_string()) {
                    Ok(token_data) => {
                        return Some(token_data.claims);
                    }
                    Err(err) => {
                        log::warn!("failed to decode token {} due to {}", token, err);
                    }
                };
            }
        }
    }
    None
}
