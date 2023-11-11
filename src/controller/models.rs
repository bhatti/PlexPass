use std::cmp;
use std::collections::HashMap;
use std::future::{Ready, ready};

use actix_multipart::Multipart;
use actix_web::{FromRequest, HttpMessage};
use chrono::NaiveDateTime;
use futures::stream::StreamExt;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::dao::models::{UserContext};
use crate::domain::error::PassError;
use crate::domain::models::{Account, AccountKind, AccountRisk, Advisory, AuditLog, Lookup, LookupKind, NameValue, PaginatedResult, PassResult, PasswordPolicy, User, UserToken, Vault, VaultAnalysis, VaultKind};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Authenticated {
    pub user_token: UserToken,
    pub context: UserContext,
}

impl Authenticated {
    pub fn new(user_token: UserToken, context: UserContext) -> Self {
        Self {
            user_token,
            context,
        }
    }
}

impl FromRequest for Authenticated {
    type Error = PassError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &actix_web::HttpRequest,
                    _payload: &mut actix_web::dev::Payload) -> Self::Future {
        let value = req.extensions().get::<Authenticated>().cloned();
        let result = match value {
            Some(v) => Ok(v),
            None => Err(PassError::authentication("request could not be authenticated")),
        };
        ready(result)
    }
}

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
    // The locale of user.
    pub locale: Option<String>,
    // The light-mode of user.
    pub light_mode: Option<bool>,
    // The icon of user.
    pub icon: Option<String>,
    // The attributes of user.
    pub attributes: Option<HashMap<String, String>>,
}

impl UpdateUserRequest {
    pub fn to_user(&self) -> User {
        let mut u = User::new(&self.username, self.name.clone(), self.email.clone());
        u.user_id = self.user_id.clone();
        u.version = self.version.clone();
        u.locale = self.locale.clone();
        u.light_mode = self.light_mode.clone();
        u.icon = self.icon.clone();
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
    // The kind of vault.
    pub kind: Option<VaultKind>,
    // icon of vault.
    pub icon: Option<String>,
}

impl CreateVaultRequest {
    pub fn to_vault(&self, user_id: &str) -> Vault {
        let mut vault = Vault::new(user_id, &self.title, self.kind.clone().unwrap_or(VaultKind::Logins));
        vault.icon = self.icon.clone();
        vault
    }
}

/// CreateCategoryRequest represents input request for category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCategoryRequest {
    pub name: String,
}

impl CreateCategoryRequest {
    pub fn to_lookup(&self, user_id: &str) -> Lookup {
        Lookup::new(user_id, LookupKind::CATEGORY, &self.name)
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
    // The kind of vault.
    pub kind: VaultKind,
    pub analysis: VaultAnalysis,
    // The metadata for date when passwords for the vault were analyzed.
    pub analyzed_at: Option<NaiveDateTime>,
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
            kind: vault.kind.clone(),
            analysis: vault.analysis.clone().unwrap_or(VaultAnalysis::new()),
            analyzed_at: vault.analyzed_at.clone(),
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
    // The kind of vault.
    pub kind: Option<VaultKind>,
    // icon of vault.
    pub icon: Option<String>,
}

impl UpdateVaultRequest {
    pub fn to_vault(&self, user_id: &str) -> Vault {
        let mut vault = Vault::new(user_id, &self.title, self.kind.clone().unwrap_or(VaultKind::Logins));
        vault.vault_id = self.vault_id.clone();
        vault.version = self.version.clone();
        vault.icon = self.icon.clone();
        vault
    }
}

/// CreateAccountRequest represents input request for creating account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAccountRequest {
    // The vault_id associated with account the vault.
    pub vault_id: String,
    // kind of account
    pub kind: Option<AccountKind>,
    // label of account.
    pub label: Option<String>,
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
    // The category of the account.
    pub category: Option<String>,
    // The tags of the account.
    pub tags: Option<Vec<String>>,
    // otp
    pub otp: Option<String>,
    // icon
    pub icon: Option<String>,
    // The form-fields of the account.
    pub form_fields: Option<HashMap<String, String>>,
    pub notes: Option<String>,
    // renew interval
    pub renew_interval_days: Option<i32>,
    // expiration
    pub expires_at: Option<NaiveDateTime>,
    // The custom fields of the account.
    pub custom_name: Option<Vec<String>>,
    // The custom fields of the account.
    pub custom_value: Option<Vec<String>>,

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
}

impl CreateAccountRequest {
    #[allow(dead_code)]
    pub fn new(vault_id: &str) -> Self {
        Self {
            vault_id: vault_id.into(),
            kind: None,
            label: None,
            favorite: None,
            description: None,
            username: None,
            password: None,
            email: None,
            url: None,
            category: None,
            tags: vec![].into(),
            otp: None,
            icon: None,
            form_fields: None,
            notes: None,
            renew_interval_days: None,
            expires_at: None,
            custom_name: None,
            custom_value: None,
            password_min_uppercase: None,
            password_min_lowercase: None,
            password_min_digits: None,
            password_min_special_chars: None,
            password_min_length: None,
            password_max_length: None,
        }
    }

    fn get_kind(&self) -> AccountKind {
        if let Some(kind) = &self.kind {
            return kind.clone();
        }
        if self.username == None && self.email == None && self.password == None && self.notes != None {
            return AccountKind::Notes;
        }
        AccountKind::Login
    }

    pub fn to_account(&self) -> Account {
        let mut account = Account::new(&self.vault_id, self.get_kind());
        account.details.label = self.label.clone();
        account.details.favorite = self.favorite == Some(true);
        account.details.description = self.description.clone();
        account.details.username = self.username.clone();
        account.details.email = self.email.clone();
        account.details.url = self.url.clone();
        account.details.category = self.category.clone();
        account.details.tags = self.tags.clone().unwrap_or(vec![]);
        account.details.icon = self.icon.clone();
        account.details.renew_interval_days = self.renew_interval_days.clone();
        account.details.expires_at = self.expires_at.clone();

        account.credentials.password = self.password.clone();
        account.credentials.form_fields = self.form_fields.clone().unwrap_or(HashMap::new());
        account.credentials.notes = self.notes.clone();
        account.credentials.otp = self.otp.clone();

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
    // kind of account
    pub kind: AccountKind,
    // label of account.
    pub label: Option<String>,
    // favorite flag.
    pub favorite: Option<bool>,
    // risk of password and account
    pub risk: AccountRisk,
    // risk background color
    pub risk_bg_color: String,
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
    // The category of the account.
    pub category: Option<String>,
    // The tags of the account.
    pub tags: Option<Vec<String>>,
    // otp
    pub otp: Option<String>,
    // icon
    pub icon: Option<String>,
    // The form-fields of the account.
    pub form_fields: Option<HashMap<String, String>>,
    pub notes: Option<String>,
    pub advisories: HashMap<Advisory, String>,

    // renew interval
    // renew interval
    pub renew_interval_days: Option<i32>,
    // expiration
    pub expires_at: Option<NaiveDateTime>,
    // The metadata for dates of the account.
    pub credentials_updated_at: Option<NaiveDateTime>,
    // The metadata for date when password was analyzed.
    pub analyzed_at: Option<NaiveDateTime>,
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
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
}

impl AccountResponse {
    pub fn new(account: &Account) -> Self {
        Self {
            vault_id: account.vault_id.clone(),
            account_id: account.details.account_id.clone(),
            version: account.details.version.clone(),
            kind: account.details.kind.clone(),
            label: account.details.label.clone(),
            favorite: Some(account.details.favorite.clone()),
            risk: account.details.risk.clone(),
            risk_bg_color: account.details.risk_bg_color(),
            description: account.details.description.clone(),
            username: account.details.username.clone(),
            password: account.credentials.password.clone(),
            email: account.details.email.clone(),
            url: account.details.url.clone(),
            category: account.details.category.clone(),
            tags: Some(account.details.tags.clone()),
            otp: account.credentials.otp.clone(),
            icon: account.details.icon.clone(),
            form_fields: Some(account.credentials.form_fields.clone()),
            notes: account.credentials.notes.clone(),
            advisories: account.details.advisories.clone(),
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
            renew_interval_days: account.details.renew_interval_days.clone(),
            expires_at: account.details.expires_at.clone(),
            credentials_updated_at: account.details.credentials_updated_at.clone(),
            analyzed_at: account.details.analyzed_at.clone(),
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

// It defines abstraction for paginated audit logs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedAuditLogResult {
    // The page number or token
    pub offset: i64,
    // limit size
    pub limit: usize,
    pub total_records: Option<i64>,
    // list of records
    pub audit_logs: Vec<AuditLog>,
}


/// UpdateAccountRequest represents input request for updating account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateAccountRequest {
    // The key representing the account
    pub account_id: String,
    // version of account.
    pub version: i64,
    // kind of account
    pub kind: Option<AccountKind>,
    // The vault_id associated with account the vault.
    pub vault_id: String,
    // label of account.
    pub label: Option<String>,
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
    pub category: Option<String>,
    // The tags of the account.
    pub tags: Option<Vec<String>>,
    // otp
    pub otp: Option<String>,
    // icon
    pub icon: Option<String>,
    // The form-fields of the account.
    pub form_fields: Option<HashMap<String, String>>,
    pub notes: Option<String>,
    // The custom fields of the account.
    pub custom_name: Option<Vec<String>>,
    // The custom fields of the account.
    pub custom_value: Option<Vec<String>>,

    // renew interval
    pub renew_interval_days: Option<i32>,
    // expiration
    pub expires_at: Option<NaiveDateTime>,

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
}

impl UpdateAccountRequest {
    #[allow(dead_code)]
    pub fn new(vault_id: &str, account_id: &str) -> Self {
        Self {
            account_id: account_id.into(),
            version: 0,
            vault_id: vault_id.into(),
            kind: None,
            label: None,
            favorite: None,
            description: None,
            username: None,
            password: None,
            email: None,
            url: None,
            category: None,
            tags: None,
            otp: None,
            icon: None,
            form_fields: None,
            notes: None,
            custom_name: None,
            custom_value: None,
            renew_interval_days: None,
            expires_at: None,
            password_min_uppercase: None,
            password_min_lowercase: None,
            password_min_digits: None,
            password_min_special_chars: None,
            password_min_length: None,
            password_max_length: None,
        }
    }

    fn get_kind(&self) -> AccountKind {
        if let Some(kind) = &self.kind {
            return kind.clone();
        }
        if self.username == None && self.email == None && self.password == None && self.notes != None {
            return AccountKind::Notes;
        }
        AccountKind::Login
    }

    pub fn to_account(&self) -> Account {
        let mut account = Account::new(&self.vault_id, self.get_kind());
        account.details.account_id = self.account_id.clone();
        account.details.version = self.version.clone();
        account.details.label = self.label.clone();
        account.details.favorite = self.favorite == Some(true);
        account.details.description = self.description.clone();
        account.details.username = self.username.clone();
        account.details.email = self.email.clone();
        account.details.url = self.url.clone();
        account.details.category = self.category.clone();
        account.details.tags = self.tags.clone().unwrap_or(vec![]);
        account.details.icon = self.icon.clone();

        account.credentials.password = self.password.clone();
        account.credentials.form_fields = self.form_fields.clone().unwrap_or(HashMap::new());
        account.credentials.notes = self.notes.clone();
        account.credentials.otp = self.otp.clone();
        account.details.renew_interval_days = self.renew_interval_days.clone();
        account.details.expires_at = self.expires_at.clone();

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
        account.credentials.password_policy = password_policy;
        account
    }
}

/// DeleteAccountRequest represents input request for deleting account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteAccountRequest {
    // The key representing the account
    pub account_id: String,
}

impl Account {
    pub async fn from_multipart(payload: &mut Multipart, new_rec: bool) -> PassResult<Self> {
        let mut account = Self::new("", AccountKind::Login);
        let mut custom_names = vec![];
        let mut custom_values = vec![];
        while let Some(item) = payload.next().await {
            let mut field = item?;
            let content_disposition = field.content_disposition().clone();
            let name = content_disposition.get_name().unwrap();
            let mut value = String::new();
            while let Some(chunk) = field.next().await {
                value += &String::from_utf8(chunk?.to_vec()).unwrap();
            }
            value = value.trim().to_string();
            match name {
                "account_id" => account.details.account_id = value,
                "version" => account.details.version = value.parse::<i64>()?,
                "vault_id" => account.vault_id = value,
                "kind" => account.details.kind = AccountKind::from(value.as_str()),
                "label" => account.details.label = Some(value),
                "favorite" => account.details.favorite = value == "on",
                "description" => account.details.description = Some(value),
                "username" => account.details.username = Some(value),
                "email" => account.details.email = Some(value),
                "url" => account.details.url = Some(value),
                "category" => account.details.category = Some(value),
                "tags" => account.details.tags = value.as_str().split("[,;]").map(|s| s.to_string()).collect::<Vec<String>>(),
                "password" => account.credentials.password = Some(value),
                "notes" => account.credentials.notes = Some(value),
                "custom_name" => custom_names.push(value),
                "custom_value" => custom_values.push(value),
                _ => {}
                // otp: None,
                // icon: None,
                // renew_interval_days: None,
                // expires_at: None,
            };
        }
        if new_rec {
            account.details.account_id = Uuid::new_v4().to_string();
            account.details.version = 0;
        } else if account.details.account_id == "" {
            return Err(PassError::validation("account_id is not specified", None));
        }
        if account.vault_id == "" {
            return Err(PassError::validation("vault_id is not specified", None));
        }
        let max_custom = cmp::min(custom_names.len(), custom_values.len());
        let mut attributes: HashMap<String, String> = HashMap::new();
        for i in 0..max_custom {
            if custom_names[i].len() > 0 {
                attributes.insert(custom_names[i.clone()].clone(), custom_values[i.clone()].clone());
            }
        }
        account.credentials.form_fields = attributes;
        Ok(account)
    }
}

/// ShareVaultParams parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareVaultParams {
    pub target_username: String,
    pub read_only: Option<bool>,
}

/// ShareAccountParams parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareAccountParams {
    pub target_username: String,
}

// GeneratePasswordRequest request to generate password
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratePasswordRequest {
    // random or memorable password
    pub random: Option<bool>,
    // minimum number of upper_case letters should be included.
    pub min_uppercase: Option<usize>,
    // minimum number of lower_case letters should be included.
    pub min_lowercase: Option<usize>,
    // minimum number of digits should be included.
    pub min_digits: Option<usize>,
    // minimum number of symbols should be included.
    pub min_special_chars: Option<usize>,
    // minimum length of password.
    pub min_length: Option<usize>,
    // maximum length of password.
    pub max_length: Option<usize>,
    // exclude_ambiguous to remove ambiguous letters
    pub exclude_ambiguous: Option<bool>,
    pub password_type: Option<String>,
}

impl GeneratePasswordRequest {
    pub fn to_password_policy(&self) -> PasswordPolicy {
        let mut policy = PasswordPolicy {
            random: self.random.unwrap_or(false),
            min_uppercase: self.min_uppercase.unwrap_or(1),
            min_lowercase: self.min_lowercase.unwrap_or(1),
            min_digits: self.min_digits.unwrap_or(1),
            min_special_chars: self.min_special_chars.unwrap_or(1),
            min_length: self.min_length.unwrap_or(12),
            max_length: self.max_length.unwrap_or(16),
            exclude_ambiguous: self.exclude_ambiguous.unwrap_or(false),
        };
        if let Some(password_type) = &self.password_type {
            policy.random = password_type == "random";
        }
        policy
    }
}

/// QueryAuditParams parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryAuditParams {
    pub offset: Option<i64>,
    pub limit: Option<usize>,
    pub user_id: Option<String>,
    pub q: Option<String>,
}

/// QueryAccountParams parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryAccountParams {
    pub offset: Option<i64>,
    pub limit: Option<usize>,
    pub q: Option<String>,
}

