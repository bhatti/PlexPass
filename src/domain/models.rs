extern crate regex;
use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::{fmt, fs};

use crate::crypto;
use chrono::{NaiveDateTime, Utc};
use hex::FromHexError;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::error::PassError;
use crate::utils::words::WORDS;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation};
use rand::distributions::{Distribution, Uniform};
use rand::Rng;
use regex::Regex;

pub(crate) const DEFAULT_VAULT_KEY: &str = "DEFAULT";

const SPECIAL_CHARS: &str = "!@#$%^&*()-_=+[]{}|;:,.<>?";

/// A specialized Result type for Password Manager Result.
pub type PassResult<T> = Result<T, PassError>;

// It defines abstraction for paginated result
#[derive(Debug, Clone)]
pub struct PaginatedResult<T> {
    // The page number or token
    pub offset: i64,
    // limit size
    pub limit: usize,
    // list of records
    pub records: Vec<T>,
    pub total_records: Option<i64>,
}

impl<T> PaginatedResult<T> {
    pub fn new(offset: i64, limit: usize, records: Vec<T>) -> Self {
        PaginatedResult {
            offset,
            limit,
            records,
            total_records: None,
        }
    }
}

pub const ADMIN_USER: i64 = 2048;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Roles {
    // The roles of user.
    pub mask: i64,
}

impl Roles {
    pub fn new(roles: i64) -> Self {
        Self { mask: roles }
    }

    pub(crate) fn is_admin(&self) -> bool {
        &self.mask & ADMIN_USER != 0
    }

    pub(crate) fn set_admin(&mut self) {
        self.mask = self.mask.clone() | ADMIN_USER;
    }
}

impl PartialEq for Roles {
    fn eq(&self, other: &Self) -> bool {
        self.mask == other.mask
    }
}

/// UserKeyParams defines master salt, pepper, and secret-key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserKeyParams {
    // The user_id for the user.
    pub user_id: String,
    // The salt for the user.
    pub salt: String,
    // The pepper key for the user.
    pub pepper: String,
}

impl UserKeyParams {
    pub fn new(user_id: &str, salt: &str, pepper: &str) -> Self {
        Self {
            user_id: user_id.into(),
            salt: salt.into(),
            pepper: pepper.into(),
        }
    }

    pub fn serialize(&self) -> PassResult<String> {
        Ok(serde_json::to_string(self)?)
    }

    pub fn deserialize(j: &str) -> PassResult<Self> {
        let data: UserKeyParams = serde_json::from_str(j)?;
        Ok(data)
    }
}

/// LoginSession for tracking authenticated sessions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginSession {
    // The session_id for login
    pub login_session_id: String,
    // The user_id for the user.
    pub user_id: String,
    // The source of the session.
    pub source: Option<String>,
    // The ip-address of the session.
    pub ip_address: Option<String>,
    pub created_at: Option<NaiveDateTime>,
    pub signed_out_at: Option<NaiveDateTime>,
}

impl LoginSession {
    pub fn new(user_id: &str) -> Self {
        Self {
            login_session_id: hex::encode(crypto::generate_secret_key()),
            user_id: user_id.into(),
            source: None,
            ip_address: None,
            created_at: Some(Utc::now().naive_utc()),
            signed_out_at: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserToken {
    // issued at
    pub iat: i64,
    // expiration
    pub exp: i64,
    // data
    pub user_id: String,
    pub username: String,
    pub roles: i64,
    pub login_session: String,
}

impl UserToken {
    pub fn new(config: &PassConfig, user: &User, session: &LoginSession) -> UserToken {
        let now = Utc::now().timestamp_nanos() / 1_000_000_000; // nanosecond -> second
        Self {
            iat: now.clone(),
            exp: now + config.jwt_max_age_secs.clone(),
            user_id: user.user_id.clone(),
            username: user.username.clone(),
            roles: user.roles.mask.clone(),
            login_session: session.login_session_id.clone(),
        }
    }

    pub fn encode_token(&self, config: &PassConfig) -> PassResult<String> {
        let ser_token = jsonwebtoken::encode(
            &Header::default(),
            self,
            &EncodingKey::from_secret(config.jwt_key.as_str().as_bytes()),
        )?;
        Ok(ser_token)
    }

    pub fn decode_token(config: &PassConfig, token: String) -> PassResult<TokenData<UserToken>> {
        let token_data = jsonwebtoken::decode::<UserToken>(
            &token,
            &DecodingKey::from_secret(config.jwt_key.as_str().as_bytes()),
            &Validation::default(),
        )?;
        Ok(token_data)
    }
}

// For looking up master crypto params in keychain
pub const USER_KEY_PARAMS_NAME: &str = "user_key_params";

// For looking up master secret in keychain
pub const USER_SECRET_KEY_NAME: &str = "user_secret_key";

// file name for database
pub const DB_FILE_NAME: &str = "PlexPass.sqlite";

/// User represents an actor who uses password manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    // id of the user.
    pub user_id: String,
    // The version of the user in database.
    pub version: i64,
    // The username of user.
    pub username: String,
    // The roles of user.
    pub roles: Roles,
    // The name of user.
    pub name: Option<String>,
    // The email of user.
    pub email: Option<String>,
    // The icon of user.
    pub icon: Option<String>,
    // The attributes of user.
    pub attributes: Vec<NameValue>,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
}

impl User {
    pub fn new(username: &str, name: Option<String>, email: Option<String>) -> Self {
        User {
            user_id: Uuid::new_v4().to_string(),
            version: 0,
            username: username.into(),
            roles: Roles::new(0),
            name: name.clone(),
            email: email.clone(),
            icon: None,
            attributes: vec![],
            created_at: Some(Utc::now().naive_utc()),
            updated_at: Some(Utc::now().naive_utc()),
        }
    }

    pub fn key_params_name(&self) -> String {
        User::build_key_params_name(&self.username)
    }
    pub fn build_key_params_name(username: &str) -> String {
        format!("key_params_{}", username)
    }

    pub fn secret_key_name(&self) -> String {
        User::build_secret_key_name(&self.username)
    }
    pub fn build_secret_key_name(username: &str) -> String {
        format!("secret_key_{}", username)
    }

    pub fn validate(&self) -> PassResult<()> {
        if self.username.is_empty() {
            return Err(PassError::validation("username is not defined", None));
        }
        Ok(())
    }
}

impl PartialEq for User {
    fn eq(&self, other: &Self) -> bool {
        self.username == other.username
    }
}

impl Hash for User {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.username.hash(hasher);
    }
}

#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
pub enum LookupKind {
    CATEGORY,
    TAG,
}

impl Display for LookupKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LookupKind::CATEGORY => write!(f, "CATEGORY"),
            LookupKind::TAG => write!(f, "TAG"),
        }
    }
}

impl PartialEq for LookupKind {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
    }
}

impl From<&str> for LookupKind {
    fn from(s: &str) -> LookupKind {
        match s {
            "CATEGORY" => LookupKind::CATEGORY,
            "TAG" => LookupKind::TAG,
            _ => LookupKind::TAG,
        }
    }
}

// Setting names for scans
pub const LAST_LOCAL_SCAN_AT: &str = "LAST_LOCAL_SCAN_AT";
pub const LAST_REMOTE_SCAN_AT: &str = "LAST_REMOTE_SCAN_AT";

#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
pub enum SettingKind {
    Config,
    Scan,
    UserKeyParams,
}

impl Display for SettingKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SettingKind::Config => write!(f, "Config"),
            SettingKind::Scan => write!(f, "Scan"),
            SettingKind::UserKeyParams => write!(f, "UserKeyParams"),
        }
    }
}

impl PartialEq for SettingKind {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
    }
}

impl From<&str> for SettingKind {
    fn from(s: &str) -> SettingKind {
        match s {
            "Config" => SettingKind::Config,
            "Scan" => SettingKind::Scan,
            "UserKeyParams" => SettingKind::UserKeyParams,
            _ => SettingKind::Config,
        }
    }
}

/// AccountSummary defines summary of user-accounts that are used for listing accounts.
#[derive(Debug, Clone, Serialize, Deserialize, Eq)]
pub struct AccountSummary {
    // id of the account.
    pub account_id: String,
    // The version of the account in database.
    pub version: i64,
    // The title of the account.
    pub title: Option<String>,
    // favorite flag.
    pub favorite: bool,
    // risk mask.
    pub risk_mask: i64,
    // The description of the account.
    pub description: Option<String>,
    // The username of the account.
    pub username: Option<String>,
    // The email of the account.
    pub email: Option<String>,
    // The url of the account.
    pub url: Option<String>,
    // The categories of the account.
    pub categories: Vec<String>,
    // The tags of the account.
    pub tags: Vec<String>,
    // otp
    pub otp: Option<String>,
    // icon
    pub icon: Option<String>,
    // The metadata for dates of the account.
    pub credentials_updated_at: Option<NaiveDateTime>,
}

impl PartialEq for AccountSummary {
    fn eq(&self, other: &Self) -> bool {
        self.account_id == other.account_id
    }
}

impl Hash for AccountSummary {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.account_id.hash(hasher);
    }
}

impl AccountSummary {
    pub fn new() -> Self {
        Self {
            account_id: Uuid::new_v4().to_string(),
            version: 0,
            title: None,
            favorite: false,
            risk_mask: 0,
            description: None,
            username: None,
            email: None,
            url: None,
            categories: Default::default(),
            tags: Default::default(),
            otp: None,
            icon: None,
            credentials_updated_at: None,
        }
    }
}

/// AccountCredentials defines abstraction for user password and other encrypted data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountCredentials {
    // The password of the account.
    pub password: Option<String>,
    // The password hash of the account.
    pub password_sha1: Option<String>,
    // The form-fields of the account.
    pub form_fields: HashMap<String, String>,
    pub notes: Option<String>,
    pub password_policy: PasswordPolicy,
}

impl AccountCredentials {
    pub fn new() -> Self {
        Self {
            password: None,
            password_sha1: None,
            form_fields: Default::default(),
            notes: None,
            password_policy: PasswordPolicy::new(),
        }
    }
}

/// Account defines abstraction for user account with password to protect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    // details of account
    pub details: AccountSummary,
    // The vault_id associated with account the vault.
    pub vault_id: String,
    // The archived_version of the account in database.
    pub archived_version: Option<i64>,
    // The credentials of the account.
    pub credentials: AccountCredentials,
    // The hash of primary attributes
    pub value_hash: String,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
}

impl Account {
    pub fn new(vault_id: &str) -> Self {
        Self {
            details: AccountSummary::new(),
            vault_id: vault_id.into(),
            archived_version: None,
            credentials: AccountCredentials::new(),
            value_hash: "".into(),
            created_at: Some(Utc::now().naive_utc()),
            updated_at: Some(Utc::now().naive_utc()),
        }
    }

    fn filter_list(v: &Vec<String>) -> Vec<String> {
        let re = Regex::new(r"[,;:]").unwrap();
        v.into_iter()
            .map(|s| re.replace_all(s, "").trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }

    pub fn validate(&self) -> PassResult<()> {
        if !self.credentials.password.is_none() && self.credentials.password_sha1.is_none() {
            return Err(PassError::validation("password-hash not defined", None));
        }
        Ok(())
    }

    pub fn all_cat_tags(&self) -> String {
        let mut all_cat_tags = Vec::new();
        all_cat_tags.extend(Account::filter_list(&self.details.categories));
        all_cat_tags.extend(Account::filter_list(&self.details.tags));
        all_cat_tags.join(",")
    }

    pub fn compute_primary_attributes_hash(&self) -> String {
        let mut buf = String::with_capacity(128);
        if let Some(username) = &self.details.username {
            buf.push_str(&username);
        }
        if let Some(email) = &self.details.email {
            buf.push_str(&email);
        }
        if let Some(url) = &self.details.url {
            buf.push_str(&url);
        }
        if buf.len() == 0 {
            if let Some(notes) = &self.credentials.notes {
                buf.push_str(&notes);
            }
            for (k, v) in &self.credentials.form_fields {
                buf.push_str(k.as_str());
                buf.push_str(v.as_str());
            }
        }
        if buf.len() == 0 {
            if let Some(title) = &self.details.title {
                buf.push_str(&title);
            }
            if let Some(des) = &self.details.description {
                buf.push_str(&des);
            }
        }
        println!("hhhhhhhhhhhh {}", buf);
        crypto::compute_sha256(&buf)
    }

    pub fn before_save(&mut self) {
        // calculating sha1 of password
        if let Some(password) = self.credentials.password.clone() {
            let sha1 = crypto::compute_sha1(password.as_ref());
            if let Some(old_sha1) = self.credentials.password_sha1.clone() {
                if sha1 != old_sha1 {
                    self.details.credentials_updated_at = None;
                }
            } else {
                self.details.credentials_updated_at = None; // no previous sha1
            }
            self.credentials.password_sha1 = Some(sha1);
        }

        if self.details.credentials_updated_at.is_none() {
            self.details.credentials_updated_at = Some(Utc::now().naive_utc());
        }

        self.value_hash = self.compute_primary_attributes_hash();
        self.updated_at = Some(Utc::now().naive_utc());
    }
}

const DEFAULT_VAULT_NAMES: [&str; 4] = ["Personal", "Work", "Family & Shared", "Secure Notes"];
const DEFAULT_CATEGORIES: [&str; 10] = [
    "Login",
    "Bank",
    "Credit Card",
    "Finance",
    "Identity",
    "Note",
    "Social",
    "Shopping",
    "Travel",
    "Miscellaneous",
];

/// Vault represents a folder or bucket for storing passwords.
#[derive(Debug, Clone, Serialize, Deserialize, Eq)]
pub struct Vault {
    // The key representing the vault
    pub vault_id: String,
    // version of vault.
    pub version: i64,
    // The owner_user_id of the vault
    pub owner_user_id: String,
    // The name of vault.
    pub title: String,
    pub icon: Option<String>,
    pub entries: HashMap<String, AccountSummary>,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
}

impl Vault {
    pub fn new(owner_user_id: &str, title: &str) -> Self {
        Self {
            vault_id: Uuid::new_v4().to_string(),
            version: 0,
            owner_user_id: owner_user_id.into(),
            title: title.to_string(),
            entries: HashMap::new(),
            icon: None,
            created_at: Some(Utc::now().naive_utc()),
            updated_at: Some(Utc::now().naive_utc()),
        }
    }
}

impl PartialEq for Vault {
    fn eq(&self, other: &Self) -> bool {
        self.vault_id == other.vault_id
    }
}

impl Hash for Vault {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.vault_id.hash(hasher);
    }
}

impl Display for Vault {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.title)
    }
}

// PassConfig represents configuration for password manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassConfig {
    // The default constraints for password generation.
    pub default_constraints: Option<PasswordPolicy>,
    pub data_dir: String,
    pub http_port: String,
    pub https_port: String,
    pub max_pool_size: u32,
    pub max_retries: u32,
    pub delay_between_retries: u64,
    pub max_vaults_per_user: u32,
    pub max_accounts_per_vault: u32,
    pub max_lookup_entries: u32,
    pub max_setting_entries: u32,
    pub hash_algorithm: String,
    pub crypto_algorithm: String,
    pub hsm_provider: String,
    pub session_key: [u8; crypto::SECRET_LEN],
    pub api_secret: String, // master api secret
    pub jwt_key: String,
    pub jwt_max_age_secs: i64,
    pub cert_file: Option<String>,    // path to PEM file
    pub key_file: Option<String>,     // path to PEM file
    pub key_password: Option<String>, // password for encrypted private PEM file
}

const CHANGEME_SECRET: &str = "e68505475f740b2748024c7d140a5ffea037ff4dfde143a1549d7583c93b32b0";

impl PassConfig {
    pub fn new() -> Self {
        let _ = dotenv::dotenv(); // ignore errors
        let data_dir = std::env::var("DATA_DIR").unwrap_or("PlexPassData".into());
        fs::create_dir_all(Path::new(&data_dir)).expect("failed to create data dir");

        let hsm_provider = std::env::var("HSM_PROVIDER").unwrap_or("Keychain".into());
        let http_port = std::env::var("HTTP_PORT").unwrap_or("8080".into());
        let https_port = std::env::var("HTTPS_PORT").unwrap_or("8443".into());
        let api_secret = std::env::var("API_SECRET").unwrap_or(CHANGEME_SECRET.into());
        let jwt_key = std::env::var("JWT_KEY").unwrap_or(api_secret.clone());
        let jwt_max_age_secs: i64 = std::env::var("JWT_MAX_AGE")
            .unwrap_or("86400".into())
            .parse()
            .unwrap();
        let cert_file: Option<String> = if let Ok(val) = std::env::var("CERT_FILE") {
            Some(val)
        } else {
            None
        };
        let key_file: Option<String> = if let Ok(val) = std::env::var("KEY_FILE") {
            Some(val)
        } else {
            None
        };
        let key_password: Option<String> = if let Ok(val) = std::env::var("KEY_PASSWORD") {
            Some(val)
        } else {
            None
        };

        PassConfig {
            default_constraints: None,
            data_dir,
            http_port,
            https_port,
            max_pool_size: 10,
            max_retries: 10,
            delay_between_retries: 20, // milliseconds
            max_vaults_per_user: 1000,
            max_accounts_per_vault: 1000,
            max_lookup_entries: 1000,
            max_setting_entries: 1000,
            hash_algorithm: "ARGON2id".into(),
            crypto_algorithm: "Aes256Gcm".into(),
            hsm_provider,
            session_key: crypto::generate_secret_key(),
            api_secret,
            jwt_key,
            jwt_max_age_secs,
            cert_file,
            key_file,
            key_password,
        }
    }

    pub fn validate(&self) -> PassResult<()> {
        if self.api_secret == CHANGEME_SECRET {
            return Err(PassError::validation(
                "Please specify api-secret via API_SECRET environment variable",
                None,
            ));
        }
        Ok(())
    }
    pub fn http_port(&self) -> u16 {
        self.http_port.parse().unwrap()
    }
    pub fn https_port(&self) -> u16 {
        self.https_port.parse().unwrap()
    }

    pub fn database_file(&self) -> String {
        self.build_data_file(DB_FILE_NAME)
    }

    pub fn build_data_file(&self, file_name: &str) -> String {
        Path::new(&self.data_dir)
            .join(file_name)
            .to_str()
            .unwrap_or(file_name)
            .to_string()
    }

    pub fn hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::from(self.hash_algorithm.as_str())
    }

    pub fn crypto_algorithm(&self) -> CryptoAlgorithm {
        CryptoAlgorithm::from(self.crypto_algorithm.as_str())
    }

    pub fn hsm_provider(&self) -> HSMProvider {
        HSMProvider::from(self.hsm_provider.as_str())
    }
}

#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
pub enum PasswordStrength {
    WEAK,
    MODERATE,
    STRONG,
}

impl PartialEq for PasswordStrength {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
    }
}

impl Display for PasswordStrength {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PasswordStrength::WEAK => write!(f, "WEAK"),
            PasswordStrength::MODERATE => write!(f, "MODERATE"),
            PasswordStrength::STRONG => write!(f, "STRONG"),
        }
    }
}

impl PasswordStrength {
    fn from(s: &str) -> PasswordStrength {
        match s {
            "WEAK" => PasswordStrength::WEAK,
            "MODERATE" => PasswordStrength::MODERATE,
            "STRONG" => PasswordStrength::STRONG,
            _ => PasswordStrength::WEAK,
        }
    }
}

// PasswordPolicy represents configuration for password generation.
#[derive(Debug, Clone, Serialize, Deserialize, Eq)]
pub struct PasswordPolicy {
    // minimum number of upper_case letters should be included.
    pub min_uppercase: usize,
    // minimum number of lower_case letters should be included.
    pub min_lowercase: usize,
    // minimum number of digits should be included.
    pub min_digits: usize,
    // minimum number of symbols should be included.
    pub min_special_chars: usize,
    // minimum length of password.
    pub min_length: usize,
    // maximum length of password.
    pub max_length: usize,
    // exclude_ambiguous to remove ambiguous letters
    pub exclude_ambiguous: bool,
    // renew interval
    pub renew_interval_days: Option<i32>,
}

impl PasswordPolicy {
    pub fn new() -> Self {
        PasswordPolicy {
            min_uppercase: 2,
            min_lowercase: 2,
            min_digits: 2,
            min_special_chars: 2,
            min_length: 12,
            max_length: 16,
            exclude_ambiguous: true,
            renew_interval_days: None,
        }
    }

    fn total_min_size(&self) -> usize {
        self.min_uppercase + self.min_lowercase + self.min_digits + self.min_special_chars
    }

    /// Generate strong memorable password, consisting of `number_of_words` words.
    pub fn generate_strong_memorable_password(&self, number_of_words: usize) -> Option<String> {
        for _ in 0..10 {
            if let Some(password) = self.generate_memorable_password(number_of_words.clone()) {
                let analysis = PasswordPolicy::analyze_password(&password);
                if PasswordStrength::STRONG == analysis.strength {
                    return Some(password);
                }
            }
        }
        None
    }

    /// Generate a random password, consisting of `number_of_words` words.
    pub fn generate_memorable_password(&self, number_of_words: usize) -> Option<String> {
        let mut rng = rand::thread_rng();
        let die = Uniform::from(0..7776);

        let mut password = String::with_capacity(32);
        let special_chars: Vec<char> = SPECIAL_CHARS.chars().collect();
        for _ in 0..number_of_words {
            password.push_str(WORDS[die.sample(&mut rng)]);
            if let Some(ch) = special_chars.choose(&mut rand::thread_rng()) {
                password.push(*ch);
            }
        }

        //let mut password = rand_words.join("");

        // Convert some characters to uppercase
        for _ in 0..self.min_uppercase.clone() {
            let index = rng.gen_range(0..password.len());
            password = password
                .chars()
                .enumerate()
                .map(|(i, c)| {
                    if i == index {
                        c.to_uppercase().to_string()
                    } else {
                        c.to_string()
                    }
                })
                .collect();
        }

        // Convert some characters to digits
        let digits_map = [('a', '4'), ('e', '3'), ('i', '1'), ('o', '0'), ('s', '5')]
            .iter()
            .cloned()
            .collect::<HashMap<char, char>>();

        let mut remaining_to_replace = self.min_digits.clone();
        password = password
            .chars()
            .map(|c| {
                if remaining_to_replace > 0 && digits_map.contains_key(&c) {
                    remaining_to_replace -= 1;
                    digits_map[&c].to_string()
                } else {
                    c.to_string()
                }
            })
            .collect();

        let count_special = password.chars().filter(|&c| !c.is_alphanumeric()).count();
        if count_special < self.min_special_chars {
            // Convert some characters to special characters
            let special_map = [('a', '@'), ('e', '&'), ('i', '!'), ('o', '*'), ('s', '$')]
                .iter()
                .cloned()
                .collect::<HashMap<char, char>>();

            remaining_to_replace = self.min_special_chars.clone();
            password = password
                .chars()
                .map(|c| {
                    if remaining_to_replace > 0 && special_map.contains_key(&c) {
                        remaining_to_replace -= 1;
                        special_map[&c].to_string()
                    } else {
                        c.to_string()
                    }
                })
                .collect();
        }
        Some(password)
    }

    /// Generate strong random password
    pub fn generate_strong_random_password(&self) -> Option<String> {
        for _ in 0..10 {
            if let Some(password) = self.generate_random_password() {
                let analysis = PasswordPolicy::analyze_password(&password);
                if PasswordStrength::STRONG == analysis.strength {
                    return Some(password);
                }
            }
        }
        None
    }

    pub fn generate_random_password(&self) -> Option<String> {
        let exclude: Vec<char> = if self.exclude_ambiguous {
            vec![
                '0', 'O', 'D', 'Q', '1', 'I', '!', 'B', '8', 'G', '6', 'S', '5', 'Z', '2',
            ]
        } else {
            Vec::new()
        };
        let uppercase_chars: Vec<char> = ('A'..'Z').filter(|c| !exclude.contains(c)).collect();
        let lowercase_chars: Vec<char> = ('a'..'z').filter(|c| !exclude.contains(c)).collect();
        let digit_chars: Vec<char> = ('0'..'9').filter(|c| !exclude.contains(c)).collect();
        let special_chars: Vec<char> = SPECIAL_CHARS
            .chars()
            .filter(|c| !exclude.contains(c))
            .collect();

        let mut rng = rand::thread_rng();

        // Make sure the constraints do not exceed max_length
        if self.total_min_size() > self.max_length {
            return None;
        }

        let mut password: Vec<char> = Vec::with_capacity(self.max_length);

        password.extend(uppercase_chars.choose_multiple(&mut rng, self.min_uppercase));
        password.extend(lowercase_chars.choose_multiple(&mut rng, self.min_lowercase));
        password.extend(digit_chars.choose_multiple(&mut rng, self.min_digits));
        password.extend(special_chars.choose_multiple(&mut rng, self.min_special_chars));

        let remaining_length = self.max_length.saturating_sub(password.len());

        // Randomly select from all chars (excluding excluded ones) to fill up to max_length
        let all_chars: Vec<char> = uppercase_chars
            .iter()
            .chain(&lowercase_chars)
            .chain(&digit_chars)
            .chain(&special_chars)
            .map(|c| *c)
            .collect();
        password.extend(all_chars.choose_multiple(&mut rng, remaining_length));

        // Shuffle to make the order unpredictable
        password.shuffle(&mut rng);

        Some(password.iter().collect())
    }

    pub fn analyze_password(password: &str) -> PasswordAnalysis {
        let mut analysis = PasswordAnalysis {
            strength: PasswordStrength::WEAK,
            entropy: 0.0,
            uppercase: 0,
            lowercase: 0,
            digits: 0,
            special_chars: 0,
            length: password.len(),
        };
        let mut charset_size = 0;
        for c in password.chars() {
            if c.is_lowercase() {
                analysis.lowercase += 1;
            } else if c.is_uppercase() {
                analysis.uppercase += 1;
            } else if c.is_numeric() {
                analysis.digits += 1;
            } else if SPECIAL_CHARS.contains(c) {
                analysis.special_chars += 1;
            }
        }

        if password.chars().any(|c| c.is_lowercase()) {
            charset_size += 26; // a-z
        }
        if password.chars().any(|c| c.is_uppercase()) {
            charset_size += 26; // A-Z
        }
        if password.chars().any(|c| c.is_numeric()) {
            charset_size += 10; // 0-9
        }
        if password.chars().any(|c| SPECIAL_CHARS.contains(c)) {
            charset_size += 32; // special characters (adjust this based on your definition of special characters)
        }

        let unique_chars: HashSet<char> = password.chars().collect();
        let length_bonus = unique_chars.len() as f64 / password.len() as f64;

        analysis.entropy = (charset_size as f64).log2() * password.len() as f64 * length_bonus;

        analysis.strength = if analysis.entropy < 40.0 {
            PasswordStrength::WEAK
        } else if analysis.entropy < 80.0 {
            PasswordStrength::MODERATE
        } else {
            PasswordStrength::STRONG
        };
        // let unique_chars: HashSet<char> = password.chars().collect();
        // let n = unique_chars.len() as f64;
        // let l = password.len() as f64;
        // l * n.log2()

        analysis
    }
}

impl PartialEq for PasswordPolicy {
    fn eq(&self, _other: &Self) -> bool {
        false
    }
}

// NameValue represents pair of name value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NameValue {
    pub kind: String,
    pub name: String,
    pub value: String,
}

impl NameValue {
    pub fn new(kind: &str, name: &str, value: &str) -> Self {
        NameValue {
            kind: kind.to_string(),
            name: name.into(),
            value: value.into(),
        }
    }
}

// Lookup is used to define categories and tags
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lookup {
    pub lookup_id: String,
    pub user_id: String,
    pub kind: LookupKind,
    pub name: String,
}

impl Lookup {
    pub fn new(user_id: &str, kind: LookupKind, name: &str) -> Self {
        Self {
            lookup_id: Uuid::new_v4().to_string(),
            user_id: user_id.into(),
            kind: kind.clone(),
            name: name.into(),
        }
    }
}

impl PartialEq for Lookup {
    fn eq(&self, other: &Self) -> bool {
        self.lookup_id == other.lookup_id
    }
}

impl Hash for Lookup {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.lookup_id.hash(hasher);
    }
}

// Setting is used to define preferences for user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Setting {
    pub setting_id: String,
    pub user_id: String,
    pub kind: SettingKind,
    pub name: String,
    pub value: String,
}

impl Setting {
    pub fn new(user_id: &str, kind: SettingKind, name: &str, value: &str) -> Self {
        Self {
            setting_id: Uuid::new_v4().to_string(),
            user_id: user_id.into(),
            kind: kind.clone(),
            name: name.into(),
            value: value.into(),
        }
    }
}

impl PartialEq for Setting {
    fn eq(&self, other: &Self) -> bool {
        self.setting_id == other.setting_id
    }
}

impl Hash for Setting {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.setting_id.hash(hasher);
    }
}

/// Message represents a message, notification or alter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    // id of the message.
    pub message_id: String,
    // user_id of the message.
    pub user_id: String,
    // specversion of the message.
    pub specversion: String,
    // The source of message.
    pub source: String,
    // The message_type of message.
    pub message_type: String,
    // The flags of message.
    pub flags: i64,
    // The subject of message.
    pub subject: String,
    // The encrypted data of message.
    pub data: String,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
}

impl Message {
    pub fn new(user_id: &str, message_type: &str, subject: &str, data: &str) -> Self {
        Message {
            message_id: Uuid::new_v4().to_string(),
            user_id: user_id.into(),
            specversion: "1.0".into(),
            source: "".into(),
            message_type: message_type.to_string(),
            flags: 0,
            subject: subject.to_string(),
            data: data.to_string(),
            created_at: Some(Utc::now().naive_utc()),
            updated_at: Some(Utc::now().naive_utc()),
        }
    }
}

impl PartialEq for Message {
    fn eq(&self, other: &Self) -> bool {
        self.message_id == other.message_id
    }
}

impl Hash for Message {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.message_id.hash(hasher);
    }
}

pub const PBKDF2_HMAC_SHA256_ITERATIONS: u32 = 650_000;

#[derive(Debug, Clone, Eq)]
pub enum HSMProvider {
    EncryptedFile,
    Keychain,
}

impl Display for HSMProvider {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            HSMProvider::EncryptedFile => write!(f, "EncryptedFile"),
            HSMProvider::Keychain => write!(f, "Keychain"),
        }
    }
}

impl PartialEq for HSMProvider {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
    }
}

impl From<&str> for HSMProvider {
    fn from(s: &str) -> HSMProvider {
        match s {
            "EncryptedFile" => HSMProvider::EncryptedFile,
            "Keychain" => HSMProvider::Keychain,
            _ => HSMProvider::Keychain,
        }
    }
}

#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    Pbkdf2HmacSha256 {
        iterations: u32,
    },
    ARGON2id {
        memory_mi_b: u32,
        iterations: u32,
        parallelism: u32,
    },
}

impl Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            HashAlgorithm::Pbkdf2HmacSha256 { iterations } => {
                write!(f, "Pbkdf2HmacSha256({})", iterations)
            }
            HashAlgorithm::ARGON2id {
                memory_mi_b,
                iterations,
                parallelism,
            } => write!(
                f,
                "ARGON2id({}, {}, {})",
                memory_mi_b, iterations, parallelism
            ),
        }
    }
}

impl PartialEq for HashAlgorithm {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
    }
}

impl From<&str> for HashAlgorithm {
    fn from(s: &str) -> HashAlgorithm {
        match s {
            "Pbkdf2HmacSha256" => HashAlgorithm::Pbkdf2HmacSha256 {
                iterations: PBKDF2_HMAC_SHA256_ITERATIONS,
            },
            "ARGON2id" => HashAlgorithm::ARGON2id {
                memory_mi_b: 64,
                iterations: 3,
                parallelism: 1,
            },
            _ => HashAlgorithm::ARGON2id {
                memory_mi_b: 64,
                iterations: 3,
                parallelism: 1,
            },
        }
    }
}

#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
pub enum CryptoAlgorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Display for CryptoAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CryptoAlgorithm::Aes256Gcm => write!(f, "Aes256Gcm"),
            CryptoAlgorithm::ChaCha20Poly1305 => write!(f, "ChaCha20Poly1305"),
        }
    }
}

impl PartialEq for CryptoAlgorithm {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
    }
}

impl From<&str> for CryptoAlgorithm {
    fn from(s: &str) -> CryptoAlgorithm {
        match s {
            "Aes256Gcm" => CryptoAlgorithm::Aes256Gcm,
            "ChaCha20Poly1305" => CryptoAlgorithm::ChaCha20Poly1305,
            _ => CryptoAlgorithm::Aes256Gcm,
        }
    }
}

// EncryptRequest - request for encrypting data.
#[derive(Debug, Clone)]
pub struct EncryptRequest {
    pub salt: String,
    pub device_pepper: String,
    pub master_secret: String,
    pub hash_algorithm: HashAlgorithm,
    pub crypto_algorithm: CryptoAlgorithm,
    pub aad: String,
    pub plaintext: String,
}

impl EncryptRequest {
    pub fn new(
        salt: &str,
        device_pepper: &str,
        master_secret: &str,
        hash_algorithm: HashAlgorithm,
        crypto_algorithm: CryptoAlgorithm,
        plaintext: &str,
    ) -> Self {
        EncryptRequest {
            salt: salt.into(),
            device_pepper: device_pepper.into(),
            master_secret: master_secret.into(),
            hash_algorithm,
            crypto_algorithm,
            aad: master_secret.into(),
            plaintext: plaintext.to_string(),
        }
    }

    pub(crate) fn salt_bytes(&self) -> Result<Vec<u8>, FromHexError> {
        hex::decode(self.salt.clone())
    }
}

// EncryptResponse response for encrypting data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptResponse {
    pub nonce: String,
    pub ciphertext: String,
}

impl EncryptResponse {
    pub fn new(nonce: Vec<u8>, ciphertext: Vec<u8>) -> PassResult<Self> {
        Ok(EncryptResponse {
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(ciphertext),
        })
    }
}

// DecryptRequest - request for encrypting data.
#[derive(Debug, Clone)]
pub struct DecryptRequest {
    pub salt: String,
    pub nonce: String,
    pub device_pepper: String,
    pub master_secret: String,
    pub hash_algorithm: HashAlgorithm,
    pub crypto_algorithm: CryptoAlgorithm,
    pub aad: String,
    pub ciphertext: String,
}

impl DecryptRequest {
    pub fn new(
        salt: &str,
        nonce: &str,
        device_pepper: &str,
        master_secret: &str,
        hash_algorithm: HashAlgorithm,
        crypto_algorithm: CryptoAlgorithm,
        ciphertext: &str,
    ) -> Self {
        DecryptRequest {
            salt: salt.into(),
            nonce: nonce.into(),
            device_pepper: device_pepper.into(),
            master_secret: master_secret.into(),
            hash_algorithm,
            crypto_algorithm,
            aad: master_secret.into(),
            ciphertext: ciphertext.to_string(),
        }
    }
    pub(crate) fn ciphertext_bytes(&self) -> Result<Vec<u8>, FromHexError> {
        hex::decode(self.ciphertext.clone())
    }
    pub(crate) fn salt_bytes(&self) -> Result<Vec<u8>, FromHexError> {
        hex::decode(self.salt.clone())
    }
    pub(crate) fn nonce_bytes(&self) -> Result<Vec<u8>, FromHexError> {
        hex::decode(self.nonce.clone())
    }
}

// DecryptResponse response for encrypting data.
#[derive(Debug, Clone)]
pub struct DecryptResponse {
    pub plaintext: String,
}

impl DecryptResponse {
    pub fn new(plaintext: Vec<u8>) -> PassResult<Self> {
        Ok(DecryptResponse {
            plaintext: String::from_utf8(plaintext)?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordAnalysis {
    // strength of password.
    pub strength: PasswordStrength,
    // entropy of password.
    pub entropy: f64,
    // number of upper_case letters should be included.
    pub uppercase: usize,
    // number of lower_case letters should be included.
    pub lowercase: usize,
    // number of digits should be included.
    pub digits: usize,
    // number of symbols should be included.
    pub special_chars: usize,
    // length of password.
    pub length: usize,
}

#[cfg(test)]
mod tests {
    use crate::domain::models::{
        Account, CryptoAlgorithm, DecryptRequest, DecryptResponse, EncryptRequest, EncryptResponse,
        HSMProvider, HashAlgorithm, Lookup, LookupKind, Message, NameValue, PassConfig,
        PasswordPolicy, PasswordStrength, Roles, Setting, SettingKind, User, UserKeyParams, Vault,
        PBKDF2_HMAC_SHA256_ITERATIONS,
    };
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    #[test]
    fn test_should_create_roles() {
        let mut roles = Roles::new(0);
        assert!(!roles.is_admin());
        roles.set_admin();
        assert!(roles.is_admin());
    }

    #[test]
    fn test_should_create_user() {
        let user = User::new("user0", None, None);
        assert_eq!("user0", user.username);
        assert_eq!("key_params_user0", user.key_params_name());
        assert_eq!("secret_key_user0", user.secret_key_name());
        assert_eq!(None, user.name);
        assert_ne!(None, user.created_at);
        assert_ne!(None, user.updated_at);
        assert!(user.attributes.is_empty());
    }

    #[test]
    fn test_should_validate_user() {
        let mut user = User::new("user", None, None);
        user.username = "".into();
        assert!(user.validate().is_err());
        user.username = "some".into();
        assert!(user.validate().is_ok());
    }

    #[test]
    fn test_should_equal_user() {
        let user1 = User::new("user1", None, None);
        let user2 = User::new("user1", None, None);
        let user3 = User::new("user3", None, None);
        assert_eq!(user1, user2);
        assert_ne!(user1, user3);
        let mut hasher = DefaultHasher::new();
        user1.hash(&mut hasher);
        assert_ne!("", format!("{:x}!", hasher.finish()));
    }

    #[test]
    fn test_should_create_user_key_data() {
        let ukd = UserKeyParams::new("id", "salt", "pepper");
        let j = ukd.serialize().unwrap();
        let loaded = UserKeyParams::deserialize(&j).unwrap();
        assert_eq!("id", loaded.user_id);
        assert_eq!("salt", loaded.salt);
        assert_eq!("pepper", loaded.pepper);
    }

    #[test]
    fn test_should_create_lookup_kind() {
        let nv = NameValue::new(&LookupKind::TAG.to_string(), "name", "value");
        assert_eq!("name", nv.name);
        assert_eq!("value", nv.value);
        assert_eq!(LookupKind::TAG, LookupKind::from(nv.kind.as_str()));
    }

    #[test]
    fn test_should_create_account() {
        let account = Account::new("vault0");
        assert_ne!("", &account.details.account_id);
        assert_eq!("vault0", &account.vault_id);
        assert_eq!(0, account.details.version);
        assert_eq!(None, account.archived_version);
        assert!(!account.details.favorite);
        assert_eq!(0, account.details.risk_mask);
        assert_eq!(None, account.details.description);
        assert_eq!(None, account.details.username);
        assert_eq!(None, account.details.email);
        assert_eq!(None, account.details.url);
        assert_eq!(None, account.credentials.password);
        assert_eq!(None, account.credentials.password_sha1);
        assert_eq!(None, account.credentials.notes);
        assert_eq!(2, account.credentials.password_policy.min_digits);
        assert!(account.credentials.form_fields.is_empty());
        assert_eq!(None, account.details.credentials_updated_at);
        assert_ne!(None, account.created_at);
        assert_ne!(None, account.updated_at);
        assert!(account.details.categories.is_empty());
        assert!(account.details.tags.is_empty());
    }

    #[test]
    fn test_should_validate_account() {
        let mut account = Account::new("vault");
        account.details.username = Some("user".into());
        account.details.url = Some("url".into());
        account.credentials.password = Some("pass".into());
        assert!(account.validate().is_err());
        account.before_save();
        assert!(account.validate().is_ok());
    }

    #[test]
    fn test_should_before_save_account() {
        let mut account = Account::new("vault");
        account.details.categories = vec!["login".into(), "bank".into(), ", ".into()];
        account.details.tags = vec!["personal".into(), "work".into()];
        account.before_save();
    }

    #[test]
    fn test_should_equal_account() {
        let account1 = Account::new("vault1");
        let account2 = Account::new("vault1");
        let account3 = Account::new("vault1");
        assert_ne!(account1.details, account2.details);
        assert_ne!(account1.details, account3.details);
        let mut hasher = DefaultHasher::new();
        account1.details.hash(&mut hasher);
        assert_ne!("", format!("{:x}!", hasher.finish()));
    }

    #[test]
    fn test_should_create_vault() {
        let vault = Vault::new("user", "title");
        assert_eq!("title", vault.title);
        assert_ne!("", vault.vault_id);
        assert_eq!(0, vault.version);
        assert_ne!(None, vault.created_at);
        assert_ne!(None, vault.updated_at);
    }

    #[test]
    fn test_should_equal_vault() {
        let vault1 = Vault::new("user", "title");
        let vault2 = Vault::new("user", "title");
        assert_ne!(vault1, vault2);
        assert_eq!("title", vault1.to_string());
        let mut hasher = DefaultHasher::new();
        vault1.hash(&mut hasher);
        assert_ne!("", format!("{:x}!", hasher.finish()));
    }

    #[test]
    fn test_should_create_config() {
        let config = PassConfig::new();
        assert_eq!(None, config.default_constraints);
        assert_eq!("PlexPassData/PlexPass.sqlite", config.database_file());
        assert_eq!(10, config.max_pool_size);
        assert_eq!(HSMProvider::Keychain, config.hsm_provider());
        assert_eq!(CryptoAlgorithm::Aes256Gcm, config.crypto_algorithm());
        assert_eq!(
            HashAlgorithm::ARGON2id {
                memory_mi_b: 64,
                iterations: 3,
                parallelism: 1
            },
            config.hash_algorithm()
        );
    }

    #[test]
    fn test_generate_strong_memorable_password() {
        let pwc = PasswordPolicy::new();
        let password = pwc.generate_strong_memorable_password(3).unwrap();
        let analysis = PasswordPolicy::analyze_password(&password);
        assert_eq!(PasswordStrength::STRONG, analysis.strength);
        assert!(analysis.lowercase >= pwc.min_lowercase);
        assert!(analysis.uppercase >= pwc.min_uppercase);
        assert!(analysis.digits >= pwc.min_digits);
        assert!(analysis.special_chars >= pwc.min_special_chars);
        assert!(analysis.entropy > 80.0);
    }

    #[test]
    fn test_generate_memorable_password() {
        let mut pwc = PasswordPolicy::new();
        pwc.min_special_chars = 4;
        let password = pwc.generate_memorable_password(3).unwrap();
        let analysis = PasswordPolicy::analyze_password(&password);
        assert_eq!(PasswordStrength::STRONG, analysis.strength);
        assert!(analysis.lowercase >= pwc.min_lowercase);
        assert!(analysis.uppercase >= pwc.min_uppercase);
        assert!(analysis.digits >= pwc.min_digits);
        assert!(analysis.special_chars >= pwc.min_special_chars);
        assert!(analysis.entropy > 80.0);
    }

    #[test]
    fn test_should_random_generate_password() {
        let pwc = PasswordPolicy::new();
        let password = pwc.generate_strong_random_password().unwrap();
        let analysis = PasswordPolicy::analyze_password(&password);
        assert_eq!(PasswordStrength::STRONG, analysis.strength);
        assert!(analysis.lowercase >= pwc.min_lowercase);
        assert!(analysis.uppercase >= pwc.min_uppercase);
        assert!(analysis.digits >= pwc.min_digits);
        assert!(analysis.special_chars >= pwc.min_special_chars);
        assert!(analysis.entropy > 80.0);
    }

    #[test]
    fn test_should_convert_strength() {
        assert_eq!(PasswordStrength::STRONG, PasswordStrength::from("STRONG"));
    }

    #[test]
    fn test_should_create_name_value() {
        let nv = NameValue::new("kind", "name", "value");
        assert_eq!("kind", nv.kind);
        assert_eq!("name", nv.name);
        assert_eq!("value", nv.value);
    }

    #[test]
    fn test_should_create_lookup() {
        let lookup = Lookup::new("user", LookupKind::TAG, "name");
        assert_eq!(LookupKind::TAG, lookup.kind);
        assert_eq!("user", lookup.user_id);
        assert_eq!("name", lookup.name);
        assert_eq!(lookup, lookup);
        let mut hasher = DefaultHasher::new();
        lookup.hash(&mut hasher);
        assert_ne!("", format!("{:x}!", hasher.finish()));
    }

    #[test]
    fn test_should_create_setting() {
        let setting = Setting::new("user", SettingKind::Config, "name", "value");
        assert_eq!(SettingKind::Config, setting.kind);
        assert_eq!("user", setting.user_id);
        assert_eq!("name", setting.name);
        assert_eq!("value", setting.value);
        let mut hasher = DefaultHasher::new();
        setting.hash(&mut hasher);
        assert_ne!("", format!("{:x}!", hasher.finish()));
    }

    #[test]
    fn test_should_create_message() {
        let msg = Message::new("user", "type", "subject", "data");
        assert_eq!("user", msg.user_id);
        assert_eq!("type", msg.message_type);
        assert_eq!("subject", msg.subject);
        assert_eq!("data", msg.data);
        assert!(msg.created_at.expect("created time").timestamp() > 0);
        assert_eq!(msg, msg);
        let mut hasher = DefaultHasher::new();
        msg.hash(&mut hasher);
        assert_ne!("", format!("{:x}!", hasher.finish()));
    }

    #[test]
    fn test_should_parse_hsm_provider() {
        assert_eq!(
            HSMProvider::EncryptedFile,
            HSMProvider::from("EncryptedFile")
        );
        assert_eq!(HSMProvider::Keychain, HSMProvider::from("Keychain"));
        assert_eq!(HSMProvider::Keychain, HSMProvider::from("foo"));
        assert_eq!(HSMProvider::EncryptedFile.to_string(), "EncryptedFile");
        assert_eq!(HSMProvider::Keychain.to_string(), "Keychain");
    }

    #[test]
    fn test_should_parse_crypto_algorithm() {
        assert_eq!(
            CryptoAlgorithm::Aes256Gcm,
            CryptoAlgorithm::from("Aes256Gcm")
        );
        assert_eq!(
            CryptoAlgorithm::ChaCha20Poly1305,
            CryptoAlgorithm::from("ChaCha20Poly1305")
        );
        assert_eq!(CryptoAlgorithm::Aes256Gcm, CryptoAlgorithm::from("unknown"));
    }

    #[test]
    fn test_should_parse_hash_algorithm() {
        assert_eq!(
            HashAlgorithm::Pbkdf2HmacSha256 {
                iterations: PBKDF2_HMAC_SHA256_ITERATIONS,
            },
            HashAlgorithm::from("Pbkdf2HmacSha256")
        );
        assert_eq!(
            HashAlgorithm::ARGON2id {
                memory_mi_b: 64,
                iterations: 3,
                parallelism: 1
            },
            HashAlgorithm::from("ARGON2id")
        );
        assert_eq!(
            HashAlgorithm::ARGON2id {
                memory_mi_b: 64,
                iterations: 3,
                parallelism: 1
            },
            HashAlgorithm::from("unknown")
        );
    }

    #[test]
    fn test_should_build_encrypt_request_response() {
        let req = EncryptRequest::new(
            "salt",
            "pepper",
            "master",
            HashAlgorithm::Pbkdf2HmacSha256 {
                iterations: PBKDF2_HMAC_SHA256_ITERATIONS,
            },
            CryptoAlgorithm::Aes256Gcm,
            "text",
        );
        assert_eq!("master", req.master_secret);
        assert_eq!("salt", req.salt);
        assert_eq!("pepper", req.device_pepper);
        assert_eq!("text", req.plaintext);
        assert_eq!(
            HashAlgorithm::Pbkdf2HmacSha256 {
                iterations: PBKDF2_HMAC_SHA256_ITERATIONS,
            },
            req.hash_algorithm
        );
        assert_eq!(CryptoAlgorithm::Aes256Gcm, req.crypto_algorithm);
        let res = EncryptResponse::new("nonce".as_bytes().to_vec(), "cipher".as_bytes().to_vec())
            .unwrap();
        assert_eq!("6e6f6e6365", res.nonce); // hex encoded `nonce`
        assert_eq!("636970686572", res.ciphertext); // hex encoded `cipher`
    }

    #[test]
    fn test_should_build_decrypt_request_response() {
        let req = DecryptRequest::new(
            "salt",
            "nonce",
            "pepper",
            "master",
            HashAlgorithm::Pbkdf2HmacSha256 {
                iterations: PBKDF2_HMAC_SHA256_ITERATIONS,
            },
            CryptoAlgorithm::Aes256Gcm,
            "cipher",
        );
        assert_eq!("master", req.master_secret);
        assert_eq!("salt", req.salt);
        assert_eq!("nonce", req.nonce);
        assert_eq!("pepper", req.device_pepper);
        assert_eq!("cipher", req.ciphertext);
        assert_eq!(
            HashAlgorithm::Pbkdf2HmacSha256 {
                iterations: PBKDF2_HMAC_SHA256_ITERATIONS,
            },
            req.hash_algorithm
        );
        assert_eq!(CryptoAlgorithm::Aes256Gcm, req.crypto_algorithm);
        let res = DecryptResponse::new("plain".as_bytes().to_vec()).unwrap();
        assert_eq!("plain", res.plaintext);
    }
}
