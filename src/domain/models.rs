extern crate regex;

use std::fmt;
use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose;
use chrono::{Duration, NaiveDateTime, Utc};
use clap::{ValueEnum};
use hex::FromHexError;
use itertools::Itertools;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation};
use lazy_static::lazy_static;
use otpauth::TOTP;
use rand::distributions::{Distribution, Uniform};
use rand::Rng;
use rand::seq::SliceRandom;
use regex::Regex;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::{AuthenticationResult, CredentialID, Passkey};

use crate::crypto;
use crate::dao::models::{AuditKind, UserContext};
use crate::domain::error::PassError;
use crate::utils::words::WORDS;

const SPECIAL_CHARS: &str = "!@#$%^&*()-_=+[]{}|;:,.<>?";
pub const PBKDF2_HMAC_SHA256_ITERATIONS: u32 = 650_000;
const DEVICE_PEPPER_KEY: &str = "DEVICE_PEPPER_KEY";

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

/// An enum for progress callback
pub enum ProgressStatus {
    Started { total: usize },
    Updated { current: usize, total: usize },
    Completed,
    Failed(PassError),
}

#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
pub enum EncodingScheme {
    None,
    Hex,
    Base64,
}

impl EncodingScheme {
    pub(crate) fn encode(&self, data: Vec<u8>) -> PassResult<String> {
        match self {
            EncodingScheme::None => {
                String::from_utf8(data).map_err(
                    |_e| PassError::serialization("could not encode utf8"))
            }
            EncodingScheme::Hex => {
                Ok(hex::encode(data))
            }
            EncodingScheme::Base64 => {
                Ok(general_purpose::STANDARD_NO_PAD.encode(data))
            }
        }
    }
    pub(crate) fn decode(&self, data: &str) -> PassResult<Vec<u8>> {
        match self {
            EncodingScheme::None => {
                Ok(data.as_bytes().to_vec())
            }
            EncodingScheme::Hex => {
                hex::decode(data).map_err(
                    |_e| PassError::serialization("could  not decode hex"))
            }
            EncodingScheme::Base64 => {
                general_purpose::STANDARD_NO_PAD.decode(data).map_err(
                    |_e| PassError::serialization("could  not decode base64"))
            }
        }
    }
}

impl Display for EncodingScheme {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            EncodingScheme::None => write!(f, "None"),
            EncodingScheme::Hex => write!(f, "Hex"),
            EncodingScheme::Base64 => write!(f, "Base64"),
        }
    }
}

impl PartialEq for EncodingScheme {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
    }
}

impl From<&str> for EncodingScheme {
    fn from(s: &str) -> EncodingScheme {
        match s {
            "None" => EncodingScheme::None,
            "Hex" => EncodingScheme::Hex,
            _ => EncodingScheme::Base64,
        }
    }
}

pub const ADMIN_USER: i64 = 2048;

pub const READ_FLAG: i64 = 8192;

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
        self.mask & ADMIN_USER != 0
    }

    #[allow(dead_code)]
    pub(crate) fn set_admin(&mut self) {
        self.mask |= ADMIN_USER;
    }
}

impl PartialEq for Roles {
    fn eq(&self, other: &Self) -> bool {
        self.mask == other.mask
    }
}

/// ImportResult defines response for data import
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportResult {
    pub imported: usize,
    pub failed: usize,
    pub duplicate: usize,
}

impl Default for ImportResult {
    fn default() -> Self {
        Self::new()
    }
}

impl ImportResult {
    pub fn new() -> Self {
        Self {
            imported: 0,
            failed: 0,
            duplicate: 0,
        }
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

#[derive(Debug, Clone, PartialEq)]
pub enum SessionStatus {
    Valid,
    Invalid,
    RequiresMFA,
}

/// LoginSession for tracking authenticated sessions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginSession {
    // The session_id for login
    pub login_session_id: String,
    // The user_id for the user.
    pub user_id: String,
    // The username of user.
    pub username: String,
    // The roles of user.
    pub roles: i64,
    // The light mode of UI.
    pub light_mode: bool,
    // The source of the session.
    pub source: Option<String>,
    // The ip-address of the session.
    pub ip_address: Option<String>,
    pub mfa_required: bool,
    pub mfa_verified_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
    pub signed_out_at: Option<NaiveDateTime>,
}

impl LoginSession {
    pub fn new(user: &User) -> Self {
        Self {
            login_session_id: hex::encode(crypto::generate_secret_key()),
            user_id: user.user_id.clone(),
            username: user.username.clone(),
            roles: user.roles.clone().unwrap_or(Roles::new(0)).mask,
            light_mode: user.light_mode.unwrap_or_default(),
            source: None,
            ip_address: None,
            mfa_required: user.mfa_required(),
            mfa_verified_at: None,
            created_at: Utc::now().naive_utc(),
            signed_out_at: None,
        }
    }

    pub fn check_status(&self) -> SessionStatus {
        if self.signed_out_at.is_some() {
            return SessionStatus::Invalid;
        }
        let now = Utc::now().naive_utc();
        let eight_hours_ago = now - Duration::hours(8);
        if self.created_at < eight_hours_ago {
            return SessionStatus::Invalid;
        }
        if self.mfa_required && self.mfa_verified_at.is_none() {
            if self.expired_mfa() {
                return SessionStatus::Invalid;
            }
            return SessionStatus::RequiresMFA;
        }
        SessionStatus::Valid
    }

    pub fn expired_mfa(&self) -> bool {
        let now = Utc::now().naive_utc();
        let three_minutes_ago = now - Duration::minutes(3);
        self.created_at < three_minutes_ago
    }

    pub fn verified_mfa(&mut self) -> bool {
        if !self.mfa_required {
            return false;
        }
        if !self.expired_mfa() {
            self.mfa_verified_at = Some(Utc::now().naive_utc());
            return true;
        }
        false
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
    pub fn from_session(config: &PassConfig, session: &LoginSession) -> UserToken {
        let now = Utc::now().timestamp_nanos() / 1_000_000_000; // nanosecond -> second
        Self {
            iat: now,
            exp: now + (config.jwt_max_age_minutes * 60),
            user_id: session.user_id.clone(),
            username: session.username.clone(),
            roles: session.roles,
            login_session: session.login_session_id.clone(),
        }
    }

    pub fn from_context(
        session_id: &str,
        ctx: &UserContext,
        jwt_max_age_minutes: i64) -> UserToken {
        let now = Utc::now().timestamp_nanos() / 1_000_000_000; // nanosecond -> second
        Self {
            iat: now,
            exp: now + (jwt_max_age_minutes * 60),
            user_id: ctx.user_id.clone(),
            username: ctx.username.clone(),
            roles: ctx.roles.clone().unwrap_or(Roles::new(0)).mask,
            login_session: session_id.to_string(),
        }
    }

    pub fn encode_token(&self, config: &PassConfig) -> PassResult<String> {
        let ser_token = jsonwebtoken::encode(
            &Header::default(),
            self,
            &EncodingKey::from_secret(config.jwt_key.as_bytes()),
        )?;
        Ok(ser_token)
    }

    pub fn decode_token(config: &PassConfig, token: String) -> PassResult<TokenData<UserToken>> {
        let token_data = jsonwebtoken::decode::<UserToken>(
            &token,
            &DecodingKey::from_secret(config.jwt_key.as_bytes()),
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

/// HardwareSecurityKey abstracts hardware security key such as Yubikey.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareSecurityKey {
    pub id: String,
    // The name of key.
    pub name: String,
    // The kind of key.
    pub kind: String,
    // The secret for hardware key.
    pub key: Passkey,
    // recovery code
    pub recovery_code: String,
}

impl HardwareSecurityKey {
    pub fn new(name: &str, key: &Passkey) -> Self {
        Self {
            id: key.cred_id().to_string(),
            name: name.to_string(),
            kind: "webauthn".into(),
            key: key.clone(),
            recovery_code: crypto::generate_recovery_code(12),
        }
    }

    // recovery code should be one-time use only
    pub fn update_recovery(&mut self) {
        self.recovery_code = crypto::generate_recovery_code(12);
    }
}

/// UserLocale abstracts geographical locale for user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserLocale {
    // The short name.
    pub short_name: String,
    // The display-name of locale
    pub display_name: String,
}

lazy_static! {
    pub static ref DEFAULT_LOCALES: [UserLocale; 5] = [
        UserLocale::default(),
        UserLocale::new("es", "Spanish"),
        UserLocale::new("it", "Italian"),
        UserLocale::new("fr", "French"),
        UserLocale::new("de", "German"),
    ];
}

impl UserLocale {
    fn new(short_name: &str, display_name: &str) -> Self {
        Self {
            short_name: short_name.into(),
            display_name: display_name.into(),
        }
    }
    pub fn match_any(name: &Option<String>) -> Option<UserLocale> {
        if let Some(locale_str) = name {
            DEFAULT_LOCALES.iter()
                .find_or_first(|l| &l.display_name == locale_str ||
                    &l.short_name == locale_str).cloned()
        } else {
            None
        }
    }
}

impl Default for UserLocale {
    fn default() -> Self {
        Self {
            short_name: "en_US".into(),
            display_name: "US English".into(),
        }
    }
}

pub const MAX_ICON_LENGTH: usize = 81920;

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
    pub roles: Option<Roles>,
    // The name of user.
    pub name: Option<String>,
    // The email of user.
    pub email: Option<String>,
    // The locale of user.
    pub locale: Option<UserLocale>,
    // The light-mode of user.
    pub light_mode: Option<bool>,
    // The icon of user.
    pub icon: Option<String>,
    // The notifications enabled.
    pub notifications: Option<bool>,
    // hardware keys
    pub hardware_keys: Option<HashMap<String, HardwareSecurityKey>>,
    // otp secret for MFA
    pub otp_secret: String,
    // The attributes of user.
    pub attributes: Option<Vec<NameValue>>,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
}

impl User {
    pub fn new(username: &str, name: Option<String>, email: Option<String>) -> Self {
        User {
            user_id: Uuid::new_v4().to_string(),
            version: 0,
            username: username.into(),
            roles: None,
            name: name.clone(),
            email: email.clone(),
            locale: None,
            light_mode: None,
            icon: None,
            notifications: None,
            hardware_keys: None,
            otp_secret: crypto::generate_base32_secret(32),
            attributes: None,
            created_at: Some(Utc::now().naive_utc()),
            updated_at: Some(Utc::now().naive_utc()),
        }
    }

    pub fn set_icon(&mut self, icon: Vec<u8>) {
        self.icon = Some(base64_trim_icon(icon));
    }

    pub fn icon_string(&self) -> String {
        icon_string(&self.icon, "/assets/images/user.png")
    }

    pub fn verify_otp(&self, code: u32) -> bool {
        let totp = TOTP::new(self.otp_secret.clone());
        totp.verify(code, 30, Utc::now().timestamp() as u64)
    }

    pub fn reset_security_keys(&mut self, recovery_code: &str) -> bool {
        if let Some(keys) = &self.hardware_keys {
            if keys.iter().any(|(_, v)| v.recovery_code == recovery_code) {
                // Using empty hashmap so that we can update it otherwise we ignore none
                self.hardware_keys = Some(HashMap::new());
                return true;
            }
        }
        false
    }

    pub fn add_security_key(&mut self, name: &str, key: &Passkey) -> HardwareSecurityKey {
        let mut keys = self.hardware_keys.clone().unwrap_or_default();
        let hardware_key = HardwareSecurityKey::new(name, key);
        keys.insert(key.cred_id().to_string(), hardware_key.clone());
        self.hardware_keys = Some(keys);
        hardware_key
    }

    pub fn update_security_keys(&mut self, auth_result: &AuthenticationResult) {
        // This will update the credential if it's the matching
        // one. Otherwise it's ignored. That is why it is safe to
        // iterate this over the full list.
        let mut keys = self.hardware_keys.clone().unwrap_or_default();
        for key in keys.values_mut() {
            key.key.update_credential(auth_result);
        }
        self.hardware_keys = Some(keys);
    }

    pub fn mfa_required(&self) -> bool {
        match &self.hardware_keys {
            Some(keys) => !keys.is_empty(),
            None => false,
        }
    }

    pub fn get_security_keys(&self) -> Vec<Passkey> {
        match &self.hardware_keys {
            Some(keys) => keys.iter().map(|(_, key)| key.key.clone()).collect(),
            None => Vec::new(),
        }
    }

    pub fn remove_security_key(&mut self, id: &str) {
        let mut keys = self.hardware_keys.clone().unwrap_or_default();
        keys.remove(id);
        self.hardware_keys = Some(keys);
    }

    pub fn update(&mut self, other: &User) {
        self.version = other.version;
        // roles must be explicitly copied
        if other.roles.is_some() {
            self.roles = other.roles.clone();
        }
        self.name = other.name.clone();
        self.email = other.email.clone();
        self.locale = other.locale.clone();
        self.light_mode = other.light_mode;
        self.icon = other.icon.clone();
        self.notifications = other.notifications;
        if let Some(keys) = other.clone().hardware_keys {
            self.hardware_keys = Some(keys);
        }
        if let Some(attrs) = other.clone().attributes {
            self.attributes = Some(attrs);
        }
        self.otp_secret = other.otp_secret.clone();
        self.updated_at = Some(Utc::now().naive_utc());
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

    pub fn hardware_keys(&self) -> Vec<HardwareSecurityKey> {
        match &self.hardware_keys {
            Some(keys) => keys.iter().map(|(_, key)| key.clone()).collect(),
            None => Vec::new(),
        }
    }

    pub fn hardware_key_ids(&self) -> Option<Vec<CredentialID>> {
        self.hardware_keys.as_ref().map(|keys|
            keys.iter().map(|(_, key)| key.key.cred_id().clone()).collect()
        )
    }
    pub fn name_string(&self) -> String {
        self.name.clone().unwrap_or("".to_string())
    }
    pub fn email_string(&self) -> String {
        self.email.clone().unwrap_or("".to_string())
    }
    pub fn locale_string(&self) -> String {
        self.locale.clone().unwrap_or_default().display_name.to_string()
    }
    pub fn is_light_mode(&self) -> bool {
        self.light_mode.unwrap_or(false)
    }
    pub fn light_string(&self) -> String {
        if self.light_mode.unwrap_or(false) { "Light".into() } else { "Dark".into() }
    }
    pub fn is_notifications_on(&self) -> bool {
        self.notifications.unwrap_or(false)
    }
    pub fn notifications_string(&self) -> String {
        if self.notifications.unwrap_or(false) { "Enabled".into() } else { "Disabled".into() }
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
pub enum AccountRisk {
    High,
    Medium,
    Low,
    None,
    Unknown,
}

impl Display for AccountRisk {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AccountRisk::High => { write!(f, "High") }
            AccountRisk::Medium => { write!(f, "Medium") }
            AccountRisk::Low => { write!(f, "Low") }
            AccountRisk::None => { write!(f, "None") }
            AccountRisk::Unknown => { write!(f, "Unknown") }
        }
    }
}

impl PartialEq for AccountRisk {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
    }
}

impl From<&str> for AccountRisk {
    fn from(s: &str) -> AccountRisk {
        match s {
            "High" => AccountRisk::High,
            "Medium" => AccountRisk::Medium,
            "Low" => AccountRisk::Low,
            "None" => AccountRisk::None,
            _ => AccountRisk::Unknown,
        }
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

#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
pub enum AccountKind {
    Logins,
    Contacts,
    Notes,
    Custom,
}

impl AccountKind {
    pub fn to_vault_kind(&self) -> VaultKind {
        match self {
            AccountKind::Logins => VaultKind::Logins,
            AccountKind::Contacts => VaultKind::Contacts,
            AccountKind::Notes => VaultKind::Notes,
            AccountKind::Custom => VaultKind::Custom,
        }
    }
}

impl Display for AccountKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AccountKind::Logins => write!(f, "Logins"),
            AccountKind::Contacts => write!(f, "Contacts"),
            AccountKind::Notes => write!(f, "Notes"),
            AccountKind::Custom => write!(f, "Custom"),
        }
    }
}

impl PartialEq for AccountKind {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
    }
}

impl From<&str> for AccountKind {
    fn from(s: &str) -> AccountKind {
        match s {
            "Login" => AccountKind::Logins,
            "Custom" => AccountKind::Custom,
            "Notes" => AccountKind::Notes,
            "Contacts" => AccountKind::Contacts,
            _ => {
                let s = s.to_lowercase();
                if s.contains("note") {
                    AccountKind::Notes
                } else if s.contains("data") || s.contains("custom") || s.contains("form") {
                    AccountKind::Custom
                } else if s.contains("contact") {
                    AccountKind::Contacts
                } else {
                    AccountKind::Logins
                }
            }
        }
    }
}

/// AccountSummary defines summary of user-accounts that are used for listing accounts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordSimilarity {
    // levenshtein distance
    pub levenshtein_distance: usize,
    // jaccard similarity
    pub jaccard_similarity: f64,
    // cosine similarity
    pub cosine_similarity: f64,
    // jaro_winkler similarit
    pub jaro_winkler_similarity: f64,
}

/// AccountSummary defines summary of user-accounts that are used for listing accounts.
#[derive(Debug, Clone, Serialize, Deserialize, Eq)]
pub struct AccountSummary {
    // id of the account.
    pub account_id: String,
    // The version of the account in database.
    pub version: i64,
    // kind of account
    pub kind: AccountKind,
    // The label of the account.
    pub label: Option<String>,
    // favorite flag. - should be transient
    pub favorite: bool,
    // risk of password and account
    pub risk: AccountRisk,
    // The description of the account.
    pub description: Option<String>,
    // The username of the account.
    pub username: Option<String>,
    // The email of the account.
    pub email: Option<String>,
    // The phone of the account.
    pub phone: Option<String>,
    // The address of the account.
    pub address: Option<String>,
    // The url of the account.
    pub website_url: Option<String>,
    // The category of the account.
    pub category: Option<String>,
    // The tags of the account.
    pub tags: Vec<String>,
    // icon
    pub favicon: Option<String>,
    pub icon: Option<String>,
    pub advisories: HashMap<Advisory, String>,
    // renew interval
    pub renew_interval_days: Option<i32>,
    // expiration
    pub expires_at: Option<NaiveDateTime>,
    // due-at
    pub due_at: Option<NaiveDateTime>,
    // The metadata for date when password was changed.
    pub credentials_updated_at: Option<NaiveDateTime>,
    // The metadata for date when password was analyzed.
    pub analyzed_at: Option<NaiveDateTime>,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
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
    pub fn new(kind: AccountKind) -> Self {
        Self {
            account_id: Uuid::new_v4().to_string(),
            version: 0,
            kind,
            label: None,
            favorite: false,
            risk: AccountRisk::Unknown,
            description: None,
            username: None,
            email: None,
            phone: None,
            address: None,
            website_url: None,
            category: None,
            tags: Default::default(),
            favicon: None,
            icon: None,
            advisories: HashMap::new(),
            renew_interval_days: None,
            expires_at: None,
            due_at: None,
            credentials_updated_at: None,
            analyzed_at: None,
            created_at: Some(Utc::now().naive_utc()),
            updated_at: Some(Utc::now().naive_utc()),
        }
    }

    pub fn set_icon(&mut self, icon: Vec<u8>) {
        self.icon = Some(base64_trim_icon(icon));
    }

    pub fn icon_string(&self) -> String {
        icon_string(&self.icon, "/assets/images/account.png")
    }

    pub fn matches(&self, q: &str) -> bool {
        let lq = q.to_lowercase();
        if lq.contains(&self.account_id) {
            return true;
        }
        if lq.contains("favorite") && self.favorite {
            return true;
        }
        if (lq.contains("expire") || lq.contains("overdue")) && (self.is_expired() || self.is_due()) {
            return true;
        }
        if lq.contains("high_risk") &&
            (self.risk == AccountRisk::High || self.risk == AccountRisk::Medium) {
            return true;
        }
        if self.label_description().to_lowercase().contains(&lq) {
            return true;
        }
        if self.all_cat_tags().to_lowercase().contains(&lq) {
            return true;
        }
        if self.username().to_lowercase().contains(&lq) {
            return true;
        }
        if self.email().to_lowercase().contains(&lq) {
            return true;
        }
        if self.website_url().to_lowercase().contains(&lq) {
            return true;
        }
        if self.phone().to_lowercase().contains(&lq) {
            return true;
        }
        if self.address().to_lowercase().contains(&lq) {
            return true;
        }
        if format!("{:?}", &self.advisories).to_lowercase().contains(&lq) {
            return true;
        }
        false
    }

    pub fn all_cat_tags(&self) -> String {
        let mut all_cat_tags = Vec::new();
        if let Some(category) = &self.category {
            all_cat_tags.push(category.clone());
        }
        all_cat_tags.extend(Account::filter_list(&self.tags));
        all_cat_tags.join(",")
    }

    pub fn label_description(&self) -> String {
        self.label.clone().unwrap_or(self.description.clone().unwrap_or("".into()))
    }
    pub fn username(&self) -> String {
        self.username.clone().unwrap_or("".into())
    }

    pub fn has_favicon(&self) -> bool {
        self.favicon() != ""
    }

    pub fn has_url(&self) -> bool {
        not_empty(&self.website_url)
    }

    pub fn has_risk_image(&self) -> bool {
        match self.risk {
            AccountRisk::High => true,
            AccountRisk::Medium => true,
            AccountRisk::Low => true,
            AccountRisk::None => false,
            AccountRisk::Unknown => false,
        }
    }

    pub fn risk_image(&self) -> String {
        match self.risk {
            AccountRisk::High => { "/assets/images/danger.png".into() }
            AccountRisk::Medium => { "/assets/images/warning.png".into() }
            AccountRisk::Low => { "/assets/images/notice.png".into() }
            AccountRisk::None => { "".into() }
            AccountRisk::Unknown => { "".into() }
        }
    }

    pub fn is_expired_or_overdue(&self) -> bool {
        self.is_expired() || self.is_due()
    }

    pub fn has_expiration_due(&self) -> bool {
        self.expires_at.is_some() || self.due_at.is_some()
    }

    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = &self.expires_at {
            if expires_at.timestamp_millis() < Utc::now().naive_utc().timestamp_millis() {
                return true;
            }
        }
        false
    }

    pub fn is_due(&self) -> bool {
        if let Some(due_at) = &self.due_at {
            if due_at.timestamp_millis() < Utc::now().naive_utc().timestamp_millis() {
                return true;
            }
        }
        false
    }

    pub fn favicon(&self) -> String {
        if let Some(u) = &self.website_url {
            if let Ok(mut u) = url::Url::parse(u) {
                if let Ok(mut path) = u.path_segments_mut() {
                    path.clear();
                }
                u.set_query(None);
                return format!("{}/favicon.ico", u);
            }
        }

        if self.kind == AccountKind::Notes {
            return "/assets/images/note.svg".into();
        }
        String::new()
    }

    pub fn expires_at(&self) -> String {
        if let Some(expires_at) = &self.expires_at {
            return expires_at.format("%Y-%m-%d").to_string();
        }
        String::from("")
    }
    pub fn due_at(&self) -> String {
        if let Some(due_at) = &self.due_at {
            return due_at.format("%Y-%m-%d").to_string();
        }
        String::from("")
    }

    pub fn created_at(&self) -> String {
        if let Some(created_at) = &self.created_at {
            return created_at.format("%Y-%m-%d").to_string();
        }
        String::from("")
    }

    pub fn updated_at(&self) -> String {
        if let Some(updated_at) = &self.updated_at {
            return updated_at.format("%Y-%m-%d").to_string();
        }
        String::from("")
    }

    pub fn email(&self) -> String {
        self.email.clone().unwrap_or("".into())
    }

    pub fn website_url(&self) -> String {
        self.website_url.clone().unwrap_or("".into())
    }
    pub fn phone(&self) -> String {
        self.phone.clone().unwrap_or("".into())
    }
    pub fn address(&self) -> String {
        self.address.clone().unwrap_or("".into())
    }
}

impl Display for AccountSummary {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut buf = String::with_capacity(128);
        if let Some(label) = &self.label {
            buf.push_str(label);
        }
        if let Some(des) = &self.description {
            buf.push_str(des);
        }
        if let Some(username) = &self.username {
            buf.push_str(username);
        }
        if let Some(email) = &self.email {
            buf.push_str(email);
        }
        if let Some(website_url) = &self.website_url {
            buf.push_str(website_url);
        }
        if let Some(phone) = &self.phone {
            buf.push_str(phone);
        }
        if let Some(address) = &self.address {
            buf.push_str(address);
        }
        write!(f, "{}", buf)
    }
}


#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
pub enum Advisory {
    WeakPassword,
    PasswordReused,
    SimilarOtherPassword,
    SimilarPastPassword,
    CompromisedPassword,
    CompromisedWebsite,
    CompromisedEmail,
}

impl Display for Advisory {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Advisory::WeakPassword => write!(f, "WeakPassword"),
            Advisory::PasswordReused => write!(f, "PasswordReused"),
            Advisory::SimilarOtherPassword => write!(f, "SimilarOtherPassword"),
            Advisory::SimilarPastPassword => write!(f, "SimilarPastPassword"),
            Advisory::CompromisedPassword => write!(f, "CompromisedPassword"),
            Advisory::CompromisedWebsite => write!(f, "CompromisedWebsite"),
            Advisory::CompromisedEmail => write!(f, "CompromisedEmail"),
        }
    }
}

impl PartialEq for Advisory {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
    }
}

impl Hash for Advisory {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.to_string().hash(hasher);
    }
}

/// AuditLog represents an audit record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    // id of the audit.
    pub audit_id: String,
    // user_id of the audit record.
    pub user_id: String,
    // kind of audit record.
    pub kind: AuditKind,
    // The ip-address of audit record.
    pub ip_address: Option<String>,
    // The context parameters.
    pub context: String,
    // The message of audit record.
    pub message: String,
    pub created_at: NaiveDateTime,
}

impl AuditLog {
    pub fn safe_ip_address(&self) -> String {
        self.ip_address.clone().unwrap_or("".to_string())
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
    // otp base32-secret
    pub otp: Option<String>,
    pub past_passwords: HashSet<String>,
    pub password_policy: PasswordPolicy,
}

impl Default for AccountCredentials {
    fn default() -> Self {
        Self::new()
    }
}

impl AccountCredentials {
    pub fn new() -> Self {
        Self {
            password: None,
            password_sha1: None,
            form_fields: Default::default(),
            notes: None,
            otp: None,
            past_passwords: HashSet::new(),
            password_policy: PasswordPolicy::new(),
        }
    }

    pub fn has_password(&self) -> bool {
        not_empty(&self.password)
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
}

impl Account {
    pub fn new(vault_id: &str, kind: AccountKind) -> Self {
        Self {
            details: AccountSummary::new(kind),
            vault_id: vault_id.into(),
            archived_version: None,
            credentials: AccountCredentials::new(),
            value_hash: "".into(),
        }
    }

    pub fn clone_for_sharing(&self) -> Self {
        let mut copy = self.clone();
        copy.details.account_id = Uuid::new_v4().to_string();
        copy.details.version = 0;
        copy.archived_version = None;
        copy.details.credentials_updated_at = None;
        copy.details.analyzed_at = None;
        copy.details.favorite = false;
        copy.value_hash = "".into();
        copy.details.created_at = Some(Utc::now().naive_utc());
        copy.details.updated_at = Some(Utc::now().naive_utc());

        copy.before_save();
        copy
    }

    fn filter_list(v: &[String]) -> Vec<String> {
        let re = Regex::new(r"[,;:]").unwrap();
        v.iter()
            .map(|s| re.replace_all(s, "").trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }

    pub fn validate(&self) -> PassResult<()> {
        if self.credentials.password.is_some() && self.credentials.password_sha1.is_none() {
            return Err(PassError::validation("password-hash not defined", None));
        }
        Ok(())
    }

    pub fn compute_primary_attributes_hash(&self) -> String {
        let str = self.to_string();
        crypto::compute_sha256_hex(&str)
    }

    pub fn before_save(&mut self) {
        // calculating sha1 of password
        if let Some(password) = self.credentials.password.clone() {
            let sha1 = crypto::compute_sha1_hex(password.as_ref());
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
        if let Some(category) = &self.details.category {
            self.details.kind = AccountKind::from(category.as_str());
        }
        self.value_hash = self.compute_primary_attributes_hash();
        self.details.updated_at = Some(Utc::now().naive_utc());
    }

    pub fn update_analysis(&mut self, analysis: &AccountPasswordSummary) -> bool {
        if self.details.advisories.len() != analysis.advisories.len() ||
            self.details.advisories != analysis.advisories {
            self.details.advisories = analysis.advisories.clone();
            self.details.analyzed_at = Some(Utc::now().naive_utc());
            self.details.risk = AccountRisk::Unknown;
            if analysis.advisories.get(&Advisory::CompromisedPassword).is_some() ||
                analysis.advisories.get(&Advisory::CompromisedEmail).is_some() ||
                analysis.advisories.get(&Advisory::CompromisedWebsite).is_some() ||
                analysis.password_analysis.strength == PasswordStrength::WEAK {
                self.details.risk = AccountRisk::High;
            } else if analysis.password_analysis.strength == PasswordStrength::MODERATE &&
                (analysis.password_analysis.count_similar_to_other_passwords > 0 ||
                    analysis.password_analysis.count_similar_to_past_passwords > 0) {
                self.details.risk = AccountRisk::Medium;
            } else if analysis.password_analysis.strength == PasswordStrength::MODERATE ||
                analysis.password_analysis.count_similar_to_other_passwords > 0 ||
                analysis.password_analysis.count_similar_to_past_passwords > 0 {
                self.details.risk = AccountRisk::Low;
            } else {
                self.details.risk = AccountRisk::None;
            }
            true
        } else {
            false
        }
    }

    // convert to password summary
    pub fn to_password_summary(&self) -> AccountPasswordSummary {
        AccountPasswordSummary {
            account_id: self.details.account_id.clone(),
            label: self.details.label.clone(),
            username: self.details.username.clone(),
            email: self.details.email.clone(),
            phone: self.details.phone.clone(),
            address: self.details.address.clone(),
            website_url: self.details.website_url.clone(),
            advisories: self.details.advisories.clone(),
            credentials_updated_at: self.details.credentials_updated_at,
            analyzed_at: self.details.analyzed_at,
            password: self.credentials.password.clone(),
            past_passwords: self.credentials.past_passwords.clone(),
            password_policy: self.credentials.password_policy.clone(),
            password_analysis: PasswordAnalysis::new(),
        }
    }
}

impl Display for Account {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut buf = String::with_capacity(128);
        // First we try to identify each account by url, username, email and password
        if let Some(username) = &self.details.username {
            buf.push_str(username);
        }
        if let Some(email) = &self.details.email {
            buf.push_str(email);
        }
        if let Some(phone) = &self.details.phone {
            buf.push_str(phone);
        }
        if let Some(address) = &self.details.address {
            buf.push_str(address);
        }
        if let Some(url) = &self.details.website_url {
            buf.push_str(url);
        }

        if let Some(notes) = &self.credentials.notes {
            buf.push_str(notes);
        }
        for (k, v) in &self.credentials.form_fields {
            buf.push_str(k.as_str());
            buf.push_str(v.as_str());
        }

        // Finally identify by label and description
        if let Some(label) = &self.details.label {
            buf.push_str(label);
        }
        if let Some(des) = &self.details.description {
            buf.push_str(des);
        }
        write!(f, "{}", buf)
    }
}

/// AccountPasswordSummary is used to analyze passwords
#[derive(Debug, Clone)]
pub struct AccountPasswordSummary {
    // id of the account.
    pub account_id: String,
    // The label of the account.
    pub label: Option<String>,
    // The username of the account.
    pub username: Option<String>,
    // The email of the account.
    pub email: Option<String>,
    // The phoneof the account.
    pub phone: Option<String>,
    // The address of the account.
    pub address: Option<String>,
    // The url of the account.
    pub website_url: Option<String>,
    pub advisories: HashMap<Advisory, String>,
    // The metadata for date when password was changed.
    pub credentials_updated_at: Option<NaiveDateTime>,
    // The metadata for date when password was analyzed.
    pub analyzed_at: Option<NaiveDateTime>,
    // The password of the account.
    pub password: Option<String>,
    pub past_passwords: HashSet<String>,
    pub password_policy: PasswordPolicy,
    pub password_analysis: PasswordAnalysis,
}

impl AccountPasswordSummary {
    pub fn has_password(&self) -> bool {
        not_empty(&self.password)
    }
}

pub const DEFAULT_VAULT_NAMES: [&str; 5] = ["Identity", "Personal", "Work", "Contacts", "Secure Notes"];
pub const DEFAULT_CATEGORIES: [&str; 10] = [
    "Logins",
    "Contacts",
    "Notes",
    "Custom",
    "Finance",
    "Social",
    "Shopping",
    "Travel",
    "Gaming",
    "Credit Cards",
];

pub fn top_categories() -> Vec<String> {
    DEFAULT_CATEGORIES[0..3].to_vec().iter().map(|s| s.to_string()).collect()
}

pub fn all_categories() -> Vec<String> {
    let mut categories = DEFAULT_CATEGORIES.to_vec().iter().map(|s| s.to_string()).collect::<Vec<String>>();
    categories.sort();
    categories
}

#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
pub enum VaultKind {
    Logins,
    Contacts,
    Notes,
    Custom,
}

impl VaultKind {
    pub fn is_login(&self) -> bool {
        matches!(self, VaultKind::Logins)
    }

    pub fn is_contact(&self) -> bool {
        matches!(self, VaultKind::Contacts)
    }

    pub fn is_note(&self) -> bool {
        matches!(self, VaultKind::Notes)
    }
}

impl From<&str> for VaultKind {
    fn from(s: &str) -> VaultKind {
        match s {
            "Logins" => VaultKind::Logins,
            "Contacts" => VaultKind::Contacts,
            "Notes" => VaultKind::Notes,
            _ => {
                let s = s.to_lowercase();
                if s.contains("note") {
                    VaultKind::Notes
                } else if s.contains("data") || s.contains("custom") {
                    VaultKind::Custom
                } else {
                    VaultKind::Logins
                }
            }
        }
    }
}

impl Display for VaultKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VaultKind::Logins => write!(f, "Logins"),
            VaultKind::Contacts => write!(f, "Contacts"),
            VaultKind::Notes => write!(f, "Notes"),
            VaultKind::Custom => write!(f, "Custom"),
        }
    }
}

impl PartialEq for VaultKind {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
    }
}

impl Hash for VaultKind {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.to_string().hash(hasher);
    }
}


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
    pub kind: VaultKind,
    pub icon: Option<String>,
    pub entries: Option<HashMap<String, AccountSummary>>,
    pub analysis: Option<VaultAnalysis>,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
}

impl Vault {
    pub fn new(owner_user_id: &str, title: &str, kind: VaultKind) -> Self {
        Self {
            vault_id: Uuid::new_v4().to_string(),
            version: 0,
            owner_user_id: owner_user_id.into(),
            title: title.to_string(),
            kind,
            entries: None,
            analysis: None,
            icon: None,
            created_at: Some(Utc::now().naive_utc()),
            updated_at: Some(Utc::now().naive_utc()),
        }
    }

    pub fn set_icon(&mut self, icon: Vec<u8>) {
        self.icon = Some(base64_trim_icon(icon));
    }

    pub fn icon_string(&self) -> String {
        icon_string(&self.icon, "/assets/images/vault.png")
    }

    pub fn total_accounts(&self) -> usize {
        if let Some(entries) = &self.entries {
            entries.len()
        } else {
            0
        }
    }

    pub fn account_summaries(&self) -> Vec<AccountSummary> {
        let mut accounts: Vec<AccountSummary> = self.entries.clone().unwrap_or_default().values().cloned().collect();
        accounts.sort_by_key(|a| a.to_string().to_lowercase());
        accounts
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
    pub data_dir: PathBuf,
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
    pub domain: String,
    pub session_key: [u8; crypto::SECRET_LEN],
    // master device pepper key
    pub device_pepper_key: String,
    // master api secret
    pub jwt_key: String,
    pub session_timeout_minutes: i64,
    pub jwt_max_age_minutes: i64,
    // path to cert PEM file
    pub cert_file: Option<PathBuf>,
    // path to key PEM file
    pub key_file: Option<PathBuf>,
    // password for PEM file
    pub key_password: Option<String>,
    // password for encrypted private PEM file
    pub hibp_api_key: Option<String>, // API key for HIBP
}

const CHANGEME_SECRET: &str = "e68505475f740b2748024c7d140a5ffea037ff4dfde143a1549d7583c93b32b0";

impl Default for PassConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl PassConfig {
    pub fn new() -> Self {
        let _ = dotenv::dotenv(); // ignore errors
        let data_dir = std::env::var("DATA_DIR").unwrap_or("PlexPassData".into());

        let domain = std::env::var("DOMAIN").unwrap_or("localhost".into());
        let hsm_provider = Self::get_default_hsm();
        let http_port = std::env::var("HTTP_PORT").unwrap_or("8080".into());
        let https_port = std::env::var("HTTPS_PORT").unwrap_or("8443".into());
        let device_pepper_key = std::env::var("DEVICE_PEPPER_KEY").unwrap_or(CHANGEME_SECRET.into());
        let jwt_key = std::env::var("JWT_KEY").unwrap_or(device_pepper_key.clone());
        let hibp_api_key: Option<String> = if let Ok(val) = std::env::var("HIBP_API_KEY") { Some(val) } else { None };
        let session_timeout_minutes: i64 = std::env::var("SESSION_TIMEOUT_MINUTES")
            .unwrap_or("60".into())
            .parse()
            .unwrap();
        let jwt_max_age_minutes: i64 = std::env::var("JWT_MAX_AGE_MINUTES")
            .unwrap_or("8192".into())
            .parse()
            .unwrap();
        let session_key = if let Ok((_, session_key)) = crypto::generate_private_key_from_secret(&device_pepper_key) {
            session_key
        } else { crypto::generate_secret_key() };

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
            data_dir: PathBuf::from(&data_dir),
            http_port,
            https_port,
            max_pool_size: 10,
            max_retries: 10,
            delay_between_retries: 20, // milliseconds
            max_vaults_per_user: 1000,
            max_accounts_per_vault: 1000,
            max_lookup_entries: 1000,
            max_setting_entries: 1000,
            hash_algorithm: HashAlgorithmTypes::ARGON2id.to_string(),
            crypto_algorithm: CryptoAlgorithm::Aes256Gcm.to_string(),
            hsm_provider,
            domain,
            session_key,
            device_pepper_key,
            jwt_key,
            session_timeout_minutes,
            jwt_max_age_minutes,
            cert_file: cert_file.map(PathBuf::from),
            key_file: key_file.map(PathBuf::from),
            key_password,
            hibp_api_key,
        }
    }

    pub fn override_data_dir(&mut self, data_dir: &Path) {
        self.data_dir = data_dir.to_path_buf();

        if let Ok(data_dir) = data_dir.to_path_buf().into_os_string().into_string() {
            std::env::set_var("DATA_DIR", data_dir);
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn override_server_args(&mut self,
                                http_port: &Option<String>,
                                https_port: &Option<String>,
                                hsm_provider: &Option<String>,
                                domain: &Option<String>,
                                jwt_key: &Option<String>,
                                session_timeout_minutes: &Option<i64>,
                                cert_file: &Option<PathBuf>,
                                key_file: &Option<PathBuf>,
                                key_password: &Option<String>,
                                device_pepper_key: &Option<String>,
    ) {
        if let Some(http_port) = http_port {
            self.http_port = http_port.clone();
        }
        if let Some(https_port) = https_port {
            self.https_port = https_port.clone();
        }
        if let Some(hsm_provider) = hsm_provider {
            self.hsm_provider = hsm_provider.clone();
        }
        if let Some(domain) = domain {
            self.domain = domain.clone();
        }
        if let Some(jwt_key) = jwt_key {
            self.jwt_key = jwt_key.clone();
        }
        if let Some(session_timeout_minutes) = session_timeout_minutes {
            self.session_timeout_minutes = *session_timeout_minutes;
        }

        if let Some(cert_file) = cert_file {
            self.cert_file = Some(cert_file.clone());
        }
        if let Some(key_file) = key_file {
            self.key_file = Some(key_file.clone());
        }
        if let Some(key_password) = key_password {
            self.key_password = Some(key_password.clone());
        }
        if let Some(device_pepper_key) = device_pepper_key {
            self.device_pepper_key = device_pepper_key.clone();
        }
    }

    #[cfg(target_os = "macos")]
    fn get_default_hsm() -> String {
        std::env::var("HSM_PROVIDER").unwrap_or("Keychain".into())
    }

    #[cfg(not(target_os = "macos"))]
    fn get_default_hsm() -> String {
        std::env::var("HSM_PROVIDER").unwrap_or("EncryptedFile".into())
    }

    #[cfg(not(target_os = "macos"))]
    pub fn validate(&mut self) -> PassResult<()> {
        if self.device_pepper_key == CHANGEME_SECRET {
            return Err(PassError::validation(
                "Please specify device-secret via DEVICE_PEPPER_KEY environment variable",
                None,
            ));
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    pub fn validate(&mut self) -> PassResult<()> {
        use crate::store::hsm_store_keychain::KeychainHSMStore;
        use crate::store::HSMStore;
        if self.device_pepper_key == CHANGEME_SECRET {
            // auto create device pepper key and store it in keychain
            let hsm = KeychainHSMStore::new();
            if hsm.get_property("", DEVICE_PEPPER_KEY).is_err() {
                let device_pepper_key = hex::encode(crypto::generate_secret_key());
                hsm.set_property("", DEVICE_PEPPER_KEY, &device_pepper_key)?;
            }
            self.device_pepper_key = hsm.get_property("", DEVICE_PEPPER_KEY)?;
        }

        log::info!(
            "configuration using data-dir {:?}, hsm {}, cwd {:?}",
            &self.data_dir,
            &self.hsm_provider,
            std::env::current_dir()?,
        );
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

impl Hash for PasswordStrength {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.to_string().hash(hasher);
    }
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

impl From<&str> for PasswordStrength {
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
    // random or memorable password
    pub random: bool,
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
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl PasswordPolicy {
    pub fn new() -> Self {
        PasswordPolicy {
            random: false,
            min_uppercase: 1,
            min_lowercase: 1,
            min_digits: 1,
            min_special_chars: 1,
            min_length: 12,
            max_length: 16,
            exclude_ambiguous: true,
        }
    }

    fn total_min_size(&self) -> usize {
        self.min_uppercase + self.min_lowercase + self.min_digits + self.min_special_chars
    }

    /// Generate strong memorable password, consisting of `number_of_words` words.
    pub fn generate_strong_memorable_password(&self, number_of_words: usize) -> Option<String> {
        for _ in 0..10 {
            if let Some(password) = self.generate_memorable_password(number_of_words) {
                let info = PasswordPolicy::password_info(&password);
                if PasswordStrength::STRONG == info.strength {
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
        for i in 0..number_of_words {
            password.push_str(WORDS[die.sample(&mut rng)]);
            if i != &number_of_words - 1 {
                if let Some(ch) = special_chars.choose(&mut rand::thread_rng()) {
                    password.push(*ch);
                }
            }
        }

        //let mut password = rand_words.join("");

        // Convert some characters to uppercase
        for _ in 0..self.min_uppercase + 1 {
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

        let mut remaining_to_replace = self.min_digits;
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

            remaining_to_replace = self.min_special_chars;
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
                let info = PasswordPolicy::password_info(&password);
                if PasswordStrength::STRONG == info.strength {
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
        let uppercase_chars: Vec<char> = ('A'..='Z').filter(|c| !exclude.contains(c)).collect();
        let lowercase_chars: Vec<char> = ('a'..='z').filter(|c| !exclude.contains(c)).collect();
        let digit_chars: Vec<char> = ('0'..='9').filter(|c| !exclude.contains(c)).collect();
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
            .chain(&special_chars).copied()
            .collect();
        password.extend(all_chars.choose_multiple(&mut rng, remaining_length));

        // Shuffle to make the order unpredictable
        password.shuffle(&mut rng);

        Some(password.iter().collect())
    }

    pub fn password_info(password: &str) -> PasswordInfo {
        let mut info = PasswordInfo {
            strength: PasswordStrength::WEAK,
            entropy: 0.0,
            uppercase: 0,
            lowercase: 0,
            digits: 0,
            special_chars: 0,
            length: password.len(),
            compromised: false,
        };
        let mut charset_size = 0;
        for c in password.chars() {
            if c.is_lowercase() {
                info.lowercase += 1;
            } else if c.is_uppercase() {
                info.uppercase += 1;
            } else if c.is_numeric() {
                info.digits += 1;
            } else if SPECIAL_CHARS.contains(c) {
                info.special_chars += 1;
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

        info.entropy = (charset_size as f64).log2() * password.len() as f64 * length_bonus;

        info.strength = if info.entropy < 40.0 {
            PasswordStrength::WEAK
        } else if info.entropy < 80.0 {
            PasswordStrength::MODERATE
        } else {
            PasswordStrength::STRONG
        };
        // let unique_chars: HashSet<char> = password.chars().collect();
        // let n = unique_chars.len() as f64;
        // let l = password.len() as f64;
        // l * n.log2()

        info
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

#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
pub enum MessageKind {
    Advisory,
    Broadcast,
    DM,
    ShareVault,
    ShareAccount,
    Toast,
}

impl Display for MessageKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MessageKind::Advisory => { write!(f, "Advisory") }
            MessageKind::Broadcast => { write!(f, "Broadcast") }
            MessageKind::DM => { write!(f, "DM") }
            MessageKind::ShareVault => { write!(f, "ShareVault") }
            MessageKind::ShareAccount => { write!(f, "ShareAccount") }
            MessageKind::Toast => { write!(f, "Toast") }
        }
    }
}

impl PartialEq for MessageKind {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
    }
}

impl From<&str> for MessageKind {
    fn from(s: &str) -> MessageKind {
        match s {
            "Advisory" => MessageKind::Advisory,
            "Broadcast" => MessageKind::Broadcast,
            "DM" => MessageKind::DM,
            "ShareVault" => MessageKind::ShareVault,
            "ShareAccount" => MessageKind::ShareAccount,
            "Toast" => MessageKind::Toast,
            _ => MessageKind::Advisory,
        }
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
    // The kind of message.
    pub kind: MessageKind,
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
    pub fn new(user_id: &str, kind: MessageKind, subject: &str, data: &str) -> Self {
        Message {
            message_id: Uuid::new_v4().to_string(),
            user_id: user_id.into(),
            specversion: "1.0".into(),
            source: "".into(),
            kind,
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

/// ShareVaultMessage represents a message for sharing vault
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareVaultPayload {
    pub vault_id: String,
    pub vault_title: String,
    pub encrypted_crypto_key: String,
    pub from_user_id: String,
    pub from_username: String,
    pub target_user_id: String,
    pub read_only: bool,
}

impl ShareVaultPayload {
    pub fn new(
        vault_id: &str,
        vault_title: &str,
        encrypted_crypto_key: &str,
        from_user_id: &str,
        from_username: &str,
        target_user_id: &str,
        read_only: bool,
    ) -> Self {
        Self {
            vault_id: vault_id.to_string(),
            vault_title: vault_title.to_string(),
            encrypted_crypto_key: encrypted_crypto_key.to_string(),
            from_user_id: from_user_id.to_string(),
            from_username: from_username.to_string(),
            target_user_id: target_user_id.to_string(),
            read_only,
        }
    }
}

/// ShareAccountMessage represents a message for sharing account
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareAccountPayload {
    pub vault_id: String,
    pub vault_title: String,
    pub encrypted_account: String,
    pub from_user_id: String,
    pub from_username: String,
    pub target_user_id: String,
}

impl ShareAccountPayload {
    pub fn new(
        vault_id: &str,
        vault_title: &str,
        encrypted_account: &str,
        from_user_id: &str,
        from_username: &str,
        target_user_id: &str) -> Self {
        Self {
            vault_id: vault_id.to_string(),
            vault_title: vault_title.to_string(),
            encrypted_account: encrypted_account.to_string(),
            from_user_id: from_user_id.to_string(),
            from_username: from_username.to_string(),
            target_user_id: target_user_id.to_string(),
        }
    }
}

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

#[derive(ValueEnum, Debug, Clone, Eq, Serialize, Deserialize)]
pub enum HashAlgorithmTypes {
    Pbkdf2HmacSha256,
    ARGON2id,
}

impl Display for HashAlgorithmTypes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            HashAlgorithmTypes::Pbkdf2HmacSha256 => write!(f, "Pbkdf2HmacSha256"),
            HashAlgorithmTypes::ARGON2id => write!(f, "ARGON2id"),
        }
    }
}

impl PartialEq for HashAlgorithmTypes {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
    }
}

impl From<&str> for HashAlgorithmTypes {
    fn from(s: &str) -> HashAlgorithmTypes {
        match s {
            "Pbkdf2HmacSha256" => HashAlgorithmTypes::Pbkdf2HmacSha256,
            "ARGON2id" => HashAlgorithmTypes::ARGON2id,
            _ => HashAlgorithmTypes::ARGON2id,
        }
    }
}


#[derive(ValueEnum, Debug, Clone, Eq, Serialize, Deserialize)]
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
    pub payload: Vec<u8>,
    pub encoding: EncodingScheme,
}

impl EncryptRequest {
    pub fn new(
        salt: &str,
        device_pepper: &str,
        master_secret: &str,
        hash_algorithm: HashAlgorithm,
        crypto_algorithm: CryptoAlgorithm,
        payload: Vec<u8>,
        encoding: EncodingScheme,
    ) -> Self {
        EncryptRequest {
            salt: salt.into(),
            device_pepper: device_pepper.into(),
            master_secret: master_secret.into(),
            hash_algorithm,
            crypto_algorithm,
            aad: master_secret.into(),
            payload: payload.clone(),
            encoding,
        }
    }

    pub fn from_string(
        salt: &str,
        device_pepper: &str,
        master_secret: &str,
        hash_algorithm: HashAlgorithm,
        crypto_algorithm: CryptoAlgorithm,
        plaintext: &str,
        encoding: EncodingScheme,
    ) -> Self {
        Self::new(
            salt,
            device_pepper,
            master_secret,
            hash_algorithm,
            crypto_algorithm,
            plaintext.as_bytes().to_vec(),
            encoding,
        )
    }

    pub(crate) fn salt_bytes(&self) -> Vec<u8> {
        self.salt.as_bytes().to_vec().clone()
    }
}

// EncryptResponse response for encrypting data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptResponse {
    pub nonce: String,
    pub cipher_payload: Vec<u8>,
    pub encoding: EncodingScheme,
}

impl EncryptResponse {
    pub fn new(nonce: Vec<u8>, cipher_payload: Vec<u8>, encoding: EncodingScheme) -> Self {
        EncryptResponse {
            nonce: hex::encode(nonce),
            cipher_payload,
            encoding,
        }
    }

    pub fn encoded_payload(&self) -> PassResult<String> {
        self.encoding.encode(self.cipher_payload.clone())
    }
}

// DecryptRequest - request for encrypting data.
#[derive(Debug, Clone)]
pub struct DecryptRequest {
    pub salt: String,
    pub device_pepper: String,
    pub master_secret: String,
    pub hash_algorithm: HashAlgorithm,
    pub crypto_algorithm: CryptoAlgorithm,
    pub aad: String,
    pub nonce: String,
    pub cipher_payload: Vec<u8>,
    pub encoding: EncodingScheme,
}

impl DecryptRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        salt: &str,
        device_pepper: &str,
        master_secret: &str,
        hash_algorithm: HashAlgorithm,
        crypto_algorithm: CryptoAlgorithm,
        nonce: &str,
        cipher_payload: Vec<u8>,
        encoding: EncodingScheme,
    ) -> Self {
        DecryptRequest {
            salt: salt.into(),
            device_pepper: device_pepper.into(),
            master_secret: master_secret.into(),
            hash_algorithm,
            crypto_algorithm,
            aad: master_secret.into(),
            nonce: nonce.into(),
            cipher_payload,
            encoding,
        }
    }


    #[allow(clippy::too_many_arguments)]
    pub fn from_string(
        salt: &str,
        device_pepper: &str,
        master_secret: &str,
        hash_algorithm: HashAlgorithm,
        crypto_algorithm: CryptoAlgorithm,
        nonce: &str,
        ciphertext: &str,
        encoding: EncodingScheme,
    ) -> PassResult<Self> {
        Ok(Self::new(
            salt,
            device_pepper,
            master_secret,
            hash_algorithm,
            crypto_algorithm,
            nonce,
            encoding.decode(ciphertext)?,
            encoding,
        ))
    }

    pub(crate) fn salt_bytes(&self) -> Vec<u8> {
        self.salt.as_bytes().to_vec().clone()
    }

    pub(crate) fn nonce_bytes(&self) -> Result<Vec<u8>, FromHexError> {
        hex::decode(self.nonce.clone())
    }
}

// DecryptResponse response for encrypting data.
#[derive(Debug, Clone)]
pub struct DecryptResponse {
    pub payload: Vec<u8>,
}

impl DecryptResponse {
    pub fn new(payload: Vec<u8>) -> PassResult<Self> {
        Ok(DecryptResponse {
            payload,
        })
    }
    pub fn payload_string(&self) -> PassResult<String> {
        Ok(String::from_utf8(self.payload.clone())?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordInfo {
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
    // compromised flag of password.
    pub compromised: bool,
}

impl Display for PasswordInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "length of {}, {} uppercase, {} lowercase, {} digits, {} special-letters has {} strength",
               self.length, self.uppercase, self.lowercase, self.digits, self.special_chars, self.strength)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordAnalysis {
    // strength of password.
    pub strength: PasswordStrength,
    // if password is pwned by hibp.
    pub compromised: bool,
    // similar to other passwords
    pub count_similar_to_other_passwords: usize,
    // similar to past passwords
    pub count_similar_to_past_passwords: usize,
    // passwords reused
    pub count_reused: usize,
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
    // compromised account analysis
    pub compromised_account_analysis: String,
}

impl Default for PasswordAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

impl PasswordAnalysis {
    pub fn new() -> Self {
        Self {
            strength: PasswordStrength::WEAK,
            compromised: false,
            count_similar_to_other_passwords: 0,
            count_similar_to_past_passwords: 0,
            count_reused: 0,
            entropy: 0.0,
            uppercase: 0,
            lowercase: 0,
            digits: 0,
            special_chars: 0,
            length: 0,
            compromised_account_analysis: "".to_string(),
        }
    }

    pub fn copy_from(&mut self, info: &PasswordInfo) {
        self.strength = info.strength.clone();
        self.entropy = info.entropy;
        self.uppercase = info.uppercase;
        self.lowercase = info.lowercase;
        self.digits = info.digits;
        self.special_chars = info.special_chars;
        self.length = info.length;
    }

    pub fn is_healthy(&self) -> bool {
        self.strength == PasswordStrength::STRONG &&
            !self.compromised &&
            self.count_similar_to_other_passwords == 0 &&
            self.count_similar_to_past_passwords == 0 &&
            self.count_reused == 0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq)]
pub struct VaultAnalysis {
    pub total_accounts: usize,
    pub total_accounts_with_passwords: usize,
    pub count_strong_passwords: usize,
    pub count_moderate_passwords: usize,
    pub count_weak_passwords: usize,
    pub count_healthy_passwords: usize,
    pub count_compromised: usize,
    pub count_reused: usize,
    pub count_similar_to_other_passwords: usize,
    pub count_similar_to_past_passwords: usize,
    // The metadata for date when passwords for the vault were analyzed.
    pub analyzed_at: NaiveDateTime,
}

impl Default for VaultAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultAnalysis {
    pub fn new() -> Self {
        Self {
            total_accounts: 0,
            total_accounts_with_passwords: 0,
            count_strong_passwords: 0,
            count_moderate_passwords: 0,
            count_weak_passwords: 0,
            count_healthy_passwords: 0,
            count_compromised: 0,
            count_reused: 0,
            count_similar_to_other_passwords: 0,
            count_similar_to_past_passwords: 0,
            analyzed_at: NaiveDateTime::from_timestamp(0, 0),
        }
    }

    pub fn analyzed_at_string(&self) -> String {
        self.analyzed_at.format("%Y-%m-%d %H:%M:%S").to_string()
    }

    pub fn risk_score(&self) -> usize {
        if self.total_accounts > 0 {
            self.count_healthy_passwords * 100 / self.total_accounts
        } else {
            0
        }
    }

    pub fn add(&mut self, other: Option<VaultAnalysis>) {
        if let Some(other) = other {
            self.total_accounts += other.total_accounts;
            self.total_accounts_with_passwords += other.total_accounts_with_passwords;
            self.count_strong_passwords += other.count_strong_passwords;
            self.count_moderate_passwords += other.count_moderate_passwords;
            self.count_weak_passwords += other.count_weak_passwords;
            self.count_healthy_passwords += other.count_healthy_passwords;
            self.count_compromised += other.count_compromised;
            self.count_reused += other.count_reused;
            self.count_similar_to_other_passwords += other.count_similar_to_other_passwords;
            self.count_similar_to_past_passwords += other.count_similar_to_past_passwords;
            if other.analyzed_at.timestamp_millis() > self.analyzed_at.timestamp_millis() {
                self.analyzed_at = other.analyzed_at;
            }
        }
    }

    pub fn update(&mut self, password_summary: &AccountPasswordSummary) {
        self.total_accounts += 1;
        if password_summary.has_password() {
            self.total_accounts_with_passwords += 1;
            match password_summary.password_analysis.strength {
                PasswordStrength::WEAK => { self.count_weak_passwords += 1; }
                PasswordStrength::MODERATE => { self.count_moderate_passwords += 1; }
                PasswordStrength::STRONG => { self.count_strong_passwords += 1; }
            }
            if password_summary.password_analysis.is_healthy() {
                self.count_healthy_passwords += 1;
            }
            if password_summary.password_analysis.compromised {
                self.count_compromised += 1;
            }
            if password_summary.password_analysis.count_reused > 0 {
                self.count_reused += 1;
            }
            if password_summary.password_analysis.count_similar_to_other_passwords > 0 {
                self.count_similar_to_other_passwords += 1;
            }
            if password_summary.password_analysis.count_similar_to_past_passwords > 0 {
                self.count_similar_to_past_passwords += 1;
            }
        }
    }
}

impl PartialEq for VaultAnalysis {
    fn eq(&self, other: &Self) -> bool {
        self.total_accounts == other.total_accounts &&
            self.total_accounts_with_passwords == other.total_accounts_with_passwords &&
            self.count_strong_passwords == other.count_strong_passwords &&
            self.count_moderate_passwords == other.count_moderate_passwords &&
            self.count_weak_passwords == other.count_weak_passwords &&
            self.count_healthy_passwords == other.count_healthy_passwords &&
            self.count_compromised == other.count_compromised &&
            self.count_reused == other.count_reused &&
            self.count_similar_to_other_passwords == other.count_similar_to_other_passwords &&
            self.count_similar_to_past_passwords == other.count_similar_to_past_passwords
    }
}

pub fn icon_string(icon: &Option<String>, def_icon: &str) -> String {
    if let Some(icon) = non_empty_string(icon) {
        format!("data:image/png;base64,{}", icon)
    } else {
        def_icon.to_string()
    }
}

pub fn base64_trim_icon(icon: Vec<u8>) -> String {
    let bytes = if icon.len() > MAX_ICON_LENGTH {
        icon[0..MAX_ICON_LENGTH].to_vec()
    } else {
        icon
    };
    general_purpose::STANDARD_NO_PAD.encode(bytes)
}

pub fn non_empty_string(opt: &Option<String>) -> Option<String> {
    if let Some(s) = opt {
        if !s.is_empty() && !s.chars().all(char::is_whitespace) {
            return Option::from(s.clone());
        }
    }
    None
}

pub fn not_empty(opt: &Option<String>) -> bool {
    if let Some(s) = opt {
        if !s.is_empty() && !s.chars().all(char::is_whitespace) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    use crate::domain::models::{Account, AccountKind, AccountRisk, CryptoAlgorithm, DecryptRequest, DecryptResponse, EncodingScheme, EncryptRequest, EncryptResponse, HashAlgorithm, HSMProvider, Lookup, LookupKind, Message, MessageKind, NameValue, PassConfig, PasswordPolicy, PasswordStrength, PBKDF2_HMAC_SHA256_ITERATIONS, Roles, Setting, SettingKind, User, UserKeyParams, Vault, VaultKind};

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
        let account = Account::new("vault0", AccountKind::Logins);
        assert_ne!("", &account.details.account_id);
        assert_eq!("vault0", &account.vault_id);
        assert_eq!(0, account.details.version);
        assert_eq!(None, account.archived_version);
        assert!(!account.details.favorite);
        assert_eq!(AccountRisk::Unknown, account.details.risk);
        assert_eq!(None, account.details.description);
        assert_eq!(None, account.details.username);
        assert_eq!(None, account.details.email);
        assert_eq!(None, account.details.phone);
        assert_eq!(None, account.details.address);
        assert_eq!(None, account.details.website_url);
        assert_eq!(None, account.credentials.password);
        assert_eq!(None, account.credentials.password_sha1);
        assert_eq!(None, account.credentials.notes);
        assert_eq!(1, account.credentials.password_policy.min_digits);
        assert!(account.credentials.form_fields.is_empty());
        assert_eq!(None, account.details.credentials_updated_at);
        assert_ne!(None, account.details.created_at);
        assert_ne!(None, account.details.updated_at);
        assert!(account.details.category.is_none());
        assert!(account.details.tags.is_empty());
    }

    #[test]
    fn test_should_validate_account() {
        let mut account = Account::new("vault", AccountKind::Logins);
        account.details.username = Some("user".into());
        account.details.website_url = Some("url".into());
        account.credentials.password = Some("pass".into());
        assert!(account.validate().is_err());
        account.before_save();
        assert!(account.validate().is_ok());
    }

    #[test]
    fn test_should_before_save_account() {
        let mut account = Account::new("vault", AccountKind::Logins);
        account.details.category = Some("login".into());
        account.details.tags = vec!["personal".into(), "work".into()];
        account.before_save();
    }

    #[test]
    fn test_should_equal_account() {
        let account1 = Account::new("vault1", AccountKind::Logins);
        let account2 = Account::new("vault1", AccountKind::Logins);
        let account3 = Account::new("vault1", AccountKind::Logins);
        assert_ne!(account1.details, account2.details);
        assert_ne!(account1.details, account3.details);
        let mut hasher = DefaultHasher::new();
        account1.details.hash(&mut hasher);
        assert_ne!("", format!("{:x}!", hasher.finish()));
    }

    #[test]
    fn test_should_create_vault() {
        let vault = Vault::new("user", "title", VaultKind::Logins);
        assert_eq!("title", vault.title);
        assert_ne!("", vault.vault_id);
        assert_eq!(0, vault.version);
        assert_ne!(None, vault.created_at);
        assert_ne!(None, vault.updated_at);
    }

    #[test]
    fn test_should_equal_vault() {
        let vault1 = Vault::new("user", "title", VaultKind::Logins);
        let vault2 = Vault::new("user", "title", VaultKind::Logins);
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
        assert_eq!(CryptoAlgorithm::Aes256Gcm, config.crypto_algorithm());
        assert_eq!(
            HashAlgorithm::ARGON2id {
                memory_mi_b: 64,
                iterations: 3,
                parallelism: 1,
            },
            config.hash_algorithm()
        );
    }

    #[test]
    fn test_generate_strong_memorable_password() {
        let pwc = PasswordPolicy::new();
        let password = pwc.generate_strong_memorable_password(3).unwrap();
        let info = PasswordPolicy::password_info(&password);
        assert_eq!(PasswordStrength::STRONG, info.strength, "{}", password);
        assert!(info.lowercase >= pwc.min_lowercase, "{}", password);
        assert!(info.uppercase >= pwc.min_uppercase, "{}", password);
        assert!(info.digits >= pwc.min_digits, "{}", password);
        assert!(info.special_chars >= pwc.min_special_chars, "{}", password);
        assert!(info.entropy > 80.0, "{} - {}", password, info);
    }

    #[test]
    fn test_generate_memorable_password() {
        let mut pwc = PasswordPolicy::new();
        pwc.min_special_chars = 4;
        let password = pwc.generate_memorable_password(3).unwrap();
        let info = PasswordPolicy::password_info(&password);
        assert_eq!(PasswordStrength::STRONG, info.strength, "{}", password);
        assert!(info.lowercase >= pwc.min_lowercase, "{}", password);
        assert!(info.uppercase >= pwc.min_uppercase, "{}", password);
        assert!(info.digits >= pwc.min_digits, "{}", password);
        assert!(info.special_chars >= pwc.min_special_chars, "{}", password);
        assert!(info.entropy > 80.0, "{}", password);
    }

    #[test]
    fn test_should_random_generate_password() {
        let pwc = PasswordPolicy::new();
        let password = pwc.generate_strong_random_password().unwrap();
        let info = PasswordPolicy::password_info(&password);
        assert_eq!(PasswordStrength::STRONG, info.strength);
        assert!(info.lowercase >= pwc.min_lowercase);
        assert!(info.uppercase >= pwc.min_uppercase);
        assert!(info.digits >= pwc.min_digits);
        assert!(info.special_chars >= pwc.min_special_chars);
        assert!(info.entropy > 80.0);
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
        let msg = Message::new("user", MessageKind::Broadcast, "subject", "data");
        assert_eq!("user", msg.user_id);
        assert_eq!(MessageKind::Broadcast, msg.kind);
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
                parallelism: 1,
            },
            HashAlgorithm::from("ARGON2id")
        );
        assert_eq!(
            HashAlgorithm::ARGON2id {
                memory_mi_b: 64,
                iterations: 3,
                parallelism: 1,
            },
            HashAlgorithm::from("unknown")
        );
    }

    #[test]
    fn test_should_build_encrypt_request_response() {
        let req = EncryptRequest::from_string(
            "salt",
            "pepper",
            "master",
            HashAlgorithm::Pbkdf2HmacSha256 {
                iterations: PBKDF2_HMAC_SHA256_ITERATIONS,
            },
            CryptoAlgorithm::Aes256Gcm,
            "text",
            EncodingScheme::Base64,
        );
        assert_eq!("master", req.master_secret);
        assert_eq!("salt", req.salt);
        assert_eq!("pepper", req.device_pepper);
        assert_eq!("text".as_bytes(), req.payload);
        assert_eq!(
            HashAlgorithm::Pbkdf2HmacSha256 {
                iterations: PBKDF2_HMAC_SHA256_ITERATIONS,
            },
            req.hash_algorithm
        );
        assert_eq!(CryptoAlgorithm::Aes256Gcm, req.crypto_algorithm);
        let res = EncryptResponse::new(
            "nonce".as_bytes().to_vec(),
            "cipher".as_bytes().to_vec(),
            EncodingScheme::Hex);
        assert_eq!("6e6f6e6365", res.nonce); // hex encoded `nonce`
        assert_eq!("636970686572", res.encoded_payload().unwrap()); // hex encoded `cipher`

        let res = EncryptResponse::new(
            "nonce".as_bytes().to_vec(),
            "cipher".as_bytes().to_vec(),
            EncodingScheme::Base64);
        assert_eq!("6e6f6e6365", res.nonce); // hex encoded `nonce`
        assert_eq!("636970686572", hex::encode(res.cipher_payload)); // hex base64 `cipher`
    }

    #[test]
    fn test_should_build_decrypt_request_response() {
        let req = DecryptRequest::from_string(
            "salt",
            "pepper",
            "master",
            HashAlgorithm::Pbkdf2HmacSha256 {
                iterations: PBKDF2_HMAC_SHA256_ITERATIONS,
            },
            CryptoAlgorithm::Aes256Gcm,
            "nonce",
            "cipher",
            EncodingScheme::None,
        ).unwrap();
        assert_eq!("master", req.master_secret);
        assert_eq!("salt", req.salt);
        assert_eq!("nonce", req.nonce);
        assert_eq!("pepper", req.device_pepper);
        assert_eq!("cipher".as_bytes(), req.cipher_payload);
        assert_eq!(
            HashAlgorithm::Pbkdf2HmacSha256 {
                iterations: PBKDF2_HMAC_SHA256_ITERATIONS,
            },
            req.hash_algorithm
        );
        assert_eq!(CryptoAlgorithm::Aes256Gcm, req.crypto_algorithm);
        let res = DecryptResponse::new("plain".as_bytes().to_vec()).unwrap();
        assert_eq!("plain".as_bytes(), res.payload);
    }
}
