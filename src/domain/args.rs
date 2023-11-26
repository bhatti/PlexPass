use std::collections::HashMap;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use crate::dao::models::UserContext;
use crate::domain::error::PassError;
use crate::domain::models::{Account, AccountKind, CryptoAlgorithm, HashAlgorithmTypes, PassConfig, PassResult, PasswordPolicy, SessionStatus, User, UserLocale, Vault, VaultKind};
use crate::service::locator::ServiceLocator;
use crate::utils::safe_parse_string_date;

#[derive(Subcommand, Debug, Clone)]
pub enum CommandActions {
    Server {
        /// HTTP Port
        #[arg(long)]
        http_port: Option<String>,

        /// HTTPS Port
        #[arg(long)]
        https_port: Option<String>,

        /// HSM Provider
        #[arg(long)]
        hsm_provider: Option<String>,

        /// Domain for Cert verification
        #[arg(long)]
        domain: Option<String>,

        /// JWT Secret key
        #[arg(long)]
        jwt_key: Option<String>,

        /// Session timeout in minutes
        #[arg(long, default_value_t = 30)]
        session_timeout_minutes: i64,

        /// Cert file path
        #[arg(long)]
        cert_file: Option<PathBuf>,

        /// path to PEM file
        #[arg(long)]
        key_file: Option<PathBuf>,

        /// password for PEM file
        #[arg(long)]
        key_password: Option<String>,
    },
    GetUser {
        /// Optional user-id if user is admin and can see other users.
        #[arg(long)]
        user_id: Option<String>,
    },
    CreateUser {
        // The name of user.
        #[arg(long)]
        name: Option<String>,

        // The email of user.
        #[arg(long)]
        email: Option<String>,

        // The locale of user.
        #[arg(long)]
        locale: Option<String>,

        // The light-mode of user.
        #[arg(long)]
        light_mode: Option<bool>,
    },
    UpdateUser {
        // The name of user.
        #[arg(long)]
        name: Option<String>,

        // The email of user.
        #[arg(long)]
        email: Option<String>,

        // The locale of user.
        #[arg(long)]
        locale: Option<String>,

        // The light-mode of user.
        #[arg(long)]
        light_mode: Option<bool>,

        // The icon of user.
        #[arg(long)]
        icon: Option<Vec<u8>>,
    },
    DeleteUser {
        /// Optional user-id if user is admin and can see other users.
        #[arg(long)]
        user_id: Option<String>,
    },
    CreateVault {
        /// The title of vault.
        #[arg(long)]
        title: String,

        /// The kind of vault
        #[arg(long)]
        kind: Option<VaultKind>,

        // The icon of vault.
        #[arg(long)]
        icon: Option<String>,
    },
    UpdateVault {
        /// The id of vault.
        #[arg(long)]
        vault_id: String,

        /// The title of vault.
        #[arg(long)]
        title: String,

        /// The kind of vault
        #[arg(long)]
        kind: Option<VaultKind>,

        // The icon of vault.
        #[arg(long)]
        icon: Option<String>,
    },
    DeleteVault {
        /// The id of vault.
        #[arg(long)]
        vault_id: String,
    },
    GetVault {
        /// The id of vault.
        #[arg(long)]
        vault_id: String,
    },
    GetVaults {},
    CreateAccount {
        /// The vault_id associated with account the vault.
        #[arg(long)]
        vault_id: String,
        /// kind of account
        #[arg(long)]
        kind: Option<AccountKind>,
        /// label of account.
        #[arg(long)]
        label: Option<String>,
        /// favorite flag.
        #[arg(long)]
        favorite: Option<bool>,
        // The description of the account.
        #[arg(long)]
        description: Option<String>,
        /// The username of the account.
        #[arg(long)]
        username: Option<String>,
        /// The password of the account.
        #[arg(long)]
        password: Option<String>,
        /// The email of the account.
        #[arg(long)]
        email: Option<String>,
        /// The phone of the account.
        #[arg(long)]
        phone: Option<String>,
        /// The address of the account.
        #[arg(long)]
        address: Option<String>,
        /// The url of the account.
        #[arg(long)]
        website_url: Option<String>,
        /// The category of the account.
        #[arg(long)]
        category: Option<String>,
        /// The tags of the account.
        #[arg(long)]
        tags: Option<Vec<String>>,
        // otp
        #[arg(long)]
        otp: Option<String>,
        /// icon
        #[arg(long)]
        icon: Option<String>,
        /// The notes
        #[arg(long)]
        notes: Option<String>,
        /// renew interval
        #[arg(long)]
        renew_interval_days: Option<i32>,
        /// expiration
        #[arg(long)]
        expires_at: Option<String>,
    },
    UpdateAccount {
        /// id of account
        #[arg(long)]
        account_id: String,

        /// The vault_id associated with account the vault.
        #[arg(long)]
        vault_id: String,

        /// kind of account
        #[arg(long)]
        kind: Option<AccountKind>,

        /// label of account.
        #[arg(long)]
        label: Option<String>,

        /// favorite flag.
        #[arg(long)]
        favorite: Option<bool>,

        // The description of the account.
        #[arg(long)]
        description: Option<String>,

        /// The username of the account.
        #[arg(long)]
        username: Option<String>,

        /// The password of the account.
        #[arg(long)]
        password: Option<String>,

        /// The email of the account.
        #[arg(long)]
        email: Option<String>,

        /// The phone of the account.
        #[arg(long)]
        phone: Option<String>,
        /// The address of the account.
        #[arg(long)]
        address: Option<String>,

        /// The url of the account.
        #[arg(long)]
        website_url: Option<String>,

        /// The category of the account.
        #[arg(long)]
        category: Option<String>,

        /// The tags of the account.
        #[arg(long)]
        tags: Option<Vec<String>>,

        // otp
        #[arg(long)]
        otp: Option<String>,

        /// icon
        #[arg(long)]
        icon: Option<String>,

        /// The notes
        #[arg(long)]
        notes: Option<String>,

        /// renew interval
        #[arg(long)]
        renew_interval_days: Option<i32>,

        /// expiration
        #[arg(long)]
        expires_at: Option<String>,
    },
    GetAccount {
        /// id of account
        #[arg(long)]
        account_id: String,
    },
    GetAccounts {
        /// The id of vault.
        #[arg(long)]
        vault_id: String,

        /// q
        #[arg(long)]
        q: Option<String>,
    },
    DeleteAccount {
        /// id of account
        #[arg(long)]
        account_id: String,
    },
    QueryAuditLogs {
        /// offset for query
        #[arg(long)]
        offset: Option<i64>,

        /// offset for limit
        #[arg(long)]
        limit: Option<usize>,

        /// q
        #[arg(long)]
        q: Option<String>,
    },
    CreateCategory {
        /// name
        #[arg(long)]
        name: String,
    },
    DeleteCategory {
        /// name
        #[arg(long)]
        name: String,
    },
    GetCategories {},
    GeneratePrivatePublicKeys {
        /// password
        #[arg(long)]
        password: Option<String>,
    },
    AsymmetricEncrypt {
        /// public key
        #[arg(long)]
        public_key: String,
        /// path to file to encrypt
        #[arg(long)]
        in_path: PathBuf,
        /// path to encrypted file
        #[arg(long)]
        out_path: PathBuf,
    },
    AsymmetricDecrypt {
        /// secret key
        #[arg(long)]
        secret_key: String,
        /// path to file to decrypt
        #[arg(long)]
        in_path: PathBuf,
        /// path to decrypted file
        #[arg(long)]
        out_path: PathBuf,
    },
    AsymmetricUserEncrypt {
        /// public key of target-username will be used
        #[arg(long)]
        target_username: String,
        /// path to file to encrypt
        #[arg(long)]
        in_path: PathBuf,
        /// path to encrypted file
        #[arg(long)]
        out_path: PathBuf,
    },
    AsymmetricUserDecrypt {
        /// path to file to decrypt
        #[arg(long)]
        in_path: PathBuf,
        /// path to decrypted file
        #[arg(long)]
        out_path: PathBuf,
    },
    SymmetricEncrypt {
        /// symmetric secret key
        #[arg(long)]
        secret_key: String,
        /// path to file to encrypt
        #[arg(long)]
        in_path: PathBuf,
        /// path to encrypted file
        #[arg(long)]
        out_path: PathBuf,
    },
    SymmetricDecrypt {
        /// symmetric secret key
        #[arg(long)]
        secret_key: String,
        /// path to file to decrypt
        #[arg(long)]
        in_path: PathBuf,
        /// path to decrypted file
        #[arg(long)]
        out_path: PathBuf,
    },
    ImportAccounts {
        /// vault-id optional
        #[arg(long)]
        vault_id: Option<String>,
        /// password if encrypted
        #[arg(long)]
        password: Option<String>,
        /// path to file to import
        #[arg(long)]
        in_path: PathBuf,
    },
    ExportAccounts {
        /// vault-id
        #[arg(long)]
        vault_id: String,
        /// password if to encrypt
        #[arg(long)]
        password: Option<String>,
        /// path to file to export
        #[arg(long)]
        out_path: PathBuf,
    },
    GeneratePassword {
        /// random or memorable password
        #[arg(long)]
        random: Option<bool>,
        /// minimum number of upper_case letters should be included.
        #[arg(long)]
        min_uppercase: Option<usize>,
        /// minimum number of lower_case letters should be included.
        #[arg(long)]
        min_lowercase: Option<usize>,
        /// minimum number of digits should be included.
        #[arg(long)]
        min_digits: Option<usize>,
        /// minimum number of symbols should be included.
        #[arg(long)]
        min_special_chars: Option<usize>,
        /// minimum length of password.
        #[arg(long)]
        min_length: Option<usize>,
        /// maximum length of password.
        #[arg(long)]
        max_length: Option<usize>,
        /// exclude_ambiguous to remove ambiguous letters
        #[arg(long)]
        exclude_ambiguous: Option<bool>,
    },
    PasswordCompromised {
        /// password
        #[arg(long)]
        password: String,
    },
    PasswordStrength {
        /// password
        #[arg(long)]
        password: String,
    },
    EmailCompromised {
        /// email
        #[arg(long)]
        email: String,
        /// hibp api key
        #[arg(long)]
        hibp_api_key: Option<String>,
    },
    AnalyzeVaultPasswords {
        /// vault-id
        #[arg(long)]
        vault_id: String,
    },
    AnalyzeAllVaultsPasswords {},
    SearchUsernames {
        /// q
        #[arg(long)]
        q: String,
    },
    GenerateOTP {
        /// otp_secret
        #[arg(long)]
        otp_secret: String,
    },
    GenerateAccountOTP {
        /// account-id
        #[arg(long)]
        account_id: String,
    },
    GenerateUserOTP {
    },
    GenerateAPIToken {
        /// duration of token
        #[arg(long)]
        jwt_max_age_minutes: Option<i64>,
    },
    ResetMultiFactorAuthentication {
        /// recovery_code
        #[arg(long)]
        recovery_code: String,
    },
    ShareVault {
        /// vault-id
        #[arg(long)]
        vault_id: String,
        /// target username
        #[arg(long)]
        target_username: String,
        /// read-only flag
        #[arg(long)]
        read_only: Option<bool>,
    },
    ShareAccount {
        /// vault-id
        #[arg(long)]
        vault_id: String,
        /// account-id
        #[arg(long)]
        account_id: String,
        /// target username
        #[arg(long)]
        target_username: String,
    },

}


/// PlexPass - a locally hostable secured password manager
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(next_line_help = true)]
pub struct Args {
    /// Action to perform
    #[command(subcommand)]
    pub action: CommandActions,

    /// json output of result from action
    #[arg(short, long, default_value = "false")]
    pub json_output: Option<bool>,

    /// Sets a data directory
    #[arg(short, long, value_name = "DATA_DIR")]
    pub data_dir: Option<PathBuf>,

    /// Device pepper key
    #[arg(long, value_name = "DEVICE_PEPPER_KEY")]
    pub device_pepper_key: Option<String>,

    /// Sets default crypto algorithm
    #[arg(long, value_name = "CRYPTO_ALG")]
    pub crypto_algorithm: Option<CryptoAlgorithm>,

    /// Sets default crypto hash algorithm
    #[arg(long, value_name = "HASH_ALG")]
    pub hash_algorithm: Option<HashAlgorithmTypes>,

    /// The username of local user.
    #[arg(long)]
    pub master_username: Option<String>,

    /// The master-password of user.
    #[arg(long)]
    pub master_password: Option<String>,

    /// The otp-code of user.
    #[arg(long)]
    pub otp_code: Option<u32>,

    /// Sets a custom config file
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,
}

impl Args {
    pub async fn to_args_context(&self, config: &PassConfig) -> PassResult<ArgsContext> {
        ArgsContext::auth_new(config, self).await
    }

    pub fn to_user(&self) -> Option<User> {
        let username = self.master_username.clone().expect("Please specify username with --master-username");
        match &self.action {
            CommandActions::CreateUser { name, email, locale, light_mode } => {
                let mut user = User::new(&username, name.clone(), email.clone());
                user.locale = UserLocale::match_any(locale);
                user.light_mode = *light_mode;
                Some(user)
            }
            CommandActions::UpdateUser { name, email, locale, light_mode, icon } => {
                let mut user = User::new(&username, name.clone(), email.clone());
                user.locale = UserLocale::match_any(locale);
                user.light_mode = *light_mode;
                if let Some(icon) = icon {
                    user.set_icon(icon.clone());
                }
                Some(user)
            }
            _ => {
                None
            }
        }
    }
    pub fn to_account(&self) -> Option<Account> {
        match &self.action {
            CommandActions::CreateAccount {
                vault_id,
                kind,
                label,
                favorite,
                description,
                username,
                password,
                email,
                phone,
                address,
                website_url,
                category,
                tags,
                otp,
                icon,
                notes,
                renew_interval_days,
                expires_at,
            } => {
                let account = self.build_account(
                    &vault_id,
                    kind,
                    label,
                    favorite,
                    description,
                    username,
                    password,
                    email,
                    phone,
                    address,
                    website_url,
                    category,
                    tags,
                    otp,
                    icon,
                    notes,
                    renew_interval_days,
                    expires_at,
                );
                Some(account)
            }
            CommandActions::UpdateAccount {
                account_id,
                vault_id,
                kind,
                label,
                favorite,
                description,
                username,
                password,
                email,
                phone,
                address,
                website_url,
                category,
                tags,
                otp,
                icon,
                notes,
                renew_interval_days,
                expires_at, ..
            } => {
                let mut account = self.build_account(
                    &vault_id,
                    kind,
                    label,
                    favorite,
                    description,
                    username,
                    password,
                    email,
                    phone,
                    address,
                    website_url,
                    category,
                    tags,
                    otp,
                    icon,
                    notes,
                    renew_interval_days,
                    expires_at,
                );
                account.details.account_id = account_id.clone();
                Some(account)
            }
            _ => {
                None
            }
        }
    }

    pub fn to_vault(&self) -> Option<Vault> {
        match &self.action {
            CommandActions::CreateVault { title, kind, icon } => {
                let mut vault = Vault::new("", title, kind.clone().unwrap_or(VaultKind::Logins));
                vault.icon = icon.clone();
                Some(vault)
            }
            CommandActions::UpdateVault { vault_id, title, kind, icon } => {
                let mut vault = Vault::new("", title, kind.clone().unwrap_or(VaultKind::Logins));
                vault.vault_id = vault_id.clone();
                vault.icon = icon.clone();
                Some(vault)
            }
            _ => {
                None
            }
        }
    }

    pub fn to_policy(&self) -> Option<PasswordPolicy> {
        match &self.action {
            CommandActions::GeneratePassword {
                random,
                min_uppercase,
                min_lowercase,
                min_digits,
                min_special_chars,
                min_length,
                max_length,
                exclude_ambiguous,
            } => {
                let policy = PasswordPolicy {
                    random: random.unwrap_or(false),
                    min_uppercase: min_uppercase.unwrap_or(1),
                    min_lowercase: min_lowercase.unwrap_or(1),
                    min_digits: min_digits.unwrap_or(1),
                    min_special_chars: min_special_chars.unwrap_or(1),
                    min_length: min_length.unwrap_or(12),
                    max_length: max_length.unwrap_or(16),
                    exclude_ambiguous: exclude_ambiguous.unwrap_or(false),
                };
                Some(policy)
            }
            _ => {
                None
            }
        }
    }

    fn build_account(&self,
                     vault_id: &&String,
                     kind: &Option<AccountKind>,
                     label: &Option<String>,
                     favorite: &Option<bool>,
                     description: &Option<String>,
                     username: &Option<String>,
                     password: &Option<String>,
                     email: &Option<String>,
                     phone: &Option<String>,
                     address: &Option<String>,
                     website_url: &Option<String>,
                     category: &Option<String>,
                     tags: &Option<Vec<String>>,
                     otp: &Option<String>,
                     icon: &Option<String>,
                     notes: &Option<String>,
                     renew_interval_days: &Option<i32>,
                     expires_at: &Option<String>,
    ) -> Account {
        let kind = if let Some(kind) = kind {
            kind.clone()
        } else if username.is_none() && email.is_none() && password.is_none() && notes.is_some() {
            AccountKind::Notes
        } else {
            AccountKind::Login
        };
        let mut account = Account::new(vault_id, kind);
        account.details.label = label.clone();
        account.details.favorite = *favorite == Some(true);
        account.details.description = description.clone();
        account.details.username = username.clone();
        account.details.email = email.clone();
        account.details.phone = phone.clone();
        account.details.address = address.clone();
        account.details.website_url = website_url.clone();
        account.details.category = category.clone();
        account.details.tags = tags.clone().unwrap_or_default();
        account.details.icon = icon.clone();
        account.details.renew_interval_days = *renew_interval_days;
        account.details.expires_at = safe_parse_string_date(expires_at.clone());

        account.credentials.password = password.clone();
        account.credentials.form_fields = HashMap::new();
        account.credentials.notes = notes.clone();
        account.credentials.otp = otp.clone();

        let password_policy = PasswordPolicy::new();
        account.credentials.password_policy = password_policy;
        account
    }
}

pub struct ArgsContext {
    pub config: PassConfig,
    pub user_context: UserContext,
    pub user: User,
    pub session_id: String,
    pub service_locator: ServiceLocator,
}

impl ArgsContext {
    pub async fn auth_new(config: &PassConfig, args: &Args) -> PassResult<Self> {
        let master_username = args.master_username.clone().expect("Please specify username with --master-username.");
        let master_password = args.master_password.clone().expect("Please specify master password with --master-password.");
        let service_locator = ServiceLocator::new(config).await?;
        let (ctx, user, token, session_status) = service_locator.auth_service.signin_user(
            &master_username, &master_password, args.otp_code, HashMap::new()).await?;

        if session_status == SessionStatus::RequiresMFA {
            return Err(PassError::authentication(
                "could not verify otp, please use settings section in the WebApp to find the otp-code."));
        }

        Ok(ArgsContext {
            config: config.clone(),
            user_context: ctx.clone(),
            user: user.clone(),
            session_id: token.login_session.clone(),
            service_locator: service_locator.clone(),
        })
    }
}

