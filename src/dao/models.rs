use std::backtrace::Backtrace;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Display;
use crate::crypto;
use crate::dao::schema::*;
use crate::domain::error::PassError;
use crate::domain::models::{Account, CryptoAlgorithm, DecryptRequest, EncryptRequest, HashAlgorithm, LoginSession, Lookup, LookupKind, Message, PassResult, Roles, Setting, SettingKind, User, UserKeyParams, Vault, PBKDF2_HMAC_SHA256_ITERATIONS, VaultKind, EncodingScheme, AuditLog};
use chrono::{NaiveDateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};
use uuid::Uuid;

pub const CONTEXT_IP_ADDRESS: &str = "ip_address";

/// UserContext defines master key, pepper, hashing and crypto algorithms.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserContext {
    // The username for the user.
    pub username: String,
    // The user_id for the user.
    pub user_id: String,
    // The roles for the user.
    pub roles: Roles,
    // The pepper key for the user.
    pub pepper: String,
    // The secret_key generated from the user password and user pepper.
    pub secret_key: String,
    pub hash_algorithm: HashAlgorithm,
    pub crypto_algorithm: CryptoAlgorithm,
    pub attributes: HashMap<String, String>,
}

impl UserContext {
    pub fn new(
        username: &str,
        user_id: &str,
        roles: Roles,
        pepper: &str,
        secret_key: &str,
        hash_algorithm: HashAlgorithm,
        crypto_algorithm: CryptoAlgorithm,
    ) -> Self {
        Self {
            username: username.into(),
            user_id: user_id.into(),
            roles,
            pepper: pepper.into(),
            secret_key: secret_key.into(),
            hash_algorithm,
            crypto_algorithm,
            attributes: HashMap::new(),
        }
    }

    pub fn from_master_password(
        username: &str,
        user_id: &str,
        master_password: &str,
        roles: Roles,
        salt: &str,
        pepper: &str,
        hash_algorithm: HashAlgorithm,
        crypto_algorithm: CryptoAlgorithm,
    ) -> PassResult<Self> {
        let secret_key =
            Self::build_secret_key(salt, pepper, master_password, hash_algorithm.clone())?;

        Ok(Self::new(
            username,
            user_id,
            roles,
            pepper,
            &secret_key,
            hash_algorithm,
            crypto_algorithm,
        ))
    }

    // Create master symmetric secret key based on master-password, salt, and pepper using secured hashing algorithm
    pub(crate) fn build_secret_key(
        salt: &str,
        pepper: &str,
        master_password: &str,
        hash_algorithm: HashAlgorithm,
    ) -> PassResult<String> {
        Ok(hex::encode(crypto::compute_hash(
            &hex::decode(salt)?,
            pepper,
            master_password,
            hash_algorithm.clone(),
        )?))
    }

    pub(crate) fn default_new(
        username: &str,
        user_id: &str,
        salt: &str,
        pepper: &str,
        master_password: &str,
    ) -> PassResult<Self> {
        UserContext::from_master_password(
            username,
            user_id,
            master_password,
            Roles::new(0),
            salt,
            pepper,
            HashAlgorithm::Pbkdf2HmacSha256 {
                iterations: PBKDF2_HMAC_SHA256_ITERATIONS,
            },
            CryptoAlgorithm::Aes256Gcm,
        )
    }

    pub(crate) fn as_admin(&self) -> Self {
        let mut copy = self.clone();
        copy.roles.set_admin();
        copy
    }

    pub(crate) fn validate_username(&self, username: &str) -> PassResult<()> {
        if self.username == username || self.is_admin() {
            Ok(())
        } else {
            Err(PassError::authorization(
                "username in context didn't match target user entity",
            ))
        }
    }

    pub(crate) fn validate_user_id(&self,
                                   user_id: &str,
                                   acl_check: impl Fn() -> bool,
    ) -> PassResult<()> {
        if self.user_id == user_id || self.is_admin() || acl_check() {
            Ok(())
        } else {
            eprintln!("backtrace: {}", Backtrace::capture());
            Err(PassError::authorization(&format!(
                "user_id in context ({}) didn't match user_id ({}) in the request",
                &self.user_id, user_id
            )))
        }
    }

    pub(crate) fn to_user_key_params(&self, salt: &str) -> UserKeyParams {
        UserKeyParams::new(&self.user_id, salt, &self.pepper)
    }

    pub(crate) fn is_admin(&self) -> bool {
        !self.user_id.is_empty() && !self.username.is_empty() && self.roles.is_admin()
    }

    pub(crate) fn decrypted_user_private_key(
        &self,
        user_crypto_key: &CryptoKeyEntity,
    ) -> PassResult<String> {
        user_crypto_key.decrypted_private_key_with_symmetric_input(self, &self.secret_key)
    }

    #[allow(dead_code)]
    pub(crate) fn decrypted_user_symmetric_key(
        &self,
        user_crypto_key: &CryptoKeyEntity,
    ) -> PassResult<String> {
        let decrypted_private_key = self.decrypted_user_private_key(user_crypto_key)?;
        user_crypto_key.decrypted_symmetric_key_with_private_key(&decrypted_private_key)
    }
}

/// UserEntity represents actor who uses password manager.
#[derive(Debug, Clone, Eq, Queryable, Selectable, Identifiable, Insertable, AsChangeset)]
#[diesel(table_name = users)]
#[diesel(primary_key(user_id))]
pub struct UserEntity {
    // id of the user.
    pub user_id: String,
    // The version of the user in database.
    pub version: i64,
    // The username of user.
    pub username: String,
    // The roles of user.
    pub roles: i64,
    // The salt for encryption.
    pub salt: String,
    // The nonce for encryption.
    pub nonce: String,
    // The encrypted_value of account value in encrypted format.
    pub encrypted_value: String,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

impl UserEntity {
    pub fn new(user: &User, salt: &str, nonce: &str, encrypted_value: &str) -> Self {
        Self {
            user_id: user.user_id.clone(),
            version: 0,
            username: user.username.clone(),
            roles: user.roles.mask,
            salt: salt.into(),
            nonce: nonce.into(),
            encrypted_value: encrypted_value.into(),
            created_at: Utc::now().naive_utc(),
            updated_at: Utc::now().naive_utc(),
        }
    }

    // initialize user entity and crypto keys based on key context and user object.
    pub fn new_signup(ctx: &UserContext, user: &User) -> PassResult<(Self, CryptoKeyEntity)> {
        // Create salt for the new user
        let salt = hex::encode(crypto::generate_nonce());

        let (user_crypto_key, user_symmetric_key) = CryptoKeyEntity::new_with_input(
            ctx,
            &ctx.secret_key,
            &user.user_id,
            &user.user_id,
            "User",
            "", // no parent key
        )?;

        // Encrypt user json using the symmetric key
        let (nonce, encrypted_value) = encrypt_with(ctx, &salt, &ctx.pepper, &user_symmetric_key, user)?;

        Ok((
            UserEntity::new(user, &salt, &nonce, &encrypted_value),
            user_crypto_key,
        ))
    }

    // Convert user-entity to user
    pub fn to_user(
        &self,
        ctx: &UserContext,
        user_crypto_key: &CryptoKeyEntity,
    ) -> PassResult<User> {
        // Derive symmetric key
        let decrypted_private_ky =
            user_crypto_key.decrypted_private_key_with_symmetric_input(ctx, &ctx.secret_key)?;

        let decrypted_symmetric_key =
            user_crypto_key.decrypted_symmetric_key_with_private_key(&decrypted_private_ky)?;

        // Decrypt user with user symmetric secret key
        let decrypted_user_json = decrypt_with(
            ctx,
            self.salt.as_str(),
            &ctx.pepper,
            self.nonce.as_str(),
            &decrypted_symmetric_key,
            self.encrypted_value.as_str(),
        )?;

        let mut user: User = serde_json::from_str(&decrypted_user_json)?;
        user.version = self.version;
        user.roles = Roles::new(self.roles);
        user.created_at = Some(self.created_at);
        user.updated_at = Some(self.updated_at);
        Ok(user)
    }

    // Update user-entity from user
    pub fn update_from_user(
        &mut self,
        ctx: &UserContext,
        user: &User,
        user_crypto_key: &CryptoKeyEntity,
    ) -> PassResult<()> {
        let mut old_user = self.to_user(ctx, user_crypto_key)?;
        old_user.update(user); // only allow update of certain attributes

        self.version += 1;
        // Derive symmetric key using symmetric secret key that was created from the master-password.

        let decrypted_private_ky =
            user_crypto_key.decrypted_private_key_with_symmetric_input(ctx, &ctx.secret_key)?;

        let decrypted_symmetric_key =
            user_crypto_key.decrypted_symmetric_key_with_private_key(&decrypted_private_ky)?;

        // update old-users
        let (nonce, encrypted_value) =
            encrypt_with(ctx, &self.salt, &ctx.pepper, &decrypted_symmetric_key, &old_user)?;

        self.nonce = nonce;
        self.encrypted_value = encrypted_value;
        Ok(())
    }

    pub fn match_version(&self, version: i64) -> PassResult<()> {
        if self.version != version {
            return Err(PassError::database(
                format!(
                    "user version {} didn't match {} for {}",
                    version, &self.version, &self.user_id
                )
                    .as_str(),
                None,
                false,
            ));
        }
        Ok(())
    }
}

impl PartialEq for UserEntity {
    fn eq(&self, other: &Self) -> bool {
        self.user_id == other.user_id
    }
}

impl Hash for UserEntity {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.user_id.hash(hasher);
    }
}

/// LoginSessionEntity represents login session
#[derive(Debug, Clone, Queryable, Selectable, Identifiable, Insertable, AsChangeset)]
#[diesel(table_name = login_sessions)]
#[diesel(primary_key(login_session_id))]
pub struct LoginSessionEntity {
    // The session_id for login
    pub login_session_id: String,
    // The user_id for the user.
    pub user_id: String,
    // The source of the session.
    pub source: Option<String>,
    // The ip-address of the session.
    pub ip_address: Option<String>,
    pub created_at: NaiveDateTime,
    pub signed_out_at: Option<NaiveDateTime>,
}

impl LoginSessionEntity {
    pub fn new(login_session: &LoginSession) -> Self {
        Self {
            login_session_id: login_session.login_session_id.clone(),
            user_id: login_session.user_id.clone(),
            source: login_session.source.clone(),
            ip_address: login_session.ip_address.clone(),
            created_at: Utc::now().naive_utc(),
            signed_out_at: None,
        }
    }
    pub fn to_login_session(&self) -> LoginSession {
        LoginSession {
            login_session_id: self.login_session_id.clone(),
            user_id: self.user_id.clone(),
            source: self.source.clone(),
            ip_address: self.ip_address.clone(),
            created_at: Some(self.created_at),
            signed_out_at: self.signed_out_at,
        }
    }
}

/// CryptoKeyEntity defines encryption keys both asymmetric and symmetric.
#[derive(
Serialize, Deserialize, Debug, Clone, Eq, Queryable, Selectable, Identifiable, Insertable, AsChangeset, Associations,
)]
#[diesel(table_name = crypto_keys)]
#[diesel(primary_key(crypto_key_id))]
#[diesel(belongs_to(UserEntity, foreign_key = user_id))]
pub struct CryptoKeyEntity {
    // id of the key
    pub crypto_key_id: String,
    // id of the parent key -- empty means no parent -- need non-null due to comparison
    pub parent_crypto_key_id: String,
    // The user associated with crypto key.
    pub user_id: String,
    // The keyable_id that is associated using polymorphic association.
    pub keyable_id: String,
    // The keyable_type that is associated using polymorphic association.
    pub keyable_type: String,
    // The salt for encryption.
    pub salt: String,
    // The nonce for encryption.
    pub nonce: String,
    // The public_key for encryption.
    pub public_key: String,
    // The encrypted private key for encrypting value.
    pub encrypted_private_key: String,
    // The encrypted symmetric key for encrypting value.
    pub encrypted_symmetric_key: String,
    pub created_at: NaiveDateTime,
}

impl PartialEq for CryptoKeyEntity {
    fn eq(&self, other: &Self) -> bool {
        self.crypto_key_id == other.crypto_key_id
    }
}

impl Hash for CryptoKeyEntity {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.crypto_key_id.hash(hasher);
    }
}

impl CryptoKeyEntity {
    // Create crypto keys based on master secret key as input
    pub fn new_with_input(
        ctx: &UserContext,
        input: &str,
        user_id: &str,
        keyable_id: &str,
        keyable_type: &str,
        parent_id: &str,
    ) -> PassResult<(Self, String)> {
        // Create salt and pepper
        let salt = hex::encode(crypto::generate_nonce());

        // Create symmetric secret key based on input, salt and pepper using secured hashing algorithm
        let symmetric_key = hex::encode(crypto::compute_hash(
            &hex::decode(salt.clone())?,
            &ctx.pepper,
            input,
            ctx.hash_algorithm.clone(),
        )?);

        //
        // Generate a public and private keypair based on Elliptic Curve
        let (private_key, public_key) = crypto::generate_private_public_keys();

        // Encrypt symmetric secret-key using public key based on Elliptic Curve
        let encrypted_symmetric_key = crypto::ec_encrypt_hex(&public_key, &symmetric_key)?;

        // Encrypt private secret key with input
        let (nonce, encrypted_private_key) = encrypt_with(ctx, &salt, &ctx.pepper, input, &private_key)?;

        Ok((
            Self {
                crypto_key_id: Uuid::new_v4().to_string(),
                parent_crypto_key_id: parent_id.to_string(),
                user_id: user_id.into(),
                keyable_id: keyable_id.into(),
                keyable_type: keyable_type.into(),
                salt,
                nonce,
                public_key,
                encrypted_private_key,
                encrypted_symmetric_key,
                created_at: Utc::now().naive_utc(),
            },
            symmetric_key,
        ))
    }

    // Create crypto keys based on sharing crypto key
    pub fn clone_from_sharing(
        ctx: &UserContext,
        parent_private_key: &str,
        parent_public_key: &str,
        encrypted_crypto_key: &str,
    ) -> PassResult<Self> {
        let json_crypto_key = crypto::ec_decrypt_hex(parent_private_key, encrypted_crypto_key)?;
        let other_crypto_key: CryptoKeyEntity = serde_json::from_str(&json_crypto_key)?;

        // The other key stores decrypted private key so we will encrypt it with user's public key.
        let encrypted_private_key = crypto::ec_encrypt_hex(parent_public_key, &other_crypto_key.encrypted_private_key)?;

        Ok(
            Self {
                crypto_key_id: Uuid::new_v4().to_string(),
                parent_crypto_key_id: other_crypto_key.parent_crypto_key_id.clone(),
                user_id: ctx.user_id.clone(),
                keyable_id: other_crypto_key.keyable_id.clone(),
                keyable_type: other_crypto_key.keyable_type.clone(),
                salt: other_crypto_key.salt.clone(),
                nonce: other_crypto_key.nonce.clone(),
                public_key: other_crypto_key.public_key.clone(),
                encrypted_private_key,
                encrypted_symmetric_key: other_crypto_key.encrypted_symmetric_key.clone(),
                created_at: Utc::now().naive_utc(),
            }
        )
    }

    // Create crypto keys based on parent's asymmetric public and private keys
    pub fn new_with_parent(
        ctx: &UserContext,
        parent_private_key: &str,
        parent_public_key: &str,
        keyable_id: &str,
        keyable_type: &str,
        parent_id: &str,
    ) -> PassResult<(Self, String)> {
        // Create salt and pepper
        let salt = hex::encode(crypto::generate_nonce());

        // Create symmetric secret key based on parent-private-key, salt and pepper using secured hashing algorithm
        let symmetric_key = hex::encode(crypto::compute_hash(
            &hex::decode(salt.clone())?,
            &ctx.pepper,
            parent_private_key,
            ctx.hash_algorithm.clone(),
        )?);

        //
        // Generate a public and private keypair based on Elliptic Curve
        let (private_key, public_key) = crypto::generate_private_public_keys();

        // Encrypt symmetric secret-key using self's public key based on Elliptic Curve
        let encrypted_symmetric_key = crypto::ec_encrypt_hex(&public_key, &symmetric_key)?;

        // Encrypt private key of based on parent's public using Elliptic Curve.
        let encrypted_private_key = crypto::ec_encrypt_hex(parent_public_key, &private_key)?;

        Ok((
            Self {
                crypto_key_id: Uuid::new_v4().to_string(),
                parent_crypto_key_id: parent_id.to_string(),
                user_id: ctx.user_id.clone(),
                keyable_id: keyable_id.into(),
                keyable_type: keyable_type.into(),
                salt,
                nonce: "".into(),
                public_key,
                encrypted_private_key,
                encrypted_symmetric_key,
                created_at: Utc::now().naive_utc(),
            },
            symmetric_key,
        ))
    }
    pub fn encrypted_clone_for_sharing(&self,
                                       ctx: &UserContext,
                                       user_crypto_key: &CryptoKeyEntity,
                                       target_user_id: &str,
                                       target_user_crypto_key: &CryptoKeyEntity,
                                       parent_id: &str,
    ) -> PassResult<String> {
        let decrypted_private_key = self
            .decrypted_private_key_with_parent_private_key(
                &ctx.decrypted_user_private_key(user_crypto_key)?,
            )?;
        let shared_crypto_key = CryptoKeyEntity {
            crypto_key_id: Uuid::new_v4().to_string(),
            parent_crypto_key_id: parent_id.to_string(),
            user_id: target_user_id.into(),
            keyable_id: self.keyable_id.clone(),
            keyable_type: self.keyable_type.clone(),
            salt: self.salt.clone(),
            nonce: self.nonce.clone(),
            public_key: self.public_key.clone(),
            encrypted_private_key: decrypted_private_key, // decrypted
            encrypted_symmetric_key: self.encrypted_symmetric_key.clone(),
            created_at: Utc::now().naive_utc(),
        };
        let json_shared_crypto_key = serde_json::to_string(&shared_crypto_key)?;

        // encrypt new_crypto_key key with target user's public key
        crypto::ec_encrypt_hex(&target_user_crypto_key.public_key, &json_shared_crypto_key)
    }

    pub fn decrypted_private_key_with_symmetric_input(
        &self,
        ctx: &UserContext,
        input: &str,
    ) -> PassResult<String> {
        // Decrypt user private key based on input symmetric key
        decrypt_with(
            ctx,
            self.salt.as_str(),
            &ctx.pepper,
            self.nonce.as_str(),
            input,
            self.encrypted_private_key.as_str(),
        )
    }

    pub fn decrypted_private_key_with_parent_private_key(
        &self,
        parent_private_key: &str,
    ) -> PassResult<String> {
        // Decrypt private key using parent private key
        crypto::ec_decrypt_hex(parent_private_key, &self.encrypted_private_key)
    }

    pub fn decrypted_symmetric_key_with_parent_private_key(
        &self,
        parent_private_key: &str,
    ) -> PassResult<String> {
        let private_key = self.decrypted_private_key_with_parent_private_key(parent_private_key)?;
        self.decrypted_symmetric_key_with_private_key(&private_key)
    }

    pub fn decrypted_symmetric_key_with_private_key(
        &self,
        decrypted_private_key: &str,
    ) -> PassResult<String> {
        crypto::ec_decrypt_hex(decrypted_private_key, &self.encrypted_symmetric_key)
    }
}

/// VaultEntity represents a folder for storing passwords.
#[derive(Debug, Clone, Eq, Queryable, Selectable, Identifiable, Insertable, AsChangeset)]
#[diesel(table_name = vaults)]
#[diesel(primary_key(vault_id))]
#[diesel(belongs_to(UserEntity, foreign_key = user_id))]
pub struct VaultEntity {
    // id of the vault.
    pub vault_id: String,
    // The version of the vault in database.
    pub version: i64,
    // owner user-id of the vault.
    pub owner_user_id: String,
    // The name of vault.
    pub title: String,
    // The kind of vault.
    pub kind: String,
    // The salt for encryption.
    pub salt: String,
    // The nonce for encryption.
    pub nonce: String,
    // The encrypted_value of account value in encrypted format.
    pub encrypted_value: String,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

impl VaultEntity {
    pub fn new(vault: &Vault, salt: &str, nonce: &str, encrypted_value: &str) -> Self {
        VaultEntity {
            vault_id: vault.vault_id.clone(),
            version: vault.version,
            owner_user_id: vault.owner_user_id.clone(),
            title: vault.title.clone(),
            kind: vault.kind.to_string(),
            salt: salt.into(),
            nonce: nonce.into(),
            encrypted_value: encrypted_value.into(),
            created_at: Utc::now().naive_utc(),
            updated_at: Utc::now().naive_utc(),
        }
    }

    // Create new vault-entity from vault adn user-context
    pub(crate) fn new_from_context_vault(
        ctx: &UserContext,
        user_crypto_key: &CryptoKeyEntity,
        vault: &Vault,
    ) -> PassResult<(Self, CryptoKeyEntity)> {
        let salt = hex::encode(crypto::generate_nonce());

        let (crypto_key, decrypted_symmetric_key) = CryptoKeyEntity::new_with_parent(
            ctx,
            &ctx.decrypted_user_private_key(user_crypto_key)?,
            &user_crypto_key.public_key,
            &vault.vault_id,
            "Vault",
            &user_crypto_key.crypto_key_id, // parent id
        )?;

        // 3. Encrypt json of vault using the vault secret key and without pepper key so that we can share it
        let (nonce, enc_value) = encrypt_with(ctx, &salt, "", &decrypted_symmetric_key, vault)?;

        // no key nonce for vault as we use Asymmetric encryption
        Ok((
            VaultEntity::new(vault, &salt, &nonce, &enc_value),
            crypto_key,
        ))
    }

    // Update vault-entity from vault
    pub(crate) fn update_from_context_vault(
        &mut self,
        ctx: &UserContext,
        user_crypto_key: &CryptoKeyEntity,
        vault: &Vault,
        vault_crypto_key: &CryptoKeyEntity,
    ) -> PassResult<()> {
        self.title = vault.title.clone();
        self.version += 1;

        // Decrypt vault symmetric key based on salt, user's private key and master pepper
        let decrypted_symmetric_key = vault_crypto_key
            .decrypted_symmetric_key_with_parent_private_key(
                &ctx.decrypted_user_private_key(user_crypto_key)?,
            )?;

        let vault = if vault.entries.is_none() {
            // we will load entries from old vault
            let vault_json = decrypt_with(
                ctx,
                &self.salt,
                "", // no pepper so that we can share it
                &self.nonce,
                &decrypted_symmetric_key,
                &self.encrypted_value,
            )?;
            let old_vault: Vault = serde_json::from_str(&vault_json)?;
            let mut vault = vault.clone();
            vault.entries = old_vault.entries;
            vault
        } else {
            vault.clone()
        };

        // Using empty pepper so that we can share it with other users
        let (nonce, encrypted_value) =
            encrypt_with(ctx, &self.salt, "", &decrypted_symmetric_key, &vault)?;
        self.nonce = nonce;
        self.encrypted_value = encrypted_value;
        self.kind = vault.kind.to_string();
        Ok(())
    }

    // Convert vault-entity to vault
    pub(crate) fn to_vault(
        &self,
        ctx: &UserContext,
        user_crypto_key: &CryptoKeyEntity,
        vault_crypto_key: &CryptoKeyEntity,
    ) -> PassResult<Vault> {
        // Decrypt vault symmetric key based on salt, user's private key and master pepper
        let decrypted_symmetric_key = vault_crypto_key
            .decrypted_symmetric_key_with_parent_private_key(
                &ctx.decrypted_user_private_key(user_crypto_key)?,
            )?;

        let vault_json = decrypt_with(
            ctx,
            &self.salt,
            "", // no pepper so that we can share it
            &self.nonce,
            &decrypted_symmetric_key,
            &self.encrypted_value,
        )?;

        let mut vault: Vault = serde_json::from_str(&vault_json)?;
        vault.version = self.version;
        vault.title = self.title.clone();
        vault.kind = VaultKind::from(self.kind.as_str());
        vault.created_at = Some(self.created_at);
        vault.updated_at = Some(self.updated_at);
        Ok(vault)
    }

    pub fn match_version(&self, version: i64) -> PassResult<()> {
        if self.version != version {
            return Err(PassError::database(
                format!(
                    "vault version {} didn't match {} for {}",
                    version, &self.version, &self.vault_id
                )
                    .as_str(),
                None,
                false,
            ));
        }
        Ok(())
    }
}

impl PartialEq for VaultEntity {
    fn eq(&self, other: &Self) -> bool {
        self.vault_id == other.vault_id
    }
}

impl Hash for VaultEntity {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.vault_id.hash(hasher);
    }
}

/// UserVaultEntity represents a many-to-many association between user and vault.
#[derive(Debug, Clone, Queryable, Selectable, Identifiable, Insertable, AsChangeset)]
#[diesel(table_name = users_vaults)]
#[diesel(primary_key(user_vault_id))]
#[diesel(belongs_to(UserEntity, foreign_key = user_id))]
#[diesel(belongs_to(VaultEntity, foreign_key = vault_id))]
pub struct UserVaultEntity {
    // id of the user-vault.
    pub user_vault_id: String,
    // id of the user.
    pub user_id: String,
    // id of the vault.
    pub vault_id: String,
    // created at
    pub created_at: NaiveDateTime,
}

impl UserVaultEntity {
    pub fn new(user_id: &str, vault_id: &str) -> Self {
        Self {
            user_vault_id: Uuid::new_v4().to_string(),
            user_id: user_id.into(),
            vault_id: vault_id.into(),
            created_at: Utc::now().naive_utc(),
        }
    }
}

/// AccountEntity defines abstraction for user account that can be persistable
#[derive(
Debug, Clone, Eq, Queryable, Selectable, Identifiable, Insertable, AsChangeset, Associations,
)]
#[diesel(table_name = accounts)]
#[diesel(primary_key(account_id))]
#[diesel(belongs_to(VaultEntity, foreign_key = vault_id))]
pub struct AccountEntity {
    // id of the account.
    pub account_id: String,
    // The version of the account in database.
    pub version: i64,
    // The vault_id associated with account the vault.
    pub vault_id: String,
    // The archived_version of the account in database.
    pub archived_version: Option<i64>,
    // The salt for hashing.
    pub salt: String,
    // The key-nonce for encryption.
    pub nonce: String,
    // The encrypted_value of account value in encrypted format.
    pub encrypted_value: String,
    // The hash of primary attributes
    pub value_hash: String,
    pub credentials_updated_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

impl PartialEq for AccountEntity {
    fn eq(&self, other: &Self) -> bool {
        self.account_id == other.account_id
    }
}

impl Hash for AccountEntity {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.account_id.hash(hasher);
    }
}

impl AccountEntity {
    pub fn new(account: &Account, salt: &str, nonce: &str, encrypted_value: &str) -> Self {
        AccountEntity {
            account_id: account.details.account_id.clone(),
            version: account.details.version,
            vault_id: account.vault_id.clone(),
            archived_version: account.archived_version,
            salt: salt.into(),
            nonce: nonce.into(),
            encrypted_value: encrypted_value.into(),
            value_hash: account.value_hash.clone(),
            credentials_updated_at: Utc::now().naive_utc(),
            created_at: Utc::now().naive_utc(),
            updated_at: Utc::now().naive_utc(),
        }
    }

    pub fn to_archived(&self, account_crypto_key: &CryptoKeyEntity) -> ArchivedAccountEntity {
        ArchivedAccountEntity::new(self, &account_crypto_key.crypto_key_id)
    }

    // Build account-entity from account
    pub fn from_context_vault_account(
        ctx: &UserContext,
        user_crypto_key: &CryptoKeyEntity,
        vault_crypto_key: &CryptoKeyEntity,
        account: &Account,
    ) -> PassResult<(Self, CryptoKeyEntity)> {
        let salt = hex::encode(crypto::generate_nonce());

        // Note: Vault's private key is encrypted using User's public key so we must decrypt it using
        // User's private key.
        let vault_decrypted_private_key = vault_crypto_key
            .decrypted_private_key_with_parent_private_key(
                &ctx.decrypted_user_private_key(user_crypto_key)?,
            )?;

        // Create crypto key for account based on vault's private and public key
        let (crypto_key, vault_symmetric_key) = CryptoKeyEntity::new_with_parent(
            ctx,
            &vault_decrypted_private_key,
            &vault_crypto_key.public_key,
            &account.details.account_id,
            "Account",
            &vault_crypto_key.crypto_key_id, // vault crypto key as parent id
        )?;

        // Encrypt json of account using the symmetric key and without pepper key so that we can share it
        let (nonce, encrypted_value) = encrypt_with(ctx, &salt, "", &vault_symmetric_key, account)?;

        Ok((
            AccountEntity::new(account, &salt, &nonce, &encrypted_value),
            crypto_key,
        ))
    }

    pub(crate) fn update_from_context_vault_account(
        &mut self,
        ctx: &UserContext,
        user_crypto_key: &CryptoKeyEntity,
        vault_crypto_key: &CryptoKeyEntity,
        account: &Account,
        account_crypto_key: &CryptoKeyEntity,
    ) -> PassResult<()> {
        self.version += 1;

        let decrypted_symmetric_key = Self::decrypted_account_symmetric_key(
            ctx,
            user_crypto_key,
            vault_crypto_key,
            account_crypto_key,
        )?;

        let mut account = account.clone();
        account.details.version = self.version;

        // Encrypting without pepper key so that we can share it
        let (nonce, encrypted_value) =
            encrypt_with(ctx, &self.salt, "", &decrypted_symmetric_key, &account)?;
        self.value_hash = account.value_hash.clone();
        self.nonce = nonce;
        self.encrypted_value = encrypted_value;

        Ok(())
    }

    pub(crate) fn to_account(
        &self,
        ctx: &UserContext,
        user_crypto_key: &CryptoKeyEntity,
        vault_crypto_key: &CryptoKeyEntity,
        account_crypto_key: &CryptoKeyEntity,
    ) -> PassResult<Account> {
        let decrypted_symmetric_key = Self::decrypted_account_symmetric_key(
            ctx,
            user_crypto_key,
            vault_crypto_key,
            account_crypto_key,
        )?;

        let account_json = decrypt_with(
            ctx,
            &self.salt,
            "", // no pepper so that we can share it
            &self.nonce,
            &decrypted_symmetric_key,
            &self.encrypted_value,
        )?;

        let mut account: Account = serde_json::from_str(&account_json)?;
        account.value_hash = self.value_hash.clone();
        account.details.version = self.version;
        account.created_at = Some(self.created_at);
        account.updated_at = Some(self.updated_at);
        Ok(account)
    }

    fn decrypted_account_symmetric_key(
        ctx: &UserContext,
        user_crypto_key: &CryptoKeyEntity,
        vault_crypto_key: &CryptoKeyEntity,
        account_crypto_key: &CryptoKeyEntity,
    ) -> PassResult<String> {
        // Decrypt vault's private key using User's private key,
        let decrypted_vault_private_key = vault_crypto_key
            .decrypted_private_key_with_parent_private_key(
                &ctx.decrypted_user_private_key(user_crypto_key)?,
            )?;

        // Then use Vault's private key to decrypt account's symmetric key
        let decrypted_symmetric_key = account_crypto_key
            .decrypted_symmetric_key_with_parent_private_key(&decrypted_vault_private_key)?;
        Ok(decrypted_symmetric_key)
    }

    pub fn match_version(&self, version: i64) -> PassResult<()> {
        if self.version != version {
            return Err(PassError::database(
                format!(
                    "account version {} didn't match {} for {}",
                    version, &self.version, &self.account_id
                )
                    .as_str(),
                None,
                false,
            ));
        }
        Ok(())
    }
}

/// ArchivedAccountEntity defines abstraction for an old user account that has been archived.
#[derive(
Debug, Clone, Eq, Queryable, Selectable, Identifiable, Insertable, AsChangeset, Associations,
)]
#[diesel(table_name = archived_accounts)]
#[diesel(primary_key(account_id, version))]
#[diesel(belongs_to(VaultEntity, foreign_key = vault_id))]
pub struct ArchivedAccountEntity {
    // id of the account.
    pub account_id: String,
    // The version of the account in database.
    pub version: i64,
    // The vault_id associated with account the vault.
    pub vault_id: String,
    // The crypto_key_id for encryption.
    pub crypto_key_id: String,
    // The salt for hashing.
    pub salt: String,
    // The nonce for encryption.
    pub nonce: String,
    // The encrypted_value of account value in encrypted format.
    pub encrypted_value: String,
    // The hash of primary attributes
    pub value_hash: String,
    pub created_at: NaiveDateTime,
}

impl PartialEq for ArchivedAccountEntity {
    fn eq(&self, other: &Self) -> bool {
        self.account_id == other.account_id
    }
}

impl Hash for ArchivedAccountEntity {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.account_id.hash(hasher);
    }
}

impl ArchivedAccountEntity {
    pub fn new(account: &AccountEntity, crypto_key_id: &str) -> Self {
        ArchivedAccountEntity {
            account_id: account.account_id.clone(),
            version: account.version,
            vault_id: account.vault_id.clone(),
            crypto_key_id: crypto_key_id.into(),
            salt: account.salt.clone(),
            nonce: account.nonce.clone(),
            encrypted_value: account.encrypted_value.clone(),
            value_hash: account.value_hash.clone(),
            created_at: Utc::now().naive_utc(),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn to_account(
        &self,
        ctx: &UserContext,
        user_crypto_key: &CryptoKeyEntity,
        vault_crypto_key: &CryptoKeyEntity,
        account_crypto_key: &CryptoKeyEntity,
    ) -> PassResult<Account> {
        let decrypted_symmetric_key = AccountEntity::decrypted_account_symmetric_key(
            ctx,
            user_crypto_key,
            vault_crypto_key,
            account_crypto_key,
        )?;

        let account_json = decrypt_with(
            ctx,
            &self.salt,
            "", // no pepper so that we can share it
            &self.nonce,
            &decrypted_symmetric_key,
            &self.encrypted_value,
        )?;

        let mut account: Account = serde_json::from_str(&account_json)?;
        account.value_hash = self.value_hash.clone();
        account.details.version = self.version;
        account.created_at = Some(self.created_at);
        account.updated_at = Some(self.created_at);
        Ok(account)
    }
}

/// LookupEntity represents lookup entries such as categories and tags
#[derive(Debug, Clone, Eq, Queryable, Selectable, Identifiable, Insertable, AsChangeset)]
#[diesel(table_name = lookups)]
#[diesel(primary_key(lookup_id))]
#[diesel(belongs_to(UserEntity, foreign_key = user_id))]
pub struct LookupEntity {
    // id of the lookup.
    pub lookup_id: String,
    // The version of the lookup in database.
    pub version: i64,
    // id of the user.
    pub user_id: String,
    // The kind of lookup.
    pub kind: String,
    // The name of lookup.
    pub name: String,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

impl LookupEntity {
    pub fn new(lookup: &Lookup) -> Self {
        LookupEntity {
            lookup_id: lookup.lookup_id.clone(),
            version: 0,
            user_id: lookup.user_id.clone(),
            kind: lookup.kind.to_string(),
            name: lookup.name.clone(),
            created_at: Utc::now().naive_utc(),
            updated_at: Utc::now().naive_utc(),
        }
    }

    pub(crate) fn to_lookup(&self) -> Lookup {
        let mut lookup = Lookup::new(
            &self.user_id,
            LookupKind::from(self.kind.as_str()),
            &self.name,
        );
        lookup.lookup_id = self.lookup_id.clone();
        lookup
    }

    pub fn match_version(&self, version: i64) -> PassResult<()> {
        if self.version != version {
            return Err(PassError::database(
                format!(
                    "lookup version {} didn't match {} for {}",
                    version, &self.version, &self.lookup_id
                )
                    .as_str(),
                None,
                false,
            ));
        }
        Ok(())
    }
}

impl PartialEq for LookupEntity {
    fn eq(&self, other: &Self) -> bool {
        self.lookup_id == other.lookup_id
    }
}

impl Hash for LookupEntity {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.lookup_id.hash(hasher);
    }
}

/// SettingEntity represents configuration settings.
#[derive(Debug, Clone, Eq, Queryable, Selectable, Identifiable, Insertable, AsChangeset)]
#[diesel(table_name = settings)]
#[diesel(primary_key(setting_id))]
#[diesel(belongs_to(UserEntity, foreign_key = user_id))]
pub struct SettingEntity {
    // id of the setting.
    pub setting_id: String,
    // The version of the setting in database.
    pub version: i64,
    // The user_id of setting.
    pub user_id: String,
    // The kind of setting.
    pub kind: String,
    // The name of setting.
    pub name: String,
    // The value of setting.
    pub value: String,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

impl SettingEntity {
    pub fn new(setting: &Setting) -> Self {
        SettingEntity {
            setting_id: setting.setting_id.clone(),
            version: 0,
            user_id: setting.user_id.clone(),
            kind: setting.kind.to_string(),
            name: setting.name.clone(),
            value: setting.value.clone(),
            created_at: Utc::now().naive_utc(),
            updated_at: Utc::now().naive_utc(),
        }
    }

    pub(crate) fn to_setting(&self) -> Setting {
        let mut setting = Setting::new(
            &self.user_id,
            SettingKind::from(self.kind.as_str()),
            &self.name,
            &self.value,
        );
        setting.setting_id = self.setting_id.clone();
        setting
    }

    pub fn match_version(&self, version: i64) -> PassResult<()> {
        if self.version != version {
            return Err(PassError::database(
                format!(
                    "setting version {} didn't match {} for {}",
                    version, &self.version, &self.setting_id
                )
                    .as_str(),
                None,
                false,
            ));
        }
        Ok(())
    }
}

impl PartialEq for SettingEntity {
    fn eq(&self, other: &Self) -> bool {
        self.setting_id == other.setting_id
    }
}

impl Hash for SettingEntity {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.setting_id.hash(hasher);
    }
}

/// MessageEntity represents a message, notification or alter.
#[derive(Debug, Clone, Eq, Queryable, Selectable, Identifiable, Insertable, AsChangeset)]
#[diesel(table_name = messages)]
#[diesel(primary_key(message_id))]
#[diesel(belongs_to(UserEntity, foreign_key = user_id))]
pub struct MessageEntity {
    // id of the message.
    pub message_id: String,
    // user_id of the message.
    pub user_id: String,
    // specversion of the message.
    pub specversion: String,
    // The source of message.
    pub source: String,
    // The kind of message.
    pub kind: String,
    // The flags of message.
    pub flags: i64,
    // The salt of encryption of message.
    pub salt: String,
    // The nonce of encryption of message.
    pub nonce: String,
    // The encrypted value of message.
    pub encrypted_value: String,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

impl MessageEntity {
    pub fn new(message: &Message, salt: &str, nonce: &str, encrypted_value: &str) -> Self {
        MessageEntity {
            message_id: message.message_id.clone(),
            user_id: message.user_id.clone(),
            specversion: message.specversion.clone(),
            source: message.source.clone(),
            kind: message.kind.to_string(),
            flags: message.flags,
            salt: salt.into(),
            nonce: nonce.into(),
            encrypted_value: encrypted_value.into(),
            created_at: Utc::now().naive_utc(),
            updated_at: Utc::now().naive_utc(),
        }
    }
    pub(crate) fn new_from_context_message(
        _ctx: &UserContext,
        user_crypto_key: &CryptoKeyEntity,
        message: &Message,
    ) -> PassResult<Self> {
        let json_message = serde_json::to_string(message)?;
        // Encrypt json of message using the user's public key
        // Note: We are not using symmetric encryption so that anyone can send message but only user can read it otherwise
        // Send will need to know the symmetric key.
        let encrypted_value = crypto::ec_encrypt_hex(&user_crypto_key.public_key, &json_message)?;

        Ok(MessageEntity::new(message, "", "", &encrypted_value))
    }

    pub(crate) fn to_message(
        &self,
        ctx: &UserContext,
        user_crypto_key: &CryptoKeyEntity,
    ) -> PassResult<Message> {
        // Decrypt json of message using the user's private key
        // Note: We are not using symmetric encryption so that anyone can send message but only user can read it otherwise
        // Send will need to know the symmetric key.
        let decrypted_private_key = ctx.decrypted_user_private_key(user_crypto_key)?;
        let decrypted_json_message = crypto::ec_decrypt_hex(&decrypted_private_key, &self.encrypted_value)?;
        let mut message: Message = serde_json::from_str(&decrypted_json_message)?;
        message.flags = self.flags;
        message.created_at = Some(self.created_at);
        message.updated_at = Some(self.updated_at);
        Ok(message)
    }
}

impl PartialEq for MessageEntity {
    fn eq(&self, other: &Self) -> bool {
        self.message_id == other.message_id
    }
}

impl Hash for MessageEntity {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.message_id.hash(hasher);
    }
}

#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
pub enum AuditKind {
    Signup,
    Signin,
    Signout,
    UserUpdated,
    UserDeleted,
    CreatedVault,
    UpdatedVault,
    DeletedVault,
    SharedVault,
    SharedCreatedVault,
    CreatedAccount,
    UpdatedAccount,
    UpdatedPassword,
    DeletedAccount,
    SharedAccount,
    PasswordAnalysis,
    Unknown,
}

impl Display for AuditKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AuditKind::Signup => { write!(f, "Signup") }
            AuditKind::Signin => { write!(f, "Signin") }
            AuditKind::Signout => { write!(f, "Signout") }
            AuditKind::UserUpdated => { write!(f, "UserUpdated") }
            AuditKind::UserDeleted => { write!(f, "UserDeleted") }
            AuditKind::CreatedVault => { write!(f, "CreatedVault") }
            AuditKind::UpdatedVault => { write!(f, "UpdatedVault") }
            AuditKind::DeletedVault => { write!(f, "DeletedVault") }
            AuditKind::SharedVault => { write!(f, "SharedVault") }
            AuditKind::SharedCreatedVault => { write!(f, "SharedCreatedVault") }
            AuditKind::CreatedAccount => { write!(f, "CreatedAccount") }
            AuditKind::UpdatedAccount => { write!(f, "UpdatedAccount") }
            AuditKind::UpdatedPassword => { write!(f, "UpdatedPassword") }
            AuditKind::DeletedAccount => { write!(f, "DeletedAccount") }
            AuditKind::SharedAccount => { write!(f, "SharedAccount") }
            AuditKind::PasswordAnalysis => { write!(f, "PasswordAnalysis") }
            AuditKind::Unknown => { write!(f, "Unknown") }
        }
    }
}

impl From<&str> for AuditKind {
    fn from(s: &str) -> AuditKind {
        match s {
            "Signup" => AuditKind::Signup,
            "Signin" => AuditKind::Signin,
            "Signout" => AuditKind::Signout,
            "UserUpdated" => AuditKind::UserUpdated,
            "UserDeleted" => AuditKind::UserDeleted,
            "CreatedVault" => AuditKind::CreatedVault,
            "UpdatedVault" => AuditKind::UpdatedVault,
            "DeletedVault" => AuditKind::DeletedVault,
            "SharedVault" => AuditKind::SharedVault,
            "SharedCreatedVault" => AuditKind::SharedCreatedVault,
            "CreatedAccount" => AuditKind::CreatedAccount,
            "UpdatedAccount" => AuditKind::UpdatedAccount,
            "UpdatedPassword" => AuditKind::UpdatedPassword,
            "DeletedAccount" => AuditKind::DeletedAccount,
            "SharedAccount" => AuditKind::SharedAccount,
            "PasswordAnalysis" => AuditKind::PasswordAnalysis,
            _ => AuditKind::Unknown,
        }
    }
}

impl PartialEq for AuditKind {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
    }
}

/// AuditEntity represents an audit record
#[derive(Debug, Clone, Queryable, Selectable, Identifiable, Insertable, AsChangeset)]
#[diesel(table_name = audit_records)]
#[diesel(primary_key(audit_id))]
#[diesel(belongs_to(UserEntity, foreign_key = user_id))]
pub struct AuditEntity {
    // id of the audit.
    pub audit_id: String,
    // user_id of the audit record.
    pub user_id: String,
    // kind of audit record.
    pub kind: String,
    // The ip-address of audit record.
    pub ip_address: Option<String>,
    // The context parameters.
    pub context: String,
    // The message of audit record.
    pub message: String,
    pub created_at: NaiveDateTime,
}

impl AuditEntity {
    pub fn new(ctx: &UserContext, kind: AuditKind, context: &str, message: &str) -> Self {
        Self {
            audit_id: Uuid::new_v4().to_string(),
            user_id: ctx.user_id.clone(),
            kind: kind.to_string(),
            ip_address: ctx.attributes.get(CONTEXT_IP_ADDRESS).cloned(),
            context: context.into(),
            message: message.to_string(),
            created_at: Utc::now().naive_utc(),
        }
    }

    pub fn to_log(&self) -> AuditLog {
        AuditLog {
            audit_id: self.audit_id.clone(),
            user_id: self.user_id.clone(),
            kind: AuditKind::from(self.kind.as_str()),
            ip_address: self.ip_address.clone(),
            context: self.context.clone(),
            message: self.message.clone(),
            created_at: self.created_at,
        }
    }
}

/// ACLEntity represents an access control list
#[derive(Debug, Clone, Eq, Queryable, Selectable, Identifiable, Insertable, AsChangeset)]
#[diesel(table_name = acls)]
#[diesel(primary_key(acl_id))]
#[diesel(belongs_to(UserEntity, foreign_key = user_id))]
pub struct ACLEntity {
    // id of the acl .
    pub acl_id: String,
    // version of the acl
    pub version: i64,
    // user_id of the ACL record.
    pub acl_user_id: String,
    // resource_type of ACL.
    pub resource_type: String,
    // resource_id of ACL.
    pub resource_id: String,
    // permissions mask
    pub permissions: i64,
    // The scope parameters.
    pub scope: String,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

pub const READ_PERMISSION: i64 = 2;
pub const WRITE_PERMISSION: i64 = 4;

impl ACLEntity {
    pub fn for_crypto_key(user_id: &str, resource_id: &str) -> Self {
        let mut acl = Self::new(user_id, "CryptoKeyEntity", resource_id);
        acl.permissions = READ_PERMISSION;
        acl
    }

    pub fn for_vault(user_id: &str, resource_id: &str, read_only: bool) -> Self {
        let mut acl = Self::new(user_id, "Vault", resource_id);
        acl.permissions = if read_only { READ_PERMISSION } else { WRITE_PERMISSION };
        acl
    }

    pub fn new(user_id: &str, resource_type: &str, resource_id: &str) -> Self {
        Self {
            acl_id: Uuid::new_v4().to_string(),
            version: 0,
            acl_user_id: user_id.to_string(),
            resource_type: resource_type.to_string(),
            resource_id: resource_id.to_string(),
            permissions: 0,
            scope: "".to_string(),
            created_at: Utc::now().naive_utc(),
            updated_at: Utc::now().naive_utc(),
        }
    }
}

impl PartialEq for ACLEntity {
    fn eq(&self, other: &Self) -> bool {
        self.acl_id == other.acl_id
    }
}

impl Hash for ACLEntity {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.acl_id.hash(hasher);
    }
}


// Encrypt any object using the salt, secret key and pepper key
fn encrypt_with<T>(
    ctx: &UserContext,
    salt: &str,
    pepper: &str,
    secret_key: &str,
    value: &T,
) -> PassResult<(String, String)>
    where
        T: ?Sized + Serialize,
{
    let plain_json = serde_json::to_string(value)?;
    let enc_val_resp = crypto::encrypt(EncryptRequest::from_string(
        salt,
        pepper,
        secret_key,
        ctx.hash_algorithm.clone(),
        ctx.crypto_algorithm.clone(),
        &plain_json,
        EncodingScheme::Base64,
    ))?;
    Ok((enc_val_resp.nonce.clone(), enc_val_resp.encoded_payload()?))
}

// Decrypt ciphertext using the salt, nonce, secret key and pepper key
fn decrypt_with(
    ctx: &UserContext,
    salt: &str,
    pepper: &str,
    nonce: &str,
    secret_key: &str,
    ciphertext: &str,
) -> PassResult<String> {
    let dec_res = crypto::decrypt(DecryptRequest::from_string(
        salt,
        pepper,
        secret_key,
        ctx.hash_algorithm.clone(),
        ctx.crypto_algorithm.clone(),
        nonce,
        ciphertext,
        EncodingScheme::Base64,
    )?)?;

    // serializing strings adds quotes so removing them here.
    let plain_str = dec_res.payload_string()?;
    if plain_str.starts_with('\"') && plain_str.ends_with('\"') {
        Ok(plain_str[1..plain_str.len() - 1].to_string())
    } else {
        dec_res.payload_string()
    }
}


#[cfg(test)]
mod tests {
    use crate::crypto;
    use crate::dao::models::{
        AccountEntity, CryptoKeyEntity, LookupEntity, MessageEntity, SettingEntity, UserContext,
        UserEntity, UserVaultEntity, VaultEntity,
    };
    use crate::domain::models::{Account, AccountKind, Lookup, LookupKind, Message, MessageKind, Setting, SettingKind, User, Vault, VaultKind};
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use uuid::Uuid;

    #[test]
    fn test_should_create_user() {
        let user = User::new("user1", None, None);
        let user_entity = UserEntity::new(&user, "salt", "knonce", "val");
        assert_eq!("user1", user_entity.username);
        assert_ne!("", user_entity.user_id);
        assert_eq!("salt", user_entity.salt);
        assert_eq!("knonce", user_entity.nonce);
        assert_eq!("val", user_entity.encrypted_value);
        assert_eq!(0, user_entity.version);
        assert!(user_entity.created_at.timestamp() > 0);
        assert!(user_entity.updated_at.timestamp() > 0);
    }

    #[test]
    fn test_should_equal_user() {
        let user1 = User::new("user1", None, None);
        let user2 = User::new("user1", None, None);
        let user_entity1 = UserEntity::new(&user1, "salt", "nonce", "val");
        let user_entity2 = UserEntity::new(&user2, "salt", "nonce", "val");
        assert_ne!(user_entity1, user_entity2);
        let mut hasher = DefaultHasher::new();
        user_entity1.hash(&mut hasher);
        assert_ne!("", format!("{:x}!", hasher.finish()));
    }

    #[test]
    fn test_should_create_crypto_keys() {
        let user1 = User::new("user1", None, None);
        let user2 = User::new("user1", None, None);
        let user_entity1 = UserEntity::new(&user1, "salt", "nonce", "val");
        let user_entity2 = UserEntity::new(&user2, "salt", "nonce", "val");
        assert_ne!(user_entity1, user_entity2);
        let mut hasher = DefaultHasher::new();
        user_entity1.hash(&mut hasher);
        assert_ne!("", format!("{:x}!", hasher.finish()));
    }

    #[test]
    fn test_should_create_vault() {
        let vault = Vault::new(Uuid::new_v4().to_string().as_str(), "title", VaultKind::Logins);
        let vault_entity = VaultEntity::new(&vault, "salt", "knonce", "enc-value");
        assert_eq!("title", vault_entity.title);
        assert_ne!("", vault_entity.vault_id);
        assert_eq!("salt", vault_entity.salt);
        assert_eq!("knonce", vault_entity.nonce);
        assert_eq!("enc-value", vault_entity.encrypted_value);
        assert_eq!(0, vault_entity.version);
        assert!(vault_entity.created_at.timestamp() > 0);
        assert!(vault_entity.updated_at.timestamp() > 0);
    }

    #[test]
    fn test_should_equal_vault() {
        let vault1 = Vault::new("user1", "title", VaultKind::Logins);
        let vault_entity1 = VaultEntity::new(&vault1, "salt", "konce", "enc-value");
        let vault2 = Vault::new("user1", "title", VaultKind::Logins);
        let vault_entity2 = VaultEntity::new(&vault2, "salt", "knonce", "enc-value");
        assert_ne!(vault_entity1, vault_entity2);
        let mut hasher = DefaultHasher::new();
        vault_entity1.hash(&mut hasher);
        assert_ne!("", format!("{:x}!", hasher.finish()));
    }

    #[test]
    fn test_should_create_user_vault() {
        let uv = UserVaultEntity::new("uid", "vid");
        assert_eq!("uid", uv.user_id);
        assert_eq!("vid", uv.vault_id);
    }

    #[test]
    fn test_should_encrypt_decrypt_vault() {
        let username = Uuid::new_v4().to_string();
        let user = User::new(username.as_str(), None, None);
        let mut vault = Vault::new(&user.user_id, "title", VaultKind::Logins);
        let salt = hex::encode(crypto::generate_nonce());
        let pepper = hex::encode(crypto::generate_secret_key());
        let ctx =
            UserContext::default_new(&username, &user.user_id, &salt, &pepper, "password").unwrap();
        let (user_crypto_key, _) = CryptoKeyEntity::new_with_input(
            &ctx,
            &ctx.secret_key,
            &user.user_id,
            &user.user_id,
            "User",
            "",
        )
            .unwrap();
        let (mut vault_entity, vault_crypto_key) =
            VaultEntity::new_from_context_vault(&ctx, &user_crypto_key, &vault).unwrap();
        vault.title = "new-title".into();
        vault_entity
            .update_from_context_vault(&ctx, &user_crypto_key, &vault, &vault_crypto_key)
            .unwrap();
        let loaded = vault_entity
            .to_vault(&ctx, &user_crypto_key, &vault_crypto_key)
            .unwrap();
        assert_eq!("new-title", loaded.title);
    }

    #[test]
    fn test_should_create_account() {
        let account = Account::new("vault0", AccountKind::Login);
        let account_entity = AccountEntity::new(&account, "salt", "nonce", "enc-value");
        assert_ne!("", account_entity.account_id.as_str());
        assert_eq!("vault0", account_entity.vault_id.as_str());
        assert_eq!(0, account_entity.version);
        assert_eq!(None, account_entity.archived_version);
        assert_eq!("nonce", account_entity.nonce);
        assert_eq!("enc-value", account_entity.encrypted_value);
        assert!(account_entity.credentials_updated_at.timestamp() > 0);
        assert!(account_entity.created_at.timestamp() > 0);
        assert!(account_entity.updated_at.timestamp() > 0);
    }

    #[test]
    fn test_should_equal_account() {
        let account = Account::new("vault0", AccountKind::Login);
        let account_entity1 = AccountEntity::new(&account, "salt", "nonce", "enc-value");
        let account_entity2 = AccountEntity::new(&account, "salt", "nonce", "enc-value");
        assert_eq!(account_entity1, account_entity2);
        let mut hasher = DefaultHasher::new();
        account_entity1.hash(&mut hasher);
        assert_ne!("", format!("{:x}!", hasher.finish()));
    }

    #[test]
    fn test_should_create_archived_account() {
        let user = User::new("username", None, None);
        let salt = hex::encode(crypto::generate_nonce());
        let pepper = hex::encode(crypto::generate_secret_key());
        let ctx =
            UserContext::default_new(&user.username, &user.user_id, &salt, &pepper, "password")
                .unwrap();
        let account = Account::new("vault0", AccountKind::Login);
        let account_entity = AccountEntity::new(&account, "salt", "nonce", "enc-value");
        let (crypto_key, _) =
            CryptoKeyEntity::new_with_input(&ctx, "pass", &user.user_id, "id", "type", "").unwrap();
        let archived = account_entity.to_archived(&crypto_key);
        assert_ne!("", archived.account_id.as_str());
        assert_eq!("vault0", archived.vault_id.as_str());
        assert_eq!(0, archived.version);
        assert_eq!("nonce", archived.nonce);
        assert_eq!("enc-value", archived.encrypted_value);
        assert!(account_entity.created_at.timestamp() > 0);
    }

    #[test]
    fn test_should_create_encrypt_decrypt_account() {
        let user = User::new("username", None, None);
        let salt = hex::encode(crypto::generate_nonce());
        let pepper = hex::encode(crypto::generate_secret_key());
        let ctx =
            UserContext::default_new(&user.username, &user.user_id, &salt, &pepper, "password")
                .unwrap();
        let (user_crypto_key, _) = CryptoKeyEntity::new_with_input(
            &ctx,
            &ctx.secret_key,
            &user.user_id,
            &user.user_id,
            "User",
            "",
        )
            .unwrap();
        let vault = Vault::new(&user.user_id, "title", VaultKind::Logins);
        let (vault_crypto_key, _) = CryptoKeyEntity::new_with_parent(
            &ctx,
            &user_crypto_key
                .decrypted_private_key_with_symmetric_input(&ctx, &ctx.secret_key)
                .unwrap(),
            &user_crypto_key.public_key,
            &vault.vault_id,
            "Vault",
            &user_crypto_key.crypto_key_id,
        )
            .unwrap();

        let mut account = Account::new("vault0", AccountKind::Login);
        let (mut account_entity, account_crypto_key) = AccountEntity::from_context_vault_account(
            &ctx,
            &user_crypto_key,
            &vault_crypto_key,
            &account,
        )
            .unwrap();

        account.details.username = Some("user1".into());
        account.credentials.password = Some("pass1".into());
        account_entity
            .update_from_context_vault_account(
                &ctx,
                &user_crypto_key,
                &vault_crypto_key,
                &account,
                &account_crypto_key,
            )
            .unwrap();
        let loaded = account_entity
            .to_account(
                &ctx,
                &user_crypto_key,
                &vault_crypto_key,
                &account_crypto_key,
            )
            .unwrap();
        assert_eq!(loaded.details.username, Some("user1".into()));
        assert_eq!(loaded.credentials.password, Some("pass1".into()));

        let archived = account_entity.to_archived(&account_crypto_key);
        let loaded = archived
            .to_account(
                &ctx,
                &user_crypto_key,
                &vault_crypto_key,
                &account_crypto_key,
            )
            .unwrap();
        assert_eq!(loaded.details.username, Some("user1".into()));
        assert_eq!(loaded.credentials.password, Some("pass1".into()));
    }

    #[test]
    fn test_should_create_lookup() {
        let lookup = Lookup::new("user", LookupKind::CATEGORY, "name");
        let mut lookup_entity = LookupEntity::new(&lookup);
        assert_eq!("user", lookup_entity.user_id);
        assert_eq!("name", lookup_entity.name);
        assert_ne!("", lookup_entity.lookup_id);
        assert_eq!(0, lookup_entity.version);
        assert!(lookup_entity.created_at.timestamp() > 0);
        assert!(lookup_entity.updated_at.timestamp() > 0);
        assert_eq!(LookupKind::CATEGORY.to_string(), lookup_entity.kind);
        lookup_entity.kind = LookupKind::TAG.to_string();
        assert_eq!(
            LookupKind::TAG,
            LookupKind::from(lookup_entity.kind.as_str())
        );
    }

    #[test]
    fn test_should_create_setting() {
        let setting = Setting::new("user1", SettingKind::Scan, "name", "value");
        let setting_entity = SettingEntity::new(&setting);
        assert_eq!(SettingKind::Scan.to_string(), setting_entity.kind);
        assert_eq!("name", setting_entity.name);
        assert_eq!("value", setting_entity.value);
        assert_ne!("", setting_entity.setting_id);
        assert_eq!(0, setting_entity.version);
        assert!(setting_entity.created_at.timestamp() > 0);
        assert!(setting_entity.updated_at.timestamp() > 0);
    }

    #[test]
    fn test_should_create_message() {
        let message = Message::new("user", MessageKind::Advisory, "subject", "data");
        let message_entity = MessageEntity::new(&message, "salt", "nonce", "data");
        assert_eq!("user", message_entity.user_id);
        assert_eq!(MessageKind::Advisory.to_string(), message_entity.kind);
        assert_eq!("data", message_entity.encrypted_value);
        assert!(message_entity.created_at.timestamp() > 0);
    }

    #[test]
    fn test_should_create_user_context() {
        let user = User::new("username", None, None);
        let salt = hex::encode(crypto::generate_nonce());
        let pepper = hex::encode(crypto::generate_secret_key());
        let ctx =
            UserContext::default_new(&user.username, &user.user_id, &salt, &pepper, "password")
                .unwrap();
        assert_eq!("username", ctx.username);
        assert_ne!("", ctx.secret_key);
        assert!(!ctx.is_admin());
    }

    #[test]
    fn test_should_user_context_to_key_data() {
        let user = User::new("username", None, None);
        let salt = hex::encode(crypto::generate_nonce());
        let pepper = hex::encode(crypto::generate_secret_key());
        let ctx =
            UserContext::default_new(&user.username, &user.user_id, &salt, &pepper, "password")
                .unwrap();
        let key_data = ctx.to_user_key_params(&salt);
        assert_eq!(user.user_id, key_data.user_id);
        assert_eq!(salt, key_data.salt);
        assert_eq!(pepper, key_data.pepper);
    }
}
