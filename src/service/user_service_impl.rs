use std::collections::HashMap;
use std::sync::Arc;

use crate::domain::models::{DEFAULT_VAULT_NAMES, PasswordPolicy, PasswordStrength, UserToken, Vault, VaultKind};
use async_trait::async_trait;
use prometheus::Registry;

use crate::crypto;
use crate::dao::models::{CONTEXT_IP_ADDRESS, UserContext};
use crate::dao::{LoginSessionRepository, ShareVaultAccountRepository, UserRepository, VaultRepository};
use crate::domain::error::PassError;
use crate::domain::models::{
    LoginSession, PassConfig, PassResult, Roles, User, UserKeyParams, USER_KEY_PARAMS_NAME,
    USER_SECRET_KEY_NAME,
};
use crate::locales::safe_localized_message;
use crate::service::{PasswordService, UserService};
use crate::store::HSMStore;
use crate::utils::current_time_ms;
use crate::utils::metrics::PassMetrics;

#[derive(Clone)]
pub(crate) struct UserServiceImpl {
    config: PassConfig,
    hsm_store: Arc<dyn HSMStore + Send + Sync>,
    user_repository: Arc<dyn UserRepository + Send + Sync>,
    vault_repository: Arc<dyn VaultRepository + Send + Sync>,
    login_session_repository: Arc<dyn LoginSessionRepository + Send + Sync>,
    share_vault_account_repository: Arc<dyn ShareVaultAccountRepository + Send + Sync>,
    password_service: Arc<dyn PasswordService + Send + Sync>,
    metrics: PassMetrics,
}

impl UserServiceImpl {
    pub(crate) fn new(
        config: &PassConfig,
        hsm_service: Arc<dyn HSMStore + Send + Sync>,
        user_repository: Arc<dyn UserRepository + Send + Sync>,
        vault_repository: Arc<dyn VaultRepository + Send + Sync>,
        login_session_repository: Arc<dyn LoginSessionRepository + Send + Sync>,
        share_vault_account_repository: Arc<dyn ShareVaultAccountRepository + Send + Sync>,
        password_service: Arc<dyn PasswordService + Send + Sync>,
        registry: &Registry,
    ) -> PassResult<Self> {
        Ok(Self {
            config: config.clone(),
            hsm_store: hsm_service,
            user_repository,
            vault_repository,
            login_session_repository,
            share_vault_account_repository,
            password_service,
            metrics: PassMetrics::new("user_service", registry)?,
        })
    }

    fn add_user_session(&self, context: HashMap<String, String>, user: &User) -> PassResult<UserToken> {
        let mut login_session = LoginSession::new(&user.user_id);
        login_session.ip_address = context.get(CONTEXT_IP_ADDRESS).cloned();
        let _ = self.login_session_repository.create(&login_session)?;
        Ok(UserToken::new(&self.config, &user, &login_session))
    }
}

#[async_trait]
impl UserService for UserServiceImpl {
    // Signup a new user
    async fn signup_user(&self,
                         user: &User,
                         master_password: &str,
                         context: HashMap<String, String>, ) -> PassResult<(UserContext, UserToken)> {
        let _ = current_time_ms();
        let metric = self.metrics.new_metric("signup_user");
        let password_info = PasswordPolicy::password_info(master_password);
        if password_info.strength != PasswordStrength::STRONG {
            let sample_password = PasswordPolicy::new().generate_strong_memorable_password(3).unwrap_or("".into());
            let err_msg = safe_localized_message(
                "weak-master-password",
                Some(&vec!["info", &password_info.to_string(),
                           "sample_password", &sample_password,
                ]));
            return Err(PassError::validation(&err_msg, None));
        }

        // creating salt and pepper for secure hashing and encryption
        let salt = hex::encode(crypto::generate_nonce());
        let pepper = hex::encode(crypto::generate_secret_key());

        // creating context
        let mut ctx = UserContext::from_master_password(
            &user.username,
            &user.user_id,
            master_password,
            user.roles.clone(),
            &salt,
            &pepper,
            self.config.hash_algorithm(),
            self.config.crypto_algorithm(),
        )?;
        ctx.attributes = context.clone();
        let existing = self
            .hsm_store
            .get_property(&user.username, USER_KEY_PARAMS_NAME);
        if existing.is_ok() {
            log::debug!("user {} may already be existing", &user.username);
        }

        // Service pepper and secret in HSM where pepper will be permanently serviced and
        // secret will be temporarily serviced while the session is active and will be removed
        // after expiration of session or logout. The secret key will be regenerated from
        // salt, pepper, and master-key upon sign-in.
        match self.user_repository.create(&ctx, user).await {
            Ok(_) => {}
            Err(err) => {
                if let PassError::DuplicateKey { .. } = err {
                    return Err(PassError::duplicate_key("duplicate username"));
                }
                return Err(err);
            }
        }

        // create default vaults
        for vault_title in DEFAULT_VAULT_NAMES {
            let vault = Vault::new(&user.user_id, &vault_title, VaultKind::from(vault_title));
            let _ = self.vault_repository.create(&ctx, &vault).await?;
        }

        self.hsm_store.set_property(
            &user.username,
            USER_KEY_PARAMS_NAME,
            ctx.to_user_key_params(&salt).serialize()?.as_str(),
        )?;
        self.hsm_store
            .set_property(&user.username, USER_SECRET_KEY_NAME, &ctx.secret_key)?;

        let token = self.add_user_session(context, &user)?;
        log::info!("Signed up {} in {:?}", &user.user_id, metric.elapsed());
        Ok((ctx, token))
    }

    // signin and retrieve the user.
    async fn signin_user(
        &self,
        username: &str,
        master_password: &str,
        context: HashMap<String, String>,
    ) -> PassResult<(UserContext, User, UserToken)> {
        let metric = self.metrics.new_metric("signin_user");
        let key_params_str = self.hsm_store
            .get_property(username, USER_KEY_PARAMS_NAME).
            map_err(|_| PassError::authentication(safe_localized_message("auth-error", None).as_str()))?;
        let key_params = UserKeyParams::deserialize(&key_params_str)?;

        let secret_key = UserContext::build_secret_key(
            &key_params.salt,
            &key_params.pepper,
            master_password,
            self.config.hash_algorithm(),
        )?;
        let mut ctx = UserContext::new(
            username,
            &key_params.user_id,
            Roles::new(0),
            &key_params.pepper,
            &secret_key,
            self.config.hash_algorithm(),
            self.config.crypto_algorithm(),
        );

        // Finding user by id
        let user = match self.user_repository.get(&ctx, &ctx.user_id).await {
            Ok(user) => { user }
            Err(err) => {
                if let PassError::Crypto { .. } = err {
                    return Err(PassError::authentication("failed to validate credentials"));
                }
                return Err(err);
            }
        };

        ctx.roles = user.roles.clone();
        let token = self.add_user_session(context, &user)?;

        self.share_vault_account_repository.handle_shared_vaults_accounts(&ctx).await?;

        let _ = self.password_service.schedule_analyze_all_vault_passwords(&ctx).await?;

        // Storing secret key temporarily while the login session is active
        self.hsm_store
            .set_property(username, USER_SECRET_KEY_NAME, &secret_key)?;

        log::info!("Signin {} in {:?}", &ctx.user_id, metric.elapsed());
        Ok((ctx, user, token))
    }

    // logout user by username.
    async fn signout_user(&self, ctx: &UserContext, login_session_id: &str) -> PassResult<()> {
        let _ = self.metrics.new_metric("signout_user");
        let _ = self.login_session_repository.delete(login_session_id)?;
        // clear secret key in HSM
        self.hsm_store
            .set_property(&ctx.username, USER_SECRET_KEY_NAME, "")?;
        Ok(())
    }

    async fn get_user(&self, ctx: &UserContext, id: &str) -> PassResult<(UserContext, User)> {
        let _ = self.metrics.new_metric("get_user");
        // Finding user by username
        let user = self.user_repository.get(&ctx, id).await?;
        let mut ctx = ctx.clone();
        ctx.roles = user.roles.clone();
        Ok((ctx, user))
    }

    async fn update_user(&self, ctx: &UserContext, user: &User) -> PassResult<usize> {
        let _ = self.metrics.new_metric("update_user");
        self.user_repository.update(&ctx, user).await
    }

    async fn delete_user(&self, ctx: &UserContext, id: &str) -> PassResult<usize> {
        let _ = self.metrics.new_metric("delete_user");
        let (ctx, user) = self.get_user(ctx, id).await?;
        let size = match self.user_repository.delete(&ctx, &user.user_id).await {
            Ok(size) => { size }
            Err(err) => {
                if let PassError::Constraints { .. } = err {
                    return Err(PassError::constraints("user cannot be deleted because it still has vaults and accounts."));
                }
                return Err(err);
            }
        };

        // ignoring errors related to resetting hsm.
        let _ = self
            .hsm_store
            .set_property(&ctx.username, USER_KEY_PARAMS_NAME, "");
        let _ = self
            .hsm_store
            .set_property(&ctx.username, USER_SECRET_KEY_NAME, "");
        Ok(size)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use uuid::Uuid;

    use crate::domain::models::{HSMProvider, PassConfig, User};
    use crate::service::factory::{create_user_service, create_vault_service};

    #[tokio::test]
    async fn test_should_signup_user() {
        let mut config = PassConfig::new();
        config.hsm_provider = HSMProvider::EncryptedFile.to_string();
        // GIVEN user-service
        let user_service = create_user_service(&config).await.unwrap();

        let user = User::new(Uuid::new_v4().to_string().as_str(), None, None);

        // WHEN signing up a new user with weak password THEN it should fail
        assert!(user_service.signup_user(&user, "password", HashMap::new()).await.is_err());

        // WHEN signing up a new user with strong password
        let (ctx, _) = user_service.signup_user(&user, "cru5h&r]fIt@$@v!or", HashMap::new()).await.unwrap();

        // THEN it should succeed
        assert_eq!(ctx.username, user.username);
        assert_eq!(ctx.user_id, user.user_id);
        assert_ne!("", ctx.user_id);
        assert_ne!("", ctx.pepper);
        assert_ne!("", ctx.secret_key);
    }

    #[tokio::test]
    async fn test_should_signin_user() {
        let mut config = PassConfig::new();
        config.hsm_provider = HSMProvider::EncryptedFile.to_string();
        // GIVEN user-service
        let user_service = create_user_service(&config).await.unwrap();

        let user = User::new(Uuid::new_v4().to_string().as_str(), None, None);

        // AND user is already signed up
        let _ = user_service.signup_user(&user, "cru5h&r]fIt@$@v!or", HashMap::new()).await.unwrap();

        // THEN Sign in should succeed
        let _ = user_service
            .signin_user(&user.username, "cru5h&r]fIt@$@v!or", HashMap::new())
            .await
            .unwrap();

        // WHEN signing in as an existing user
        let (ctx, _, _) = user_service
            .signin_user(&user.username, "cru5h&r]fIt@$@v!or", HashMap::new())
            .await
            .unwrap();

        // THEN it should succeed
        assert_eq!(ctx.username, user.username);
        assert_eq!(ctx.user_id, user.user_id);
        assert_eq!(ctx.roles, user.roles);
        assert_ne!("", ctx.pepper);
        assert_ne!("", ctx.secret_key);
    }

    #[tokio::test]
    async fn test_should_get_update_delete_user() {
        let mut config = PassConfig::new();
        config.hsm_provider = HSMProvider::EncryptedFile.to_string();
        // GIVEN user-service and vault service
        let user_service = create_user_service(&config).await.unwrap();
        let vault_service = create_vault_service(&config).await.unwrap();

        // AND user is already signed up
        let mut user = User::new(Uuid::new_v4().to_string().as_str(), None, None);

        let (ctx, _) = user_service.signup_user(&user, "cru5h&r]fIt@$@v!or", HashMap::new()).await.unwrap();

        // WHEN retrieving as an existing user
        let (ctx, _) = user_service.get_user(&ctx, &user.user_id).await.unwrap();

        // THEN it should succeed
        assert_eq!(ctx.username, user.username);
        assert_eq!(ctx.user_id, user.user_id);
        assert_ne!("", ctx.user_id);
        assert_ne!("", ctx.pepper);
        assert_ne!("", ctx.secret_key);

        // WHEN updating the user
        user.name = Some("new-name".into());
        user.email = Some("new-email".into());

        // THEN it should succeed
        assert_eq!(1, user_service.update_user(&ctx, &user).await.unwrap());

        //
        // WHEN retrieving the user
        let (_, loaded) = user_service
            .get_user(&ctx, user.user_id.as_str())
            .await
            .unwrap();
        // THEN it should succeed and user attributes should match
        assert_eq!(2, loaded.version);
        assert_eq!(Some("new-name"), loaded.name.as_deref());
        assert_eq!(Some("new-email"), loaded.email.as_deref());
        //
        // WHEN deleting the user without deleting vaults first THEN it should fail
        assert!(user_service.delete_user(&ctx, &user.user_id).await.is_err());
        let vaults = vault_service.get_user_vaults(&ctx).await.unwrap();
        // WHEN deleting the user after deleting all vaults
        for vault in vaults {
            let _ = vault_service.delete_vault(&ctx, &vault.vault_id).await.unwrap();
        }
        // THEN it should succeed
        let deleted = user_service.delete_user(&ctx, &user.user_id).await.unwrap();
        assert_eq!(1, deleted);
        //
        // WHEN retrieving the user after deleting it.
        let loaded = user_service.get_user(&ctx, &user.user_id).await;
        // THEN it should fail.
        assert!(loaded.is_err());
    }
}
