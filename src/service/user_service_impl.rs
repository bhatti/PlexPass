use std::collections::HashMap;
use std::sync::Arc;

use crate::domain::models::UserToken;
use async_trait::async_trait;
use prometheus::Registry;

use crate::crypto;
use crate::dao::models::UserContext;
use crate::dao::{LoginSessionRepository, UserRepository};
use crate::domain::models::{
    LoginSession, PassConfig, PassResult, Roles, User, UserKeyParams, USER_KEY_PARAMS_NAME,
    USER_SECRET_KEY_NAME,
};
use crate::service::UserService;
use crate::store::HSMStore;
use crate::utils::metrics::PassMetrics;

#[derive(Clone)]
pub(crate) struct UserServiceImpl {
    config: PassConfig,
    hsm_store: Arc<dyn HSMStore + Send + Sync>,
    user_repository: Arc<dyn UserRepository + Send + Sync>,
    login_session_repository: Arc<dyn LoginSessionRepository + Send + Sync>,
    metrics: PassMetrics,
}

impl UserServiceImpl {
    pub(crate) fn new(
        config: &PassConfig,
        hsm_service: Arc<dyn HSMStore + Send + Sync>,
        user_repository: Arc<dyn UserRepository + Send + Sync>,
        login_session_repository: Arc<dyn LoginSessionRepository + Send + Sync>,
        registry: &Registry,
    ) -> PassResult<Self> {
        Ok(Self {
            config: config.clone(),
            hsm_store: hsm_service,
            user_repository,
            login_session_repository,
            metrics: PassMetrics::new("user_service", registry)?,
        })
    }
}

#[async_trait]
impl UserService for UserServiceImpl {
    // Signup a new user
    async fn signup_user(&self, user: &User, master_password: &str) -> PassResult<UserContext> {
        let _ = self.metrics.new_metric("signup_user");
        // creating salt and pepper for secure hashing and encryption
        let salt = hex::encode(crypto::generate_nonce());
        let pepper = hex::encode(crypto::generate_secret_key());

        // creating context
        let ctx = UserContext::from_master_password(
            &user.username,
            &user.user_id,
            master_password,
            user.roles.clone(),
            &salt,
            &pepper,
            self.config.hash_algorithm(),
            self.config.crypto_algorithm(),
        )?;
        let existing = self
            .hsm_store
            .get_property(&user.username, USER_KEY_PARAMS_NAME);
        if existing.is_ok() {
            log::info!("user {} may already be existing", &user.username);
        }

        // Service pepper and secret in HSM where pepper will be permanently serviced and
        // secret will be temporarily serviced while the session is active and will be removed
        // after expiration of session or logout. The secret key will be regenerated from
        // salt, pepper, and master-key upon sign-in.
        let _ = self.user_repository.create(&ctx, user).await?;
        self.hsm_store.set_property(
            &user.username,
            USER_KEY_PARAMS_NAME,
            ctx.to_user_key_params(&salt).serialize()?.as_str(),
        )?;
        self.hsm_store
            .set_property(&user.username, USER_SECRET_KEY_NAME, &ctx.secret_key)?;

        Ok(ctx)
    }

    // signin and retrieve the user.
    async fn signin_user(
        &self,
        username: &str,
        master_password: &str,
        context: HashMap<String, String>,
    ) -> PassResult<(UserContext, User, UserToken)> {
        let _ = self.metrics.new_metric("signin_user");
        let key_params = UserKeyParams::deserialize(
            &self
                .hsm_store
                .get_property(username, USER_KEY_PARAMS_NAME)?,
        )?;

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
        let user = self.user_repository.get(&ctx, &ctx.user_id).await?;
        ctx.roles = user.roles.clone();
        let mut login_session = LoginSession::new(&user.user_id);
        login_session.ip_address = context.get("ip_address").cloned();
        let _ = self.login_session_repository.create(&login_session)?;
        let token = UserToken::new(&self.config, &user, &login_session);

        // Storing secret key temporarily while the login session is active
        self.hsm_store
            .set_property(username, USER_SECRET_KEY_NAME, &secret_key)?;

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
        let size = self.user_repository.delete(&ctx, &user.user_id).await?;

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
    use crate::dao::models::UserContext;
    use std::collections::HashMap;
    use uuid::Uuid;

    use crate::domain::models::{HSMProvider, PassConfig, User};
    use crate::service::factory::create_user_service;

    #[tokio::test]
    async fn test_should_signup_user() {
        let mut config = PassConfig::new();
        config.hsm_provider = HSMProvider::EncryptedFile.to_string();
        // GIVEN user-service
        let user_service = create_user_service(&config).await.unwrap();

        let user = User::new(Uuid::new_v4().to_string().as_str(), None, None);

        // WHEN signing up a new user
        let ctx = user_service.signup_user(&user, "master1").await.unwrap();

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
        let _ = user_service.signup_user(&user, "master2").await.unwrap();

        // THEN Sign in should succeed
        let _ = user_service
            .signin_user(&user.username, "master2", HashMap::new())
            .await
            .unwrap();

        // WHEN signing in as an existing user
        let (ctx, _, _) = user_service
            .signin_user(&user.username, "master2", HashMap::new())
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
        // GIVEN user-service
        let user_service = create_user_service(&config).await.unwrap();

        // AND user is already signed up
        let mut user = User::new(Uuid::new_v4().to_string().as_str(), None, None);

        let _ = user_service.signup_user(&user, "master3").await.unwrap();

        let ctx = UserContext::default_new(&user.username, &user.user_id, "", "", "").unwrap();
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
        // WHEN deleting the user
        let deleted = user_service.delete_user(&ctx, &user.user_id).await.unwrap();
        // THEN it should succeed
        assert_eq!(1, deleted);
        //
        // WHEN retrieving the user after deleting it.
        let loaded = user_service.get_user(&ctx, &user.user_id).await;
        // THEN it should fail.
        assert!(loaded.is_err());
    }
}
