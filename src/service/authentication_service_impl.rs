use std::collections::HashMap;
use std::sync::Arc;
use webauthn_rs::prelude::*;
use async_trait::async_trait;
use chrono::{NaiveDateTime, Utc};
use prometheus::Registry;
use url::Url;
use crate::dao::models::{CONTEXT_IP_ADDRESS, UserContext};

use crate::dao::{LoginSessionRepository, ShareVaultAccountRepository, UserRepository};
use crate::domain::error::PassError;
use crate::domain::models::{HardwareSecurityKey, LoginSession, PassConfig, PassResult, PasswordPolicy, PasswordStrength, SessionStatus, User, USER_KEY_PARAMS_NAME, USER_SECRET_KEY_NAME, UserKeyParams, UserToken};
use crate::locales::safe_localized_message;
use crate::service::{AuthenticationService, PasswordService};
use crate::store::HSMStore;
use crate::utils::metrics::PassMetrics;

#[derive(Clone)]
pub(crate) struct AuthenticationServiceImpl {
    config: PassConfig,
    metrics: PassMetrics,
    hsm_store: Arc<dyn HSMStore + Send + Sync>,
    user_repository: Arc<dyn UserRepository + Send + Sync>,
    login_session_repository: Arc<dyn LoginSessionRepository + Send + Sync>,
    share_vault_account_repository: Arc<dyn ShareVaultAccountRepository + Send + Sync>,
    password_service: Arc<dyn PasswordService + Send + Sync>,
    webauthn: Arc<Webauthn>,
}

const WEBAUTHN_REG_STATE: &str = "webauthn_reg_state";
const WEBAUTHN_AUTH_STATE: &str = "webauthn_auth_state";

impl AuthenticationServiceImpl {
    pub(crate) fn new(
        config: &PassConfig,
        hsm_store: Arc<dyn HSMStore + Send + Sync>,
        user_repository: Arc<dyn UserRepository + Send + Sync>,
        login_session_repository: Arc<dyn LoginSessionRepository + Send + Sync>,
        share_vault_account_repository: Arc<dyn ShareVaultAccountRepository + Send + Sync>,
        password_service: Arc<dyn PasswordService + Send + Sync>,
        registry: &Registry,
    ) -> PassResult<Self> {
        // Configure the Webauthn instance by using the WebauthnBuilder. This defines
        // the options needed for your site, and has some implications. One of these is that
        // you can NOT change your rp_id (relying party id), without invalidating all
        // webauthn credentials. Remember, rp_id is derived from your URL origin, meaning
        // that it is your effective domain name.

        // Effective domain name.
        let rp_id = config.domain.clone();
        // Url containing the effective domain name
        // MUST include the port number!
        let rp_origin = Url::parse(&format!("https://{}:{}",
                                        &rp_id, config.https_port))?;
        let builder = WebauthnBuilder::new(&rp_id, &rp_origin)?;

        // Now, with the builder you can define other options.
        let builder = builder.rp_name("PlexPass-Webauthn");

        Ok(Self {
            config: config.clone(),
            hsm_store,
            user_repository,
            login_session_repository,
            share_vault_account_repository,
            password_service,
            webauthn: Arc::new(builder.build()?),
            metrics: PassMetrics::new("webauthn_service", registry)?,
        })
    }

    fn add_user_session(&self,
                        context: HashMap<String, String>,
                        user: &User,
                        mfa_verified_at: Option<NaiveDateTime>,
    ) -> PassResult<UserToken> {
        let mut login_session = LoginSession::new(user);
        login_session.ip_address = context.get(CONTEXT_IP_ADDRESS).cloned();
        login_session.mfa_verified_at = mfa_verified_at;
        let _ = self.login_session_repository.create(&login_session)?;
        Ok(UserToken::from_session(&self.config, &login_session))
    }
}

#[async_trait]
impl AuthenticationService for AuthenticationServiceImpl {
    // signin and retrieve the user.
    async fn signin_user(
        &self,
        username: &str,
        master_password: &str,
        otp_code: Option<u32>,
        context: HashMap<String, String>,
    ) -> PassResult<(UserContext, User, UserToken, SessionStatus)> {
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
            None,
            false,
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

        ctx.light_mode = user.light_mode.unwrap_or_default();
        ctx.roles = user.roles.clone();
        self.share_vault_account_repository.handle_shared_vaults_accounts(&ctx).await?;

        let _ = self.password_service.schedule_analyze_all_vault_passwords(&ctx, false).await?;

        // Storing secret key temporarily while the login session is active
        self.hsm_store
            .set_property(username, USER_SECRET_KEY_NAME, &secret_key)?;

        let mut session_status = SessionStatus::Valid;
        let mut mfa_verified_at = None;
        if user.mfa_required() {
            session_status = SessionStatus::RequiresMFA;
            if let Some(otp_code) = otp_code {
                if user.verify_otp(otp_code) {
                    session_status = SessionStatus::Valid;
                    mfa_verified_at = Some(Utc::now().naive_utc());
                }
            }
        }
        let token = self.add_user_session(context, &user, mfa_verified_at)?;

        log::info!("Signin {} session {:?} in {:?}", &ctx.user_id, &session_status, metric.elapsed());
        Ok((ctx, user, token, session_status))
    }

    // logout user by username.
    async fn signout_user(&self, ctx: &UserContext, login_session_id: &str) -> PassResult<()> {
        let _ = self.metrics.new_metric("signout_user");
        let _ = self.login_session_repository.signout(&ctx.user_id, login_session_id)?;
        // clear secret key in HSM
        self.hsm_store
            .set_property(&ctx.username, USER_SECRET_KEY_NAME, "")?;
        Ok(())
    }

    // change password for the user.
    async fn change_password(
        &self,
        ctx: &UserContext,
        old_master_password: &str,
        new_master_password: &str,
        confirm_new_master_password: &str,
        login_session_id: &str,
    ) -> PassResult<usize> {
        if new_master_password != confirm_new_master_password {
            return Err(PassError::validation(&safe_localized_message("new-master-confirm-mismatch", None), None));
        }
        if old_master_password == new_master_password {
            return Err(PassError::validation(&safe_localized_message("same-new-master-password", None), None));
        }

        let password_info = PasswordPolicy::password_info(new_master_password);
        if password_info.strength != PasswordStrength::STRONG {
            let sample_password = PasswordPolicy::new().generate_strong_memorable_password(3).unwrap_or("".into());
            let err_msg = safe_localized_message(
                "weak-master-password",
                Some(&["info", &password_info.to_string(),
                    "sample_password", &sample_password]));
            return Err(PassError::validation(&err_msg, None));
        }

        let key_params_str = self.hsm_store
            .get_property(&ctx.username, USER_KEY_PARAMS_NAME).
            map_err(|_| PassError::authentication(safe_localized_message("auth-error", None).as_str()))?;
        let key_params = UserKeyParams::deserialize(&key_params_str)?;

        let secret_key = UserContext::build_secret_key(
            &key_params.salt, &key_params.pepper, old_master_password,
            self.config.hash_algorithm(),
        )?;
        if secret_key != ctx.secret_key {
            return Err(PassError::validation(&safe_localized_message("old-master-mismatch", None), None));
        }
        let mut new_ctx = ctx.clone();
        new_ctx.secret_key = UserContext::build_secret_key(
            &key_params.salt, &key_params.pepper, new_master_password,
            self.config.hash_algorithm(),
        )?;
        let size = self.user_repository.change_password(ctx, &new_ctx).await?;

        self.signout_user(ctx, login_session_id).await?;
        Ok(size)
    }


    // Start MFA registration
    async fn start_register_key(&self,
                                ctx: &UserContext,
    ) -> PassResult<CreationChallengeResponse> {
        let _ = self.metrics.new_metric("start_register");
        log::debug!("start_register {}", &ctx.user_id);
        let user = self.user_repository.get(ctx, &ctx.user_id).await?;
        if user.hardware_keys().len() >= 5 {
           return Err(PassError::validation("you have already registered too many security keys", None));
        }
        // clear reg-state
        self.hsm_store.set_property(&ctx.username, WEBAUTHN_REG_STATE, "")?;
        // If the user has any other credentials, we exclude these here so they can't be duplicate registered.
        // It also hints to the browser that only new credentials should be "blinked" for interaction.
        let exclude_credentials = user.hardware_key_ids();

        let (ccr, reg_state) = self.webauthn.start_passkey_registration(
            Uuid::parse_str(&ctx.user_id)?,
            &ctx.username,
            &ctx.username,
            exclude_credentials)?;
        // NOTE: We shouldn't sore reg_state in session because we are using cookies store.
        // Instead, we will store HSM for safe keeping
        let json_reg_state = serde_json::to_string(&reg_state)?;
        self.hsm_store.set_property(&ctx.username, WEBAUTHN_REG_STATE, &json_reg_state)?;
        Ok(ccr)
    }

    // Finish MFA registration ad returns user
    async fn finish_register_key(&self,
                                 ctx: &UserContext,
                                 name: &str,
                                 req: &RegisterPublicKeyCredential) -> PassResult<HardwareSecurityKey> {
        let _ = self.metrics.new_metric("finish_register");
        log::debug!("finish_register {}", &ctx.user_id);
        let reg_state_str = self.hsm_store.get_property(&ctx.username, WEBAUTHN_REG_STATE)?;
        if reg_state_str.is_empty() {
            return Err(PassError::authentication("could not find webauthn registration key"));
        }
        let reg_state: PasskeyRegistration = serde_json::from_str(&reg_state_str)?;
        self.hsm_store.set_property(&ctx.username, WEBAUTHN_REG_STATE, "")?;

        let sk = self.webauthn.finish_passkey_registration(req, &reg_state)?;
        let mut user = self.user_repository.get(ctx, &ctx.user_id).await?;
        let hardware_key = user.add_security_key(name, &sk);
        self.user_repository.update(ctx, &user).await?;
        Ok(hardware_key)
    }

    // Start authentication with MFA
    async fn start_key_authentication(&self,
                                      ctx: &UserContext,
    ) -> PassResult<RequestChallengeResponse> {
        let _ = self.metrics.new_metric("start_authentication");
        // clear reg-state
        self.hsm_store.set_property(&ctx.username, WEBAUTHN_AUTH_STATE, "")?;
        let user = self.user_repository.get(ctx, &ctx.user_id).await?;

        let allow_credentials = user.get_security_keys();
        if allow_credentials.is_empty() {
            return Err(PassError::authentication("could not find webauthn keys"));
        }

        let (rcr, auth_state) = self.webauthn
            .start_passkey_authentication(&allow_credentials)?;

        // Note: We will store auth-state in HSM as we use cookie-store for session.
        let json_auth_state = serde_json::to_string(&auth_state)?;
        self.hsm_store.set_property(&ctx.username, WEBAUTHN_AUTH_STATE, &json_auth_state)?;

        Ok(rcr)
    }

    // Finish MFA authentication
    async fn finish_key_authentication(&self,
                                       ctx: &UserContext,
                                       session_id: &str,
                                       auth: &PublicKeyCredential) -> PassResult<()> {
        let _ = self.metrics.new_metric("finish_authentication");
        let auth_state_str = self.hsm_store.get_property(&ctx.username, WEBAUTHN_AUTH_STATE)?;
        if auth_state_str.is_empty() {
            return Err(PassError::authentication("could not find webauthn auth key"));
        }
        self.hsm_store.set_property(&ctx.username, WEBAUTHN_AUTH_STATE, "")?;
        let auth_state: PasskeyAuthentication = serde_json::from_str(&auth_state_str)?;

        let auth_result = self.webauthn.finish_passkey_authentication(auth, &auth_state)?;
        let mut user = self.user_repository.get(ctx, &ctx.user_id).await?;

        user.update_security_keys(&auth_result);
        self.user_repository.update(ctx, &user).await?;
        let _session = self.login_session_repository.mfa_succeeded(&ctx.user_id, session_id)?;
        Ok(())
    }

    // reset mfa keys
    async fn reset_mfa_keys(&self,
                            ctx: &UserContext,
                            recovery_code: &str,
                            session_id: &str) -> PassResult<()> {
        let mut user = self.user_repository.get(ctx, &ctx.user_id).await?;
        if user.reset_security_keys(recovery_code) {
            let _ = self.user_repository.update(ctx, &user).await?;
            self.login_session_repository.signout(&ctx.user_id, session_id)?;
            return Ok(());
        }
        Err(PassError::authentication("could not reset MFA keys, please verify your recovery code"))
    }
    // update light mode
    async fn update_light_mode(&self,
                               ctx: &UserContext,
                               session_id: &str,
                               light_mode: bool) -> PassResult<usize> {
        self.login_session_repository.update_light_mode(
            &ctx.user_id,
            session_id, light_mode)

    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use uuid::Uuid;
    use crate::domain::models::{HSMProvider, PassConfig, User};
    use crate::service::factory::{create_auth_service, create_user_service};

    #[tokio::test]
    async fn test_should_authenticate() {}

    #[tokio::test]
    async fn test_should_signin_user() {
        let mut config = PassConfig::new();
        config.hsm_provider = HSMProvider::EncryptedFile.to_string();
        // GIVEN user-service and auth-service
        let user_service = create_user_service(&config).await.unwrap();
        let auth_service = create_auth_service(&config).await.unwrap();

        let user = User::new(Uuid::new_v4().to_string().as_str(), None, None);

        // AND user is already signed up
        let _ = user_service.register_user(&user, "cru5h&r]fIt@$@v!or", HashMap::new()).await.unwrap();

        // THEN Sign in should succeed
        let _ = auth_service
            .signin_user(&user.username, "cru5h&r]fIt@$@v!or", None, HashMap::new())
            .await
            .unwrap();

        // WHEN signing in as an existing user
        let (ctx, _, _, _) = auth_service
            .signin_user(&user.username, "cru5h&r]fIt@$@v!or", None, HashMap::new())
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
    async fn test_should_change_password() {
        let mut config = PassConfig::new();
        config.hsm_provider = HSMProvider::EncryptedFile.to_string();
        // GIVEN user-service and auth-service
        let user_service = create_user_service(&config).await.unwrap();
        let auth_service = create_auth_service(&config).await.unwrap();

        let user = User::new(Uuid::new_v4().to_string().as_str(), None, None);

        // AND user is already signed up
        let _ = user_service.register_user(&user, "cru5h&r]fIt@$@v!or", HashMap::new()).await.unwrap();

        // THEN Sign in should succeed
        let (ctx, _, token, _) = auth_service
            .signin_user(&user.username, "cru5h&r]fIt@$@v!or", None, HashMap::new())
            .await
            .unwrap();

        let size = auth_service.change_password(
            &ctx,
            "cru5h&r]fIt@$@v!or",
            "cru5h&r]fIt@$@v!or111",
        &token.login_session).await.unwrap();
        assert_eq!(1, size);
    }
}
