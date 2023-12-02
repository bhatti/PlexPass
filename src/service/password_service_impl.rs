use std::collections::{HashMap};
use std::sync::Arc;
use std::time::Duration;
use crate::domain::models::{AccountPasswordSummary, Advisory, PassConfig, PassResult, PasswordInfo, PasswordPolicy, PasswordSimilarity, PasswordStrength, VaultAnalysis};
use crate::hibp;
use crate::service::{AccountService, PasswordService, VaultService};
use async_trait::async_trait;
use chrono::{Utc};
use prometheus::Registry;
use crate::background::Scheduler;
use crate::dao::models::UserContext;
use crate::domain::error::PassError;
use crate::utils::metrics::PassMetrics;
use crate::utils::text::{cosine_similarity, jaccard_similarity, jaro_winkler_similarity, levenshtein_distance};

const VAULT_ANALYZE_DELAY_MILLIS: i64 = 60 * 1000 * 30; // 30 minutes

#[derive(Clone)]
pub(crate) struct PasswordServiceImpl {
    config: PassConfig,
    vault_service: Arc<dyn VaultService + Send + Sync>,
    account_service: Arc<dyn AccountService + Send + Sync>,
    scheduler: Arc<Scheduler>,
    metrics: PassMetrics,
}

impl PasswordServiceImpl {
    pub(crate) fn new(
        config: &PassConfig,
        vault_service: Arc<dyn VaultService + Send + Sync>,
        account_service: Arc<dyn AccountService + Send + Sync>,
        scheduler: Arc<Scheduler>,
        registry: &Registry,
    ) -> PassResult<Self> {
        Ok(Self {
            config: config.clone(),
            vault_service,
            account_service,
            scheduler,
            metrics: PassMetrics::new("password_service", registry)?,
        })
    }

    async fn password_summaries(&self, ctx: &UserContext, vault_id: &str) -> PassResult<Vec<AccountPasswordSummary>> {
        let mut result = vec![];
        let mut offset = 0;
        loop {
            let accounts = self.account_service.find_accounts_by_vault(
                ctx, vault_id, HashMap::new(), offset, 1000).await?;
            for account in &accounts.records {
                if account.details.username.is_some() || account.details.email.is_some() || account.credentials.has_password() {
                    result.push(account.to_password_summary());
                }
            }

            if accounts.records.len() < 1000 {
                break;
            }
            offset += 1000;
        }
        Ok(result)
    }
}

#[async_trait]
impl PasswordService for PasswordServiceImpl {
    async fn generate_password(&self, policy: &PasswordPolicy) -> Option<String> {
        let _ = self.metrics.new_metric("generate_memorable_password");
        if policy.random {
            policy.generate_strong_random_password()
        } else {
            policy.generate_strong_memorable_password(3)
        }
    }

    async fn password_info(&self, password: &str) -> PassResult<PasswordInfo> {
        let _ = self.metrics.new_metric("password_info");
        Ok(PasswordPolicy::password_info(password))
    }

    async fn password_compromised(&self, password: &str) -> PassResult<bool> {
        let _ = self.metrics.new_metric("password_compromised");
        hibp::password_compromised(password).await
    }

    // check if email is compromised.
    async fn email_compromised(&self, email: &str) -> PassResult<String> {
        let _ = self.metrics.new_metric("password_compromised");
        if let Some(api_key) = self.config.hibp_api_key.clone() {
            hibp::email_compromised(email, &api_key).await
        } else {
            Err(PassError::validation("could not find api key for HIBP", None))
        }
    }


    // check similarity of password.
    async fn password_similarity(&self, password1: &str, password2: &str) -> PassResult<PasswordSimilarity> {
        let _ = self.metrics.new_metric("password_similarity");
        Ok(PasswordSimilarity {
            levenshtein_distance: levenshtein_distance(password1, password2),
            jaccard_similarity: jaccard_similarity(password1, password2),
            cosine_similarity: cosine_similarity(password1, password2),
            jaro_winkler_similarity: jaro_winkler_similarity(password1, password2),
        })
    }

    // analyze passwords and accounts of all accounts in given vault
    // It returns hashmap by account-id and password analysis
    async fn analyze_vault_passwords(&self, ctx: &UserContext, vault_id: &str, force: bool) -> PassResult<VaultAnalysis> {
        let _ = self.metrics.new_metric("analyze_all_account_passwords");
        let now = Utc::now().naive_utc();

        let vault = self.vault_service.get_vault(ctx, vault_id).await?;
        if let Some(analysis) = vault.analysis {
            let elapsed = now.timestamp_millis() - analysis.analyzed_at.timestamp_millis();
            if !force && elapsed < VAULT_ANALYZE_DELAY_MILLIS {
                log::info!("skipping password analysis for {} because it was created {} millis ago at {}.",
                    vault_id, &elapsed, &analysis.analyzed_at);
                return Err(PassError::validation("vault was recently analyzed so skipping it", None));
            }
        }

        let mut password_summaries: Vec<AccountPasswordSummary> = self.password_summaries(ctx, vault_id).await?;
        let mut passwords_by_account_id = HashMap::new();
        let mut vault_analysis = VaultAnalysis::new();
        for password_summary in &password_summaries {
            if let Some(password) = password_summary.password.clone() {
                passwords_by_account_id.insert(password_summary.account_id.clone(), password.clone());
            }
        }

        // skip analysis if last analysis was run 24 hours ago
        for password_summary in &mut password_summaries {
            password_summary.advisories.clear();
            if let Some(email) = &password_summary.email {
                if let Ok(compromised) = self.email_compromised(email).await {
                    password_summary.password_analysis.compromised_account_analysis = compromised.clone();
                    password_summary.advisories.insert(Advisory::CompromisedEmail, compromised.clone());
                }
            }

            if let Some(password) = &password_summary.password {
                let password_info = self.password_info(password).await?;
                if password_info.strength != PasswordStrength::STRONG {
                    password_summary.advisories.insert(Advisory::WeakPassword,
                                                       format!("The password is {}",
                                                               password_info.strength));
                }
                password_summary.password_analysis.copy_from(&password_info);

                for (account_id, other_password) in &passwords_by_account_id {
                    if account_id != &password_summary.account_id {
                        if password == other_password {
                            password_summary.password_analysis.count_reused += 1;
                        } else {
                            let similar_password = self.password_similarity(password, other_password).await?;
                            if similar_password.jaro_winkler_similarity >= 0.8 {
                                password_summary.password_analysis.count_similar_to_other_passwords += 1;
                            }
                        }
                    }
                }

                if password_summary.password_analysis.count_similar_to_other_passwords > 0 {
                    password_summary.advisories.insert(Advisory::SimilarOtherPassword,
                                                       format!("The password is similar to {} other passwords",
                                                               password_summary.password_analysis.count_similar_to_other_passwords));
                }

                if password_summary.password_analysis.count_reused > 0 {
                    password_summary.advisories.insert(Advisory::PasswordReused,
                                                       format!("The password is reused in {} other accounts",
                                                               password_summary.password_analysis.count_reused));
                }

                for old_password in &password_summary.past_passwords {
                    let similar_password = self.password_similarity(password, old_password).await?;
                    if similar_password.jaro_winkler_similarity >= 0.8 {
                        password_summary.password_analysis.count_similar_to_past_passwords += 1;
                        password_summary.advisories.insert(Advisory::SimilarPastPassword,
                                                           format!("The password is similar to {} past passwords",
                                                                   password_summary.password_analysis.count_similar_to_past_passwords));
                    }
                }

                // Check if password is compromised
                if let Ok(compromised) = self.password_compromised(password).await {
                    if compromised {
                        password_summary.advisories.insert(Advisory::CompromisedPassword,
                                                           "The password is compromised and found in 'Have I been Pwned' database.".to_string());
                        password_summary.password_analysis.compromised = compromised;
                    }
                }
                //
                // TODO  CompromisedWebsite
                //
                let mut account = self.account_service.get_account(ctx, &password_summary.account_id).await?;
                if account.update_analysis(password_summary) {
                    let _ = self.account_service.update_account(ctx, &account).await?;
                }

                vault_analysis.update(password_summary);
            }
        }

        // reading vault again because it would have been updated and version wouldn't match so it would fail to update.
        let mut vault = self.vault_service.get_vault(ctx, vault_id).await?;
        // update vault if needed
        vault_analysis.analyzed_at = Utc::now().naive_utc();
        vault.analysis = Some(vault_analysis.clone());
        let _ = self.vault_service.update_vault(ctx, &vault).await?;
        vault_analysis.total_accounts = vault.entries.unwrap_or_default().len();

        log::info!("analyzed {} passwords for user {}", &vault_analysis.total_accounts, &ctx.user_id);

        Ok(vault_analysis)
    }

    // analyze passwords and accounts of all accounts in all vaults
    // It returns hashmap by (vault-id, account-id) and password analysis
    async fn analyze_all_vault_passwords(&self, ctx: &UserContext, force: bool) -> PassResult<HashMap<String, VaultAnalysis>> {
        let _ = self.metrics.new_metric("analyze_all_vault_passwords");
        let vaults = self.vault_service.get_user_vaults(ctx).await?;
        let mut all_analysis = HashMap::new();
        for vault in vaults {
            let vault_analysis = self.analyze_vault_passwords(ctx, &vault.vault_id, force).await?;
            all_analysis.insert(vault.vault_id.clone(), vault_analysis);
        }
        Ok(all_analysis)
    }

    // schedule password analysis for vault
    async fn schedule_analyze_vault_passwords(&self, ctx: &UserContext, vault_id: &str, force: bool) -> PassResult<()> {
        let password_service_copy = self.clone();
        // Schedule a delayed task
        let vault_id = vault_id.to_string();
        self.scheduler.schedule(
            format!("analyze_passwords_{}", &ctx.user_id),
            Some(Duration::from_millis(10)),
            ctx.clone(),
            Box::new(move |ctx: UserContext| {
                Box::pin(async move {
                    match password_service_copy.analyze_vault_passwords(&ctx, &vault_id, force).await {
                        Ok(analysis) => {
                            log::info!("executed analyze_all_account_passwords {}", &analysis.total_accounts);
                        }
                        Err(err) => {
                            log::warn!("could not execute analyze_all_account_passwords due to {:?}", err);
                        }
                    };
                })
            }));
        Ok(())
    }

    // schedule password analysis for all vaults
    async fn schedule_analyze_all_vault_passwords(&self, ctx: &UserContext, force: bool) -> PassResult<()> {
        let password_service_copy = self.clone();
        // Schedule a delayed task
        self.scheduler.schedule(
            format!("analyze_passwords_{}", &ctx.user_id),
            Some(Duration::from_millis(10)),
            ctx.clone(),
            Box::new(move |ctx: UserContext| {
                Box::pin(async move {
                    match password_service_copy.analyze_all_vault_passwords(&ctx, force).await {
                        Ok(analysis) => {
                            log::info!("executed analyze_all_vault_passwords {}", analysis.len());
                        }
                        Err(err) => {
                            log::warn!("could not execute analyze_all_vault_passwords due to {:?}", err);
                        }
                    };
                })
            }));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use uuid::Uuid;
    use crate::domain::models::{Account, AccountKind, HSMProvider, PassConfig, PasswordPolicy, PasswordStrength, User, Vault, VaultKind};
    use crate::service::factory::{create_account_service, create_password_service, create_user_service, create_vault_service};

    #[tokio::test]
    async fn test_generate_memorable_password() {
        let config = PassConfig::new();
        let pws = create_password_service(&config).await.unwrap();
        let mut policy = PasswordPolicy::new();
        policy.random = false;
        let password = pws.generate_password(&policy).await.unwrap();
        let info = pws.password_info(&password).await.unwrap();
        assert_eq!(PasswordStrength::STRONG, info.strength);
        assert!(info.entropy > 80.0);
    }

    #[tokio::test]
    async fn test_should_random_generate_password() {
        let config = PassConfig::new();
        let pws = create_password_service(&config).await.unwrap();
        let mut policy = PasswordPolicy::new();
        policy.random = true;
        let password = pws.generate_password(&policy).await.unwrap();
        let info = pws.password_info(&password).await.unwrap();
        assert_eq!(PasswordStrength::STRONG, info.strength);
        assert!(info.entropy > 80.0);
    }

    #[tokio::test]
    async fn test_should_check_for_password_compromised() {
        let config = PassConfig::new();
        let pws = create_password_service(&config).await.unwrap();
        let ok = pws.password_compromised("password").await.unwrap();
        assert!(ok);
    }

    #[tokio::test]
    async fn test_should_compute_levenshtein_distance() {
        let config = PassConfig::new();
        let pws = create_password_service(&config).await.unwrap();
        let password1 = "password123";
        let password2 = "password154"; // Only two character different
        let similarity = pws.password_similarity(password1, password2).await.unwrap();
        assert_eq!(2, similarity.levenshtein_distance);
        assert!(similarity.jaccard_similarity > 0.6);
        assert!(similarity.cosine_similarity > 0.8);
        assert!(similarity.jaro_winkler_similarity > 0.8);
    }

    #[tokio::test]
    async fn test_should_analyze_all_vault_passwords() {
        let mut config = PassConfig::new();
        config.hsm_provider = HSMProvider::EncryptedFile.to_string();
        // GIVEN user-service, vault-service, account-service and password services
        let user_service = create_user_service(&config).await.unwrap();
        let vault_service = create_vault_service(&config).await.unwrap();
        let account_service = create_account_service(&config).await.unwrap();
        let password_service = create_password_service(&config).await.unwrap();

        // Due to referential integrity, we must first create a valid user
        let user = User::new(Uuid::new_v4().to_string().as_str(), None, None);
        let ctx = user_service.register_user(&user, "cru5h&r]fIt@$@v", HashMap::new()).await.unwrap();

        let passwords = vec!["apple", "applepie", "BytesAndBooks123", "cru5h&r]fIt@$@v"];
        for vault in vault_service.get_user_vaults(&ctx).await.unwrap() {
            for password in &passwords {
                // WHEN creating a new account
                let mut account = Account::new(&vault.vault_id, AccountKind::Logins);
                account.details.username = Some(format!("user_{}", password));
                account.credentials.password = Some(password.to_string());
                assert_eq!(1, account_service.create_account(&ctx, &account).await.unwrap());
                let mut retrieved = account_service.get_account(&ctx, &account.details.account_id).await.unwrap();
                retrieved.credentials.password = Some(format!("{}ab", password));
                let _ = account_service.update_account(&ctx, &retrieved).await.unwrap();
            }
        }
        let all_analysis = password_service.analyze_all_vault_passwords(&ctx, false).await.unwrap();
        assert!(!all_analysis.is_empty());
        assert!(password_service.analyze_all_vault_passwords(&ctx, false).await.is_err());
    }

    #[tokio::test]
    async fn test_analyze_vault() {
        let mut config = PassConfig::new();
        config.hsm_provider = HSMProvider::EncryptedFile.to_string();
        // GIVEN user-service, vault-service, account-service and password services
        let user_service = create_user_service(&config).await.unwrap();
        let vault_service = create_vault_service(&config).await.unwrap();
        let account_service = create_account_service(&config).await.unwrap();
        let password_service = create_password_service(&config).await.unwrap();

        // Due to referential integrity, we must first create a valid user
        let user = User::new(Uuid::new_v4().to_string().as_str(), None, None);
        let ctx = user_service.register_user(&user, "cru5h&r]fIt@$@v", HashMap::new()).await.unwrap();

        // Create dependent vault
        let vault = Vault::new(&user.user_id, "title1", VaultKind::Logins);
        assert_eq!(1, vault_service.create_vault(&ctx, &vault).await.unwrap());


        // AND Given three accounts with passwords
        let mut account1 = Account::new(&vault.vault_id, AccountKind::Logins);
        account1.details.label = Some("user1".into());
        account1.details.username = Some("user1".into());
        account1.credentials.password = Some("Rootbeer123".into());
        assert_eq!(1, account_service .create_account(&ctx, &account1).await.unwrap());
        let mut account2 = Account::new(&vault.vault_id, AccountKind::Logins);
        account2.details.label = Some("user2".into());
        account2.details.username = Some("user2".into());
        account2.credentials.password = Some("sMU{b+CMP76T9g^>".into());
        assert_eq!(1, account_service .create_account(&ctx, &account2).await.unwrap());
        let mut account3 = Account::new(&vault.vault_id, AccountKind::Logins);
        account3.details.label = Some("user3".into());
        account3.details.username = Some("user3".into());
        account3.credentials.password = Some("Rootbeer1".into());
        assert_eq!(1, account_service .create_account(&ctx, &account3).await.unwrap());

        // AND Given three accounts with usernames/emails but without passwords
        let mut account4 = Account::new(&vault.vault_id, AccountKind::Logins);
        account4.details.label = Some("user4".into());
        account4.details.username = Some("user4".into());
        assert_eq!(1, account_service .create_account(&ctx, &account4).await.unwrap());
        let mut account5 = Account::new(&vault.vault_id, AccountKind::Logins);
        account5.details.label = Some("user5".into());
        account5.details.email = Some("email5@bitvaulet.com".into());
        assert_eq!(1, account_service .create_account(&ctx, &account5).await.unwrap());
        let mut account6 = Account::new(&vault.vault_id, AccountKind::Logins);
        account6.details.phone = Some("phone6".into());
        account6.details.label = Some("user6".into());
        assert_eq!(1, account_service .create_account(&ctx, &account6).await.unwrap());

        // AND Given a account without anything and another with just label
        let account7 = Account::new(&vault.vault_id, AccountKind::Logins);
        assert_eq!(1, account_service .create_account(&ctx, &account7).await.unwrap());
        let mut account8 = Account::new(&vault.vault_id, AccountKind::Logins);
        account8.details.label = Some("user8".into());
        assert_eq!(1, account_service .create_account(&ctx, &account8).await.unwrap());

        // AND Given two accounts with notes
        let mut account9 = Account::new(&vault.vault_id, AccountKind::Logins);
        account9.details.label = Some("user9".into());
        account9.details.username = Some("user9".into());
        account9.credentials.notes = Some("note9".into());
        assert_eq!(1, account_service .create_account(&ctx, &account9).await.unwrap());

        let mut account10 = Account::new(&vault.vault_id, AccountKind::Logins);
        account10.details.label = Some("user10".into());
        account10.details.username = Some("user10".into());
        account10.credentials.notes = Some("note10".into());
        assert_eq!(1, account_service .create_account(&ctx, &account10).await.unwrap());

        // WHEN analyzing accounts
        let analysis = password_service.analyze_vault_passwords(&ctx, &vault.vault_id, false).await.unwrap();
        // THEN it should return proper analysis.

        // AND verify account updates
        let all = account_service
            .find_accounts_by_vault(&ctx, &vault.vault_id, HashMap::new(), 0, 1000)
            .await
            .unwrap();
        let mut advisories = 0;
        for account in all.records {
            advisories += account.details.advisories.len();
        }

        assert_eq!(10, analysis.total_accounts);
        assert_eq!(3, analysis.total_accounts_with_passwords);
        assert_eq!(1, analysis.count_strong_passwords);
        assert_eq!(2, analysis.count_moderate_passwords);
        assert_eq!(0, analysis.count_weak_passwords);
        assert_eq!(1, analysis.count_healthy_passwords);
        assert_eq!(2, analysis.count_compromised);
        assert_eq!(2, analysis.count_similar_to_other_passwords);
        assert_eq!(0, analysis.count_reused);
        assert_eq!(0, analysis.count_similar_to_past_passwords);
        assert_eq!(6, advisories);
    }
}
