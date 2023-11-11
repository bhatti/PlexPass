use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use prometheus::Registry;
use crate::csv::CSVRecord;

use crate::dao::models::UserContext;
use crate::domain::error::PassError;
use crate::domain::models::{Account, EncodingScheme, ImportResult, PassResult, ProgressStatus, Vault, VaultKind};
use crate::service::{AccountService, EncryptionService, ImportExportService, VaultService};
use crate::utils::metrics::PassMetrics;

#[derive(Clone)]
pub(crate) struct ImportExportServiceImpl {
    vault_service: Arc<dyn VaultService + Send + Sync>,
    account_service: Arc<dyn AccountService + Send + Sync>,
    encryption_service: Arc<dyn EncryptionService + Send + Sync>,
    metrics: PassMetrics,
}

impl ImportExportServiceImpl {
    pub(crate) fn new(
        vault_service: Arc<dyn VaultService + Send + Sync>,
        account_service: Arc<dyn AccountService + Send + Sync>,
        encryption_service: Arc<dyn EncryptionService + Send + Sync>,
        registry: &Registry,
    ) -> PassResult<Self> {
        Ok(Self {
            vault_service,
            account_service,
            encryption_service,
            metrics: PassMetrics::new("import_export_service", registry)?,
        })
    }
}

#[async_trait]
impl ImportExportService for ImportExportServiceImpl {
    async fn import_accounts(&self,
                             ctx: &UserContext,
                             vault_id: Option<String>,
                             vault_kind: Option<VaultKind>,
                             password: Option<String>,
                             encoding: EncodingScheme,
                             data: &[u8],
                             callback: Box<dyn Fn(ProgressStatus) + Send + Sync>,
    ) -> PassResult<ImportResult> {
        let _ = self.metrics.new_metric("import_accounts");
        let vault = if let Some(vault_id) = vault_id {
            self.vault_service.get_vault(ctx, &vault_id).await?
        } else {
            let vaults = self.vault_service.get_user_vaults(ctx).await?;
            let vault_kind = vault_kind.unwrap_or(VaultKind::Logins);
            vaults.into_iter().filter(|v| v.kind == vault_kind).collect::<Vec<Vault>>().first().unwrap().clone()
        };
        let data = if let Some(password) = password {
            self.encryption_service.symmetric_decrypt("", &password, data.to_vec(), encoding)?
        } else {
            data.to_vec()
        };
        let accounts = CSVRecord::parse(&data)?.iter().map(|r| r.to_account(&vault.vault_id)).collect::<Vec<Account>>();
        let mut response = ImportResult::new();
        callback(ProgressStatus::Started { total: accounts.len() });
        for i in 0..accounts.len() {
            match self.account_service.create_account(ctx, &accounts[i]).await {
                Ok(_) => {
                    response.imported += 1;
                    callback(ProgressStatus::Updated { current: i.clone(), total: accounts.len() });
                }
                Err(err) => {
                    if let PassError::DuplicateKey { .. } = err {
                        response.duplicate += 1;
                    } else {
                        response.failed += 1;
                    }
                    log::warn!("failed to import {} due to {}", &accounts[i.clone()].details.account_id, err);
                }
            }
        }
        callback(ProgressStatus::Completed);
        log::info!("imported {} accounts for {:?} vault for user {}", accounts.len(), &vault.vault_id, &ctx.user_id);
        Ok(response)
    }

    async fn export_accounts(&self,
                             ctx: &UserContext,
                             vault_id: &str,
                             secret: Option<String>,
                             encoding: EncodingScheme,
                             callback: Box<dyn Fn(ProgressStatus) + Send + Sync>,
    ) -> PassResult<(String, Vec<u8>)> {
        let _ = self.metrics.new_metric("export_accounts");
        let vault = self.vault_service.get_vault(ctx, vault_id).await?;
        let count = self.account_service.count_accounts_by_vault(ctx, &vault.vault_id, HashMap::new()).await? as usize;
        callback(ProgressStatus::Started { total: count });
        let mut buf = Vec::new();
        for i in (0..count).step_by(10) {
            match self.account_service.find_accounts_by_vault(ctx, &vault.vault_id, HashMap::new(),
                                                              i.clone() as i64, 10).await {
                Ok(accounts) => {
                    let csv_records = accounts.records.iter().map(|a| CSVRecord::new(a)).collect::<Vec<CSVRecord>>();

                    CSVRecord::write(csv_records, &mut buf, i == 0)?;
                    callback(ProgressStatus::Updated { current: i.clone(), total: count.clone() });
                }
                Err(err) => {
                    callback(ProgressStatus::Failed(err.clone()));
                    return Err(err);
                }
            }
        }
        if let Some(secret) = secret {
            buf = self.encryption_service.symmetric_encrypt("", "", &secret, buf, encoding)?;
        }
        callback(ProgressStatus::Completed);
        log::info!("exported {} accounts for {} vault for user {}", count.clone(), &vault.vault_id, &ctx.user_id);
        Ok(("".into(), buf))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use uuid::Uuid;
    use crate::domain::models::{EncodingScheme, HSMProvider, PassConfig, ProgressStatus, User, Vault, VaultKind};
    use crate::service::factory::{create_encryption_service, create_import_export_service, create_user_service, create_vault_service};

    const DATA: &str = r#"
type,name,url,username,password,note,totp,category
Login,Youtube,https://www.youtube.com/,youlogin,youpassword,younote,,
Login,Amazon      ,https://www.amazon.com/,amlogin1,ampassword1,amnote1,,
Login,Bank of America ,https://www.boa.com/,mylogin3,mypassword3,mynote3,,
Login,Twitter     ,https://www.twitter.com/,mylogin3,mypassword3,mynote3,,
Login,AT&T,https://www.att.com/,mylogin4,mypassword4,mynote4,,
Login,All State Insurance,https://www.allstate.com/,mylogin5,mypassword5,mynote5,,
Login,Microsoft,https://www.microsoft.com/,mylogin7,mypassword7,mynote7,,
Secure Note,Personal Note name,,,,My Secure Note,,
Secure Note,Social Note name1,,,,My Secure Note1,,
Secure Note,Work Note name2,,,,My Secure Note2,,
Secure Note,Reminder Note name3,,,,My Secure Note3,,
Secure Note,TODO Note name4,,,,My Secure Note4,,
Secure Note,Plan Note name5,,,,My Secure Note5,,
Login,Netflix,https://www.netflix.com/,mylogin6,mypassword6,mynote6,,
Login,Facebook,https://www.facebook.com/,mylogin8,mypassword8,mynote8,,
Login,Twitch,https://twitch.tv/,mylogin6,mypassword6,mynote6,,"""
"#;

    #[tokio::test]
    async fn test_should_export_import_accounts() {
        let mut config = PassConfig::new();
        config.hsm_provider = HSMProvider::EncryptedFile.to_string();

        // GIVEN user-service, vault-service and account-service
        let user_service = create_user_service(&config).await.unwrap();
        let vault_service = create_vault_service(&config).await.unwrap();
        let ix_service = create_import_export_service(&config).await.unwrap();
        // Due to referential integrity, we must first create a valid user
        let user = User::new(Uuid::new_v4().to_string().as_str(), None, None);
        // creating user with strong password
        let (ctx, _) = user_service.signup_user(&user, "cru5h&r]fIt@$@v", HashMap::new()).await.unwrap();

        // Create dependent vault
        let vault = Vault::new(&user.user_id, "title1", VaultKind::Logins);
        assert_eq!(1, vault_service.create_vault(&ctx, &vault).await.unwrap());

        // WHEN import accounts
        let res = ix_service.import_accounts(
            &ctx,
            Some(vault.vault_id.clone()),
            None,
            None,
            EncodingScheme::Base64,
            DATA.as_bytes(),
            Box::new(|status| match status {
                ProgressStatus::Started { .. } => {}
                ProgressStatus::Updated { .. } => {}
                ProgressStatus::Completed => {}
                ProgressStatus::Failed(_) => {}
            }),
        ).await.unwrap();
        // THEN it should add accounts
        assert_eq!(16, res.imported);

        let (_, bytes_csv) = ix_service.export_accounts(
            &ctx,
            &vault.vault_id,
            None,
            EncodingScheme::None,
            Box::new(|status| match status {
                ProgressStatus::Started { .. } => {}
                ProgressStatus::Updated { .. } => {}
                ProgressStatus::Completed => {}
                ProgressStatus::Failed(_) => {}
            }),
        ).await.unwrap();
        let str_csv = String::from_utf8(bytes_csv).expect("failed to convert csv");
        let lines = str_csv.as_str().split("\n").collect::<Vec<&str>>();
        assert_eq!(
            19, // + header and empty line
            lines.len(),
        );
    }

    #[tokio::test]
    async fn test_should_export_import_accounts_with_secret() {
        let mut config = PassConfig::new();
        config.hsm_provider = HSMProvider::EncryptedFile.to_string();

        // GIVEN user-service, vault-service and import-export service
        let user_service = create_user_service(&config).await.unwrap();
        let vault_service = create_vault_service(&config).await.unwrap();
        let ix_service = create_import_export_service(&config).await.unwrap();
        // Due to referential integrity, we must first create a valid user
        let user = User::new(Uuid::new_v4().to_string().as_str(), None, None);
        // creating user with strong password
        let (ctx, _) = user_service.signup_user(&user, "cru5h&r]fIt@$@v", HashMap::new()).await.unwrap();

        // Create dependent vault
        let vault = Vault::new(&user.user_id, "title1", VaultKind::Logins);
        assert_eq!(1, vault_service.create_vault(&ctx, &vault).await.unwrap());

        // WHEN import accounts
        let res = ix_service.import_accounts(
            &ctx,
            Some(vault.vault_id.clone()),
            None,
            None,
            EncodingScheme::Base64,
            DATA.as_bytes(),
            Box::new(|status| match status {
                ProgressStatus::Started { .. } => {}
                ProgressStatus::Updated { .. } => {}
                ProgressStatus::Completed => {}
                ProgressStatus::Failed(_) => {}
            }),
        ).await.unwrap();
        // THEN it should add accounts
        assert_eq!(16, res.imported);

        let (_, encrypted_bytes) = ix_service.export_accounts(
            &ctx,
            &vault.vault_id,
            Some("password".into()),
            EncodingScheme::Base64,
            Box::new(|status| match status {
                ProgressStatus::Started { .. } => {}
                ProgressStatus::Updated { .. } => {}
                ProgressStatus::Completed => {}
                ProgressStatus::Failed(_) => {}
            }),
        ).await.unwrap();
        let encryption_service = create_encryption_service(&config).await.unwrap();
        let bytes_csv = encryption_service.symmetric_decrypt("", "password", encrypted_bytes, EncodingScheme::Base64).unwrap();
        let str_csv = String::from_utf8(bytes_csv).expect("failed to convert csv");
        let lines = str_csv.as_str().split("\n").collect::<Vec<&str>>();
        assert_eq!(
            19, // + header and empty line
            lines.len(),
        );
    }
}
