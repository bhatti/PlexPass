use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use prometheus::Registry;

use crate::dao::models::UserContext;
use crate::dao::SettingRepository;
use crate::domain::models::{PassConfig, PassResult, Setting, SettingKind};
use crate::service::SettingService;
use crate::utils::metrics::PassMetrics;

#[derive(Clone)]
pub(crate) struct SettingServiceImpl {
    config: PassConfig,
    setting_repository: Arc<dyn SettingRepository + Send + Sync>,
    metrics: PassMetrics,
}

impl SettingServiceImpl {
    pub(crate) fn new(
        config: &PassConfig,
        setting_repository: Arc<dyn SettingRepository + Send + Sync>,
        registry: &Registry,
    ) -> PassResult<Self> {
        Ok(Self {
            config: config.clone(),
            setting_repository,
            metrics: PassMetrics::new("setting_service", registry)?,
        })
    }

    async fn get_settings_by_kind(
        &self,
        ctx: &UserContext,
        kind: SettingKind,
    ) -> PassResult<Vec<Setting>> {
        let items = self
            .setting_repository
            .find(
                ctx,
                HashMap::from([("kind".into(), kind.to_string())]),
                0,
                self.config.max_setting_entries.clone() as usize,
            )
            .await?;
        let mut res = vec![];
        for item in items.records {
            res.push(item);
        }
        Ok(res)
    }

    async fn get_setting_by_name(
        &self,
        ctx: &UserContext,
        kind: SettingKind,
        name: &str,
    ) -> PassResult<Setting> {
        self.setting_repository
            .find_one(
                ctx,
                HashMap::from([
                    ("kind".into(), kind.to_string()),
                    ("name".into(), name.into()),
                ]),
            )
            .await
    }
}

#[async_trait]
impl SettingService for SettingServiceImpl {
    async fn create_setting(&self, ctx: &UserContext, setting: &Setting) -> PassResult<usize> {
        let _ = self.metrics.new_metric("create_setting");
        self.setting_repository.create(ctx, setting).await
    }

    async fn update_setting(&self, ctx: &UserContext, setting: &Setting) -> PassResult<usize> {
        let _ = self.metrics.new_metric("update_setting");
        self.setting_repository.update(ctx, setting).await
    }

    async fn delete_setting(
        &self,
        ctx: &UserContext,
        kind: SettingKind,
        name: &str,
    ) -> PassResult<usize> {
        let _ = self.metrics.new_metric("delete_setting");
        let setting_entity = self.get_setting_by_name(ctx, kind, name).await?;
        self.setting_repository
            .delete(ctx, &setting_entity.setting_id)
            .await
    }

    async fn get_settings(&self, ctx: &UserContext, kind: SettingKind) -> PassResult<Vec<Setting>> {
        let _ = self.metrics.new_metric("get_settings");
        self.get_settings_by_kind(ctx, kind).await
    }

    async fn get_setting(
        &self,
        ctx: &UserContext,
        kind: SettingKind,
        name: &str,
    ) -> PassResult<Setting> {
        let _ = self.metrics.new_metric("get_setting");
        self.get_setting_by_name(ctx, kind, name).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use uuid::Uuid;

    use crate::domain::models::{PassConfig, Setting, SettingKind, User};
    use crate::service::factory::{create_setting_service, create_user_service};

    #[tokio::test]
    async fn test_should_create_update_setting() {
        let config = PassConfig::new();
        // GIVEN user-service and setting-service
        let user_service = create_user_service(&config).await.unwrap();
        let setting_service = create_setting_service(&config).await.unwrap();

        // Due to referential integrity, we must first create a valid user
        let user = User::new(Uuid::new_v4().to_string().as_str(), None, None);
        let (ctx, _) = user_service.signup_user(&user, "cru5h&r]fIt@$@v!or", HashMap::new()).await.unwrap();

        // WHEN creating a setting
        let mut setting = Setting::new(&user.user_id, SettingKind::Config, "name", "value");

        // THEN it should succeed
        assert_eq!(
            1,
            setting_service
                .create_setting(&ctx, &setting)
                .await
                .unwrap()
        );

        // WHEN updating an setting
        setting.value = "new-value".into();
        // THEN it should succeed updating.
        assert_eq!(
            1,
            setting_service
                .update_setting(&ctx, &setting)
                .await
                .unwrap()
        );

        // WHEN retrieving the setting
        let loaded = setting_service
            .get_setting(&ctx, SettingKind::Config, "name")
            .await
            .unwrap();
        // THEN setting should have updated attributes.
        assert_eq!("name", loaded.name);
        assert_eq!("new-value", loaded.value);
    }

    #[tokio::test]
    async fn test_should_create_delete_settings() {
        let config = PassConfig::new();
        // GIVEN user-service and setting-service
        let user_service = create_user_service(&config).await.unwrap();
        let setting_service = create_setting_service(&config).await.unwrap();

        // Due to referential integrity, we must first create a valid user
        let user = User::new(Uuid::new_v4().to_string().as_str(), None, None);
        let (ctx, _) = user_service.signup_user(&user, "cru5h&r]fIt@$@v!or", HashMap::new()).await.unwrap();

        // WHEN creating an setting
        let setting = Setting::new(&user.user_id, SettingKind::Scan, "name1", "value1");

        // THEN it should succeed
        assert_eq!(
            1,
            setting_service
                .create_setting(&ctx, &setting)
                .await
                .unwrap()
        );

        // WHEN deleting the setting
        let deleted = setting_service
            .delete_setting(&ctx, setting.kind, &setting.name)
            .await
            .unwrap();
        // THEN it should succeed.
        assert_eq!(1, deleted);

        // WHEN retrieving the setting after deleting it THEN it should not find it.
        let res = setting_service
            .get_setting(&ctx, SettingKind::Scan, "name1")
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_should_create_find_settings() {
        let config = PassConfig::new();
        // GIVEN user-service and setting-service
        let user_service = create_user_service(&config).await.unwrap();
        let setting_service = create_setting_service(&config).await.unwrap();

        // Due to referential integrity, we must first create a valid user
        let user = User::new(Uuid::new_v4().to_string().as_str(), None, None);
        let (ctx, _) = user_service.signup_user(&user, "cru5h&r]fIt@$@v!or", HashMap::new()).await.unwrap();

        let kinds = [SettingKind::Scan, SettingKind::Config];
        for i in 0..10 {
            // WHEN creating an setting
            let setting = Setting::new(
                &user.user_id,
                kinds[i % 2].clone(),
                format!("name_{}", i).as_str(),
                format!("value_{}", i).as_str(),
            );
            assert_eq!(
                1,
                setting_service
                    .create_setting(&ctx, &setting)
                    .await
                    .unwrap()
            );
        }

        let res1 = setting_service
            .get_settings(&ctx, SettingKind::Scan)
            .await
            .unwrap();
        assert_eq!(5, res1.len());
        let res2 = setting_service
            .get_settings(&ctx, SettingKind::Config)
            .await
            .unwrap();
        assert_eq!(5, res2.len());
    }
}
