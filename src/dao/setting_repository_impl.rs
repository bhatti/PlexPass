use async_trait::async_trait;
use chrono::Utc;
use diesel::prelude::*;
use std::collections::HashMap;

use crate::dao::models::{CryptoKeyEntity, SettingEntity, UserContext};
use crate::dao::schema::settings;
use crate::dao::schema::settings::dsl::*;
use crate::dao::{DbConnection, DbPool, Repository, SettingRepository};
use crate::domain::error::PassError;
use crate::domain::models::{PaginatedResult, PassResult, Setting};

#[derive(Clone)]
pub(crate) struct SettingRepositoryImpl {
    pool: DbPool,
}

impl SettingRepositoryImpl {
    pub(crate) fn new(pool: DbPool) -> Self {
        SettingRepositoryImpl { pool }
    }
    fn connection(&self) -> PassResult<DbConnection> {
        self.pool.get().map_err(|err| {
            PassError::database(
                format!("failed to get pool connection due to {}", err).as_str(),
                None,
                true,
            )
        })
    }
}

#[async_trait]
impl SettingRepository for SettingRepositoryImpl {}

#[async_trait]
impl Repository<Setting, SettingEntity> for SettingRepositoryImpl {
    // create setting.
    async fn create(&self, ctx: &UserContext, setting: &Setting) -> PassResult<usize> {
        // ensure user-context and setting user-id matches -- no acl check
        ctx.validate_user_id(&setting.user_id, || false)?;

        let setting_entity = SettingEntity::new(setting);

        let mut conn = self.connection()?;
        match diesel::insert_into(settings::table)
            .values(setting_entity)
            .execute(&mut conn)
        {
            Ok(size) => {
                if size > 0 {
                    Ok(size)
                } else {
                    Err(PassError::database(
                        format!("failed to insert setting {}", setting.setting_id).as_str(),
                        None,
                        false,
                    ))
                }
            }
            Err(err) => Err(PassError::from(err)),
        }
    }

    // updates existing setting.
    async fn update(&self, ctx: &UserContext, setting: &Setting) -> PassResult<usize> {
        // ensure setting belongs to user -- no acl check
        ctx.validate_user_id(&setting.user_id, || false)?;

        let existing_setting_entity = self.get_entity(&ctx, &setting.setting_id).await?;

        let mut conn = self.connection()?;
        let size = diesel::update(
            settings.filter(
                version
                    .eq(&existing_setting_entity.version)
                    .and(setting_id.eq(&setting.setting_id)),
            ),
        )
        .set((
            kind.eq(setting.kind.to_string()),
            name.eq(&setting.name),
            value.eq(&setting.value),
            updated_at.eq(Utc::now().naive_utc()),
        ))
        .execute(&mut conn)?;
        if size > 0 {
            Ok(size)
        } else {
            Err(PassError::database(
                format!("failed to update setting {}", setting.setting_id,).as_str(),
                None,
                false,
            ))
        }
    }

    // get setting by id
    async fn get(&self, ctx: &UserContext, id: &str) -> PassResult<Setting> {
        let setting_entity = self.get_entity(ctx, id).await?;

        Ok(setting_entity.to_setting())
    }

    // delete an existing setting.
    async fn delete(&self, ctx: &UserContext, id: &str) -> PassResult<usize> {
        let setting_entity = self.get_entity(&ctx, id).await?;

        // ensure setting belongs to user - no acl check
        ctx.validate_user_id(&setting_entity.user_id, || false)?;

        let mut conn = self.connection()?;
        match diesel::delete(settings.filter(setting_id.eq(id))).execute(&mut conn) {
            Ok(size) => {
                if size > 0 {
                    Ok(size)
                } else {
                    Err(PassError::database(
                        format!("failed to find records for deleting {}", id).as_str(),
                        None,
                        false,
                    ))
                }
            }
            Err(err) => Err(PassError::from(err)),
        }
    }

    async fn get_crypto_key(&self, _ctx: &UserContext, _id: &str) -> PassResult<CryptoKeyEntity> {
        Err(PassError::validation("not implemented", None))
    }

    // get setting entity by id
    async fn get_entity(&self, ctx: &UserContext, id: &str) -> PassResult<SettingEntity> {
        let mut conn = self.connection()?;
        let mut items = settings
            .filter(setting_id.eq(id))
            .limit(2)
            .load::<SettingEntity>(&mut conn)?;

        if items.len() > 1 {
            return Err(PassError::database(
                format!("too many settings for {}", id).as_str(),
                None,
                false,
            ));
        } else if items.is_empty() {
            return Err(PassError::not_found(
                format!("setting not found for {}", id).as_str(),
            ));
        }
        let entity = items.remove(0);
        // ensure setting belongs to user - no acl check
        ctx.validate_user_id(&entity.user_id, || false)?;
        Ok(entity)
    }

    // find one entity by predication -- must have only one record, i.e., it will throw error if 0 or 2+ records exist.
    async fn find_one(
        &self,
        ctx: &UserContext,
        predicates: HashMap<String, String>,
    ) -> PassResult<Setting> {
        let mut res = self.find(ctx, predicates, 0, 5).await?;
        if res.records.len() != 1 {
            return Err(PassError::authorization(
                format!("could not find setting [{}]", res.records.len()).as_str(),
            ));
        }
        Ok(res.records.remove(0))
    }

    // find settings with pagination
    async fn find(
        &self,
        ctx: &UserContext,
        predicates: HashMap<String, String>,
        offset: i64,
        limit: usize,
    ) -> PassResult<PaginatedResult<Setting>> {
        let mut predicates = predicates.clone();
        // only admin can query all users
        if !ctx.is_admin() {
            predicates.insert("user_id".into(), ctx.user_id.clone());
        }

        let mut conn = self.connection()?;
        let match_kind = format!(
            "%{}%",
            predicates.get("kind").cloned().unwrap_or(String::from(""))
        );
        let match_name = format!(
            "%{}%",
            predicates.get("name").cloned().unwrap_or(String::from(""))
        );
        let match_user_id = predicates
            .get("user_id")
            .cloned()
            .unwrap_or(String::from(""));

        let entities = settings
            .filter(
                user_id
                    .eq(match_user_id)
                    .and(kind.like(match_kind.as_str()))
                    .and(name.like(match_name.as_str())),
            )
            .offset(offset)
            .limit(limit as i64)
            .order(settings::kind)
            .then_order_by(settings::name)
            .load::<SettingEntity>(&mut conn)?;

        let mut res = vec![];
        for entity in entities {
            let setting = entity.to_setting();
            res.push(setting)
        }
        Ok(PaginatedResult::new(offset.clone(), limit.clone(), res))
    }

    async fn count(
        &self,
        ctx: &UserContext,
        predicates: HashMap<String, String>,
    ) -> PassResult<i64> {
        let mut predicates = predicates.clone();
        if !ctx.is_admin() {
            predicates.insert("user_id".into(), ctx.user_id.clone());
        }

        let mut conn = self.connection()?;
        let match_kind = format!(
            "%{}%",
            predicates.get("kind").cloned().unwrap_or(String::from(""))
        );
        let match_name = format!(
            "%{}%",
            predicates.get("name").cloned().unwrap_or(String::from(""))
        );
        let match_user_id = predicates
            .get("user_id")
            .cloned()
            .unwrap_or(String::from(""));
        match settings
            .filter(
                user_id
                    .eq(match_user_id)
                    .and(kind.like(match_kind.as_str()))
                    .and(name.like(match_name.as_str())),
            )
            .count()
            .get_result::<i64>(&mut conn)
        {
            Ok(count) => Ok(count),
            Err(err) => Err(PassError::from(err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto;
    use crate::dao::factory::{create_setting_repository, create_user_repository};
    use crate::dao::models::UserContext;
    use crate::domain::models::{PassConfig, Setting, SettingKind, User};
    use std::collections::HashMap;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_should_create_update_settings() {
        let config = PassConfig::new();
        // GIVEN setting and user repository
        let setting_repo = create_setting_repository(&config).await.unwrap();
        let user_repo = create_user_repository(&config).await.unwrap();

        let salt = hex::encode(crypto::generate_nonce());
        let pepper = hex::encode(crypto::generate_secret_key());
        // Due to referential integrity, we must first create a valid user
        let username = Uuid::new_v4().to_string();
        let user = User::new(username.as_str(), None, None);
        let ctx =
            UserContext::default_new(&username, &user.user_id, &salt, &pepper, "password").unwrap();

        assert_eq!(1, user_repo.create(&ctx, &user).await.unwrap());

        // WHEN creating a setting
        let mut setting = Setting::new(&user.user_id, SettingKind::Config, "name", "value");
        // THEN it should succeed
        assert_eq!(1, setting_repo.create(&ctx, &setting).await.unwrap());

        // WHEN updating the setting
        setting.value = "new-value".into();
        // THEN it should succeed.
        assert_eq!(1, setting_repo.update(&ctx, &setting).await.unwrap());

        // WHEN retrieving the setting
        let loaded = setting_repo.get(&ctx, &setting.setting_id).await.unwrap();
        // THEN it should match the value.
        assert_eq!("name", loaded.name);
        assert_eq!("new-value", loaded.value);
    }

    #[tokio::test]
    async fn test_should_create_delete_settings() {
        let config = PassConfig::new();
        // GIVEN setting and user repository
        let setting_repo = create_setting_repository(&config).await.unwrap();
        let user_repo = create_user_repository(&config).await.unwrap();

        let salt = hex::encode(crypto::generate_nonce());
        let pepper = hex::encode(crypto::generate_secret_key());
        // Due to referential integrity, we must first create a valid user
        let username = Uuid::new_v4().to_string();
        let user = User::new(username.as_str(), None, None);

        let ctx =
            UserContext::default_new(&username, &user.user_id, &salt, &pepper, "password").unwrap();

        assert_eq!(1, user_repo.create(&ctx, &user).await.unwrap());

        // WHEN creating a setting
        let setting = Setting::new(&user.user_id, SettingKind::Scan, "name", "value");
        // THEN it should succeed.
        assert_eq!(1, setting_repo.create(&ctx, &setting).await.unwrap());

        // WHEN deleting the setting
        let deleted = setting_repo
            .delete(&ctx, &setting.setting_id)
            .await
            .unwrap();
        // THEN it should succeed.
        assert_eq!(1, deleted);

        // WHEN retrieving the setting after delete THEN it should fail.
        assert!(setting_repo.get(&ctx, &setting.setting_id).await.is_err());
    }

    #[tokio::test]
    async fn test_should_create_find_settings() {
        let config = PassConfig::new();
        let prefix = Uuid::new_v4().to_string();
        // GIVEN setting and user repository
        let setting_repo = create_setting_repository(&config).await.unwrap();
        let user_repo = create_user_repository(&config).await.unwrap();

        let salt = hex::encode(crypto::generate_nonce());
        let pepper = hex::encode(crypto::generate_secret_key());
        // Due to referential integrity, we must first create a valid user
        let username = Uuid::new_v4().to_string();
        let user = User::new(username.as_str(), None, None);

        let ctx =
            UserContext::default_new(&username, &user.user_id, &salt, &pepper, "password").unwrap();

        assert_eq!(1, user_repo.create(&ctx, &user).await.unwrap());

        for i in 0..10 {
            // WHEN creating a setting
            let name = format!("{}_{}", prefix, i);
            let value = format!("{}_{}_value", prefix, i);
            let setting = Setting::new(&user.user_id, SettingKind::Scan, &name, &value);
            // THEN it should succeed.
            assert_eq!(1, setting_repo.create(&ctx, &setting).await.unwrap());
        }

        // WHEN finding the setting by kind
        let res = setting_repo
            .find(
                &ctx,
                HashMap::from([("kind".into(), SettingKind::Scan.to_string())]),
                0,
                500,
            )
            .await
            .unwrap();
        // THEN it should succeed
        assert!(res.records.len() >= 10);

        // WHEN counting the settings
        let count = setting_repo
            .count(
                &ctx,
                HashMap::from([("kind".into(), SettingKind::Scan.to_string())]),
            )
            .await
            .unwrap();
        // THEN it should succeed.
        assert!(count >= 10);
    }
}
