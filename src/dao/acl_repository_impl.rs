use async_trait::async_trait;
use chrono::Utc;
use diesel::prelude::*;
use std::collections::HashMap;

use crate::dao::models::{CryptoKeyEntity, ACLEntity, UserContext};
use crate::dao::schema::acls;
use crate::dao::schema::acls::dsl::*;
use crate::dao::{DbConnection, DbPool, ACLRepository, Repository};
use crate::domain::error::PassError;
use crate::domain::models::{PaginatedResult, PassResult};

#[derive(Clone)]
pub(crate) struct ACLRepositoryImpl {
    pool: DbPool,
}

impl ACLRepositoryImpl {
    #[allow(dead_code)]
    pub(crate) fn new(pool: DbPool) -> Self {
        ACLRepositoryImpl { pool }
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

    pub fn check_acl(
        match_user_id: &str,
        match_resource_id: &str,
        match_resource_type: &str,
        match_permissions: i64,
        c: &mut DbConnection) -> bool {
        match acls
            .filter(
                acl_user_id
                    .eq(match_user_id)
                    .and(permissions.ge(match_permissions))
                    .and(resource_type.eq(match_resource_type))
                    .and(resource_id.eq(match_resource_id)),
            )
            .count()
            .get_result::<i64>(c)
        {
            Ok(count) => {
                count > 0
            },
            Err(_) => false,
        }
    }

    // create acl with connection.
    pub fn create_conn(
        acl_entity: &ACLEntity,
        conn: &mut DbConnection,
    ) -> Result<usize, diesel::result::Error> {
        match diesel::insert_into(acls::table)
            .values(acl_entity)
            .execute(conn)
        {
            Ok(size) => {
                Ok(size)
            }
            Err(err) => {
                // ignore duplicate error
                if err.to_string().to_lowercase().contains("unique") {
                    return Ok(1);
                }
                Err(err)
            }
        }
    }
}

#[async_trait]
impl ACLRepository for ACLRepositoryImpl {}

#[async_trait]
impl Repository<ACLEntity, ACLEntity> for ACLRepositoryImpl {
    // create acl.
    async fn create(&self, ctx: &UserContext, acl_entity: &ACLEntity) -> PassResult<usize> {
        if !ctx.roles.is_admin() {
            return Err(PassError::authentication("only admin can create ACL repository"));
        }
        let mut conn = self.connection()?;
        let size = Self::create_conn(acl_entity, &mut conn)?;
        Ok(size)
    }

    // updates existing acl.
    async fn update(&self, ctx: &UserContext, acl_entity: &ACLEntity) -> PassResult<usize> {
        if !ctx.roles.is_admin() {
            return Err(PassError::authentication("only admin can update ACL repository"));
        }

        let existing_acl_entity = self.get_entity(ctx, &acl_entity.acl_id).await?;

        let mut conn = self.connection()?;
        match diesel::update(
            acls.filter(
                version
                    .eq(&existing_acl_entity.version)
                    .and(acl_id.eq(&acl_entity.acl_id)),
            ),
        )
            .set((
                resource_type.eq(acl_entity.resource_type.to_string()),
                resource_id.eq(acl_entity.resource_id.to_string()),
                permissions.eq(acl_entity.permissions),
                scope.eq(acl_entity.scope.to_string()),
                updated_at.eq(Utc::now().naive_utc()),
            ))
            .execute(&mut conn)
        {
            Ok(size) => {
                if size > 0 {
                    Ok(size)
                } else {
                    Err(PassError::database(
                        format!("failed to update acl {}", acl_entity.acl_id, ).as_str(),
                        None,
                        false,
                    ))
                }
            }
            Err(err) => Err(PassError::from(err)),
        }
    }

    // get acl by id
    async fn get(&self, ctx: &UserContext, id: &str) -> PassResult<ACLEntity> {
        let acl_entity = self.get_entity(ctx, id).await?;

        // ensure acl belongs to user
        ctx.validate_user_id(&acl_entity.acl_user_id, || false)?; // no acl-check

        Ok(acl_entity)
    }

    // delete an existing acl.
    async fn delete(&self, ctx: &UserContext, id: &str) -> PassResult<usize> {
        if !ctx.roles.is_admin() {
            return Err(PassError::authentication("only admin can update ACL repository"));
        }
        let _acl_entity = self.get_entity(ctx, id).await?;

        let mut conn = self.connection()?;
        match diesel::delete(acls.filter(acl_id.eq(id))).execute(&mut conn) {
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

    // get acl entity by id
    async fn get_entity(&self, ctx: &UserContext, id: &str) -> PassResult<ACLEntity> {
        let mut conn = self.connection()?;
        let mut items = acls
            .filter(acl_id.eq(id))
            .limit(2)
            .load::<ACLEntity>(&mut conn)?;

        if items.len() > 1 {
            return Err(PassError::database(
                format!("too many acls for {}", id).as_str(),
                None,
                false,
            ));
        } else if items.is_empty() {
            return Err(PassError::not_found(
                format!("acls not found for {}", id).as_str(),
            ));
        }
        let entity = items.remove(0);
        // ensure acl belongs to user
        ctx.validate_user_id(&entity.acl_user_id, || false)?; // no acl check
        Ok(entity)
    }

    // find one entity by predication -- must have only one record, i.e., it will throw error if 0 or 2+ records exist.
    async fn find_one(
        &self,
        ctx: &UserContext,
        predicates: HashMap<String, String>,
    ) -> PassResult<ACLEntity> {
        let mut res = self.find(ctx, predicates, 0, 5).await?;
        if res.records.len() != 1 {
            return Err(PassError::authorization(
                format!("could not find acl [{}]", res.records.len()).as_str(),
            ));
        }

        Ok(res.records.remove(0))
    }

    // find acls with pagination
    async fn find(
        &self,
        ctx: &UserContext,
        predicates: HashMap<String, String>,
        offset: i64,
        limit: usize,
    ) -> PassResult<PaginatedResult<ACLEntity>> {
        let mut predicates = predicates.clone();
        // only admin can query all users
        if !ctx.is_admin() {
            predicates.insert("user_id".into(), ctx.user_id.clone());
        }

        let match_resource_type = format!(
            "%{}%",
            predicates.get("resource_type").cloned().unwrap_or(String::from(""))
        );
        let match_resource_id = format!(
            "%{}%",
            predicates.get("resource_id").cloned().unwrap_or(String::from(""))
        );
        let match_user_id = predicates
            .get("user_id")
            .cloned()
            .unwrap_or(String::from(""));

        let match_permissions = predicates
            .get("permissions")
            .cloned()
            .unwrap_or(String::from("0")).parse::<i64>().unwrap_or(0);

        let mut conn = self.connection()?;
        let entities = acls
            .filter(
                acl_user_id
                    .eq(match_user_id)
                    .and(permissions.ge(match_permissions))
                    .and(resource_type.like(match_resource_type.as_str()))
                    .and(resource_id.like(match_resource_id.as_str())),
            )
            .offset(offset)
            .order(acls::resource_type)
            .limit(limit as i64)
            .load::<ACLEntity>(&mut conn)?;
        Ok(PaginatedResult::new(offset, limit, entities))
    }

    async fn count(&self, _: &UserContext, predicates: HashMap<String, String>) -> PassResult<i64> {
        let match_resource_type = format!(
            "%{}%",
            predicates.get("resource_type").cloned().unwrap_or(String::from(""))
        );
        let match_resource_id = format!(
            "%{}%",
            predicates.get("resource_id").cloned().unwrap_or(String::from(""))
        );
        let match_user_id = predicates
            .get("user_id")
            .cloned()
            .unwrap_or(String::from(""));
        let match_permissions = predicates
            .get("permissions")
            .cloned()
            .unwrap_or(String::from("0")).parse::<i64>().unwrap_or(0);

        let mut conn = self.connection()?;
        match acls
            .filter(
                acl_user_id
                    .eq(match_user_id)
                    .and(permissions.ge(match_permissions))
                    .and(resource_type.like(match_resource_type.as_str()))
                    .and(resource_id.like(match_resource_id.as_str())),
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
    use crate::dao::factory::{create_acl_repository, create_user_repository};
    use crate::dao::models::{ACLEntity, UserContext};
    use crate::domain::models::{PassConfig, User};
    use std::collections::HashMap;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_should_create_update_acls() {
        let config = PassConfig::new();
        // GIVEN a user and acl repositories
        let user_repo = create_user_repository(&config).await.unwrap();
        let acl_repo = create_acl_repository(&config).await.unwrap();

        // Due to referential integrity, we must first create a valid user
        let username = Uuid::new_v4().to_string();
        let user = User::new(username.as_str(), None, None);
        let salt = hex::encode(crypto::generate_nonce());
        let pepper = hex::encode(crypto::generate_secret_key());

        let ctx =
            UserContext::default_new(&username, &user.user_id, &salt, &pepper, "password").unwrap();

        assert_eq!(1, user_repo.create(&ctx, &user).await.unwrap());

        // WHEN creating a acl
        let acl_entity = ACLEntity::new(&user.user_id, "type", "id");
        // THEN it should succeed
        assert_eq!(1, acl_repo.create(&ctx.as_admin(), &acl_entity).await.unwrap());
        // THEN it should succeed with duplicate
        assert_eq!(1, acl_repo.create(&ctx.as_admin(), &acl_entity).await.unwrap());

        // WHEN updating the acl THEN it should succeed
        assert_eq!(1, acl_repo.update(&ctx.as_admin(), &acl_entity).await.unwrap());

        // WHEN retrieving the acl
        let loaded = acl_repo
            .get(&ctx, &acl_entity.acl_id)
            .await
            .unwrap();
        // THEN it should have updated values.
        assert_eq!("type", loaded.resource_type);
    }

    #[tokio::test]
    async fn test_should_create_delete_acls() {
        let config = PassConfig::new();
        // GIVEN a user and acl repositories
        let user_repo = create_user_repository(&config).await.unwrap();
        let acl_repo = create_acl_repository(&config).await.unwrap();

        let salt = hex::encode(crypto::generate_nonce());
        let pepper = hex::encode(crypto::generate_secret_key());
        // Due to referential integrity, we must first create a valid user
        let username = Uuid::new_v4().to_string();
        let user = User::new(username.as_str(), None, None);

        let ctx =
            UserContext::default_new(&username, &user.user_id, &salt, &pepper, "password").unwrap();

        assert_eq!(1, user_repo.create(&ctx, &user).await.unwrap());

        // WHEN creating a acl
        let acl_entity = ACLEntity::new(&user.user_id, "type", "id");
        // THEN it should not succeed without admin access.
        assert!(acl_repo.create(&ctx, &acl_entity).await.is_err());
        // BUT it should succeed with admin.
        assert_eq!(1, acl_repo.create(&ctx.as_admin(), &acl_entity).await.unwrap());

        // WHEN deleting the acl THEN it should succeed.
        assert_eq!(
            1,
            acl_repo.delete(&ctx.as_admin(), &acl_entity.acl_id).await.unwrap()
        );

        // WHEN retrieving the acl THEN it should not find it.
        assert!(acl_repo.get(&ctx, &acl_entity.acl_id).await.is_err());
    }

    #[tokio::test]
    async fn test_should_create_find_acls() {
        let config = PassConfig::new();
        // GIVEN a user and acl repositories
        let user_repo = create_user_repository(&config).await.unwrap();
        let acl_repo = create_acl_repository(&config).await.unwrap();

        let salt = hex::encode(crypto::generate_nonce());
        let pepper = hex::encode(crypto::generate_secret_key());
        // Due to referential integrity, we must first create a valid user
        let username1 = Uuid::new_v4().to_string();
        let username2 = Uuid::new_v4().to_string();
        let user1 = User::new(username1.as_str(), None, None);
        let ctx1 = UserContext::default_new(&username1, &user1.user_id, &salt, &pepper, "password")
            .unwrap();

        assert_eq!(1, user_repo.create(&ctx1, &user1).await.unwrap());

        let user2 = User::new(username2.as_str(), None, None);
        let ctx2 = UserContext::default_new(&username2, &user2.user_id, &salt, &pepper, "password")
            .unwrap();
        assert_eq!(1, user_repo.create(&ctx2, &user2).await.unwrap());

        let prefix1 = Uuid::new_v4().to_string();
        let prefix2 = Uuid::new_v4().to_string();
        let resource_types = vec!["type1".to_string(), "type2".to_string()];
        for i in 0..10 {
            let name1 = format!("{}_{}", prefix1, i);
            // WHEN creating a acl
            let acl1 = ACLEntity::new(&user1.user_id, &resource_types[i % 2].clone(), &name1);
            // THEN it should succeed.
            assert_eq!(1, acl_repo.create(&ctx1.as_admin(), &acl1).await.unwrap());

            // WHEN creating another acl
            let name2 = format!("{}_{}", prefix2, i);
            let acl2 = ACLEntity::new(&user2.user_id, &resource_types[i % 2].clone(), &name2);
            // THEN it should succeed.
            assert_eq!(1, acl_repo.create(&ctx2.as_admin(), &acl2).await.unwrap());
        }

        // WHEN finding by first user and TAG resource_type
        let res1 = acl_repo
            .find(
                &ctx1,
                HashMap::from([
                    ("user_id".into(), user1.user_id.clone()),
                    ("resource_type".into(), resource_types[0].clone()),
                ]),
                0,
                500,
            )
            .await
            .unwrap();

        // THEN it should succeed and match half of the rows
        assert_eq!(5, res1.records.len());

        // WHEN counting by first user and TAG resource_type
        let count1 = acl_repo
            .count(
                &ctx1,
                HashMap::from([
                    ("user_id".into(), user1.user_id.clone()),
                    ("resource_type".into(), resource_types[0].clone()),
                ]),
            )
            .await
            .unwrap();
        // THEN it should succeed and match half of the rows
        assert_eq!(5, count1);

        // WHEN finding by second user and CATEGORY resource_type
        let res2 = acl_repo
            .find(
                &ctx2,
                HashMap::from([
                    ("user_id".into(), user2.user_id.clone()),
                    ("resource_type".into(), resource_types[1].clone()),
                ]),
                0,
                500,
            )
            .await
            .unwrap();

        // THEN it should succeed and match half of the rows
        assert_eq!(5, res2.records.len());

        // WHEN counting by second user and CATEGORY resource_type
        let count2 = acl_repo
            .count(
                &ctx2,
                HashMap::from([
                    ("user_id".into(), user2.user_id.clone()),
                    ("resource_type".into(), resource_types[1].clone()),
                ]),
            )
            .await
            .unwrap();
        // THEN it should succeed and match half of the rows
        assert_eq!(5, count2);
    }
}
